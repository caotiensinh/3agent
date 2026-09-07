from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Iterable, Iterator

from .capability_authority import TaskCapabilityAuthority
from .execution_budget import TaskExecutionBudgetState
from .model_authority import TaskModelAuthority


@dataclass(frozen=True)
class InferenceScope:
    task_id: str
    agent_id: str
    stage: str
    execution_budget: TaskExecutionBudgetState | None = None
    model_authority: TaskModelAuthority | None = None
    capability_authority: TaskCapabilityAuthority | None = None

    def metadata(self) -> dict[str, str]:
        return {
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "stage": self.stage,
        }


_CURRENT_SCOPE: ContextVar[InferenceScope | None] = ContextVar(
    "workspace_inference_scope",
    default=None,
)


def current_inference_scope() -> InferenceScope | None:
    """Return trusted caller scope for the current synchronous inference path."""
    return _CURRENT_SCOPE.get()


def current_execution_budget() -> TaskExecutionBudgetState | None:
    scope = _CURRENT_SCOPE.get()
    return scope.execution_budget if scope is not None else None


def current_model_authority() -> TaskModelAuthority | None:
    scope = _CURRENT_SCOPE.get()
    return scope.model_authority if scope is not None else None


def current_capability_authority() -> TaskCapabilityAuthority | None:
    scope = _CURRENT_SCOPE.get()
    if scope is None:
        return None
    if scope.capability_authority is not None:
        return scope.capability_authority
    if scope.model_authority is not None:
        return TaskCapabilityAuthority.from_model_authority(scope.model_authority)
    return None


@contextmanager
def inference_scope(
    task_id: str,
    *,
    agent_id: str,
    stage: str,
    execution_budget: TaskExecutionBudgetState | None = None,
    model_authority: TaskModelAuthority | None = None,
    capability_authority: TaskCapabilityAuthority | None = None,
) -> Iterator[InferenceScope]:
    """Bind authoritative task identity, budgets and immutable authorities.

    Budget/model authority come from the production TaskContract bridge. The
    capability broker is either explicitly supplied from that contract or derived
    deterministically from the bridge-bound model authority's capability subset.
    Prompt/model content can never replace or expand these objects.
    """
    normalized_task = str(task_id).strip()
    normalized_agent = str(agent_id).strip()
    normalized_stage = str(stage).strip()
    if not normalized_task or len(normalized_task) > 128 or any(ch.isspace() for ch in normalized_task):
        raise ValueError("task_id must be a compact authoritative identifier")
    if not normalized_agent or len(normalized_agent) > 64 or any(ch.isspace() for ch in normalized_agent):
        raise ValueError("agent_id must be a compact identifier")
    if not normalized_stage or len(normalized_stage) > 64 or any(ch.isspace() for ch in normalized_stage):
        raise ValueError("stage must be a compact identifier")
    if execution_budget is not None and execution_budget.task_id != normalized_task:
        raise ValueError("execution budget task_id does not match inference scope")
    if model_authority is not None and model_authority.task_id != normalized_task:
        raise ValueError("model authority task_id does not match inference scope")
    if capability_authority is not None and capability_authority.task_id != normalized_task:
        raise ValueError("capability authority task_id does not match inference scope")

    scope = InferenceScope(
        normalized_task,
        normalized_agent,
        normalized_stage,
        execution_budget,
        model_authority,
        capability_authority,
    )
    token = _CURRENT_SCOPE.set(scope)
    try:
        yield scope
    finally:
        _CURRENT_SCOPE.reset(token)


@contextmanager
def delegated_inference_scope(
    *,
    agent_id: str,
    stage: str,
    sensitivity: str | None = None,
    risk_level: str | None = None,
    allowed_sources: Iterable[str] | None = None,
    allowed_tools: Iterable[str] | None = None,
    write_scope: str | Iterable[str] | None = None,
    network_scope: str | None = None,
    initial_model_tier: str | None = None,
    max_model_tier: str | None = None,
    escalation_allowed: bool | None = None,
) -> Iterator[InferenceScope]:
    """Create a bounded child/subagent scope from the current trusted scope.

    The child shares the parent's execution budget; it does not receive a fresh
    quota. Model and capability authority are independently narrowed, then their
    capability fingerprints are cross-checked before the child scope becomes
    visible. Nested delegation therefore remains monotonic and fail closed.
    """
    parent = current_inference_scope()
    if parent is None or parent.model_authority is None:
        raise RuntimeError("DELEGATED_SCOPE_PARENT_MODEL_AUTHORITY_REQUIRED")
    parent_capability = current_capability_authority()
    if parent_capability is None:
        raise RuntimeError("DELEGATED_SCOPE_PARENT_CAPABILITY_AUTHORITY_REQUIRED")

    child_model = parent.model_authority.delegate(
        task_id=parent.task_id,
        sensitivity=sensitivity,
        risk_level=risk_level,
        allowed_sources=allowed_sources,
        allowed_tools=allowed_tools,
        write_scope=write_scope,
        network_scope=network_scope,
        initial_model_tier=initial_model_tier,
        max_model_tier=max_model_tier,
        escalation_allowed=escalation_allowed,
    )
    child_capability = parent_capability.delegate(
        task_id=parent.task_id,
        sensitivity=child_model.sensitivity,
        allowed_sources=child_model.allowed_sources,
        allowed_tools=child_model.allowed_tools,
        write_scope=child_model.write_scope,
        network_scope=child_model.network_scope,
    )
    model_capability = TaskCapabilityAuthority.from_model_authority(child_model)
    if child_capability.fingerprint != model_capability.fingerprint:
        raise RuntimeError("DELEGATED_SCOPE_AUTHORITY_BINDING_MISMATCH")

    with inference_scope(
        parent.task_id,
        agent_id=agent_id,
        stage=stage,
        execution_budget=parent.execution_budget,
        model_authority=child_model,
        capability_authority=child_capability,
    ) as child_scope:
        yield child_scope
