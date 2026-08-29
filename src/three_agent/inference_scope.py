from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Iterator

from .execution_budget import TaskExecutionBudgetState


@dataclass(frozen=True)
class InferenceScope:
    task_id: str
    agent_id: str
    stage: str
    execution_budget: TaskExecutionBudgetState | None = None

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


@contextmanager
def inference_scope(
    task_id: str,
    *,
    agent_id: str,
    stage: str,
    execution_budget: TaskExecutionBudgetState | None = None,
) -> Iterator[InferenceScope]:
    """Bind authoritative task attribution and its optional hard execution budget.

    The budget wrapper is derived from the immutable bound TaskContract by the
    production validator bridge. The same wrapper is passed to Research and
    Presentation scopes, while persistent usage lives in TaskStore so process
    restart cannot reset it. Scope metadata remains content-free.
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

    scope = InferenceScope(
        normalized_task,
        normalized_agent,
        normalized_stage,
        execution_budget,
    )
    token = _CURRENT_SCOPE.set(scope)
    try:
        yield scope
    finally:
        _CURRENT_SCOPE.reset(token)
