from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from .capability_authority import TaskCapabilityAuthority
from .capability_registry import CapabilityRegistry
from .execution_budget import TaskExecutionBudgetState
from .inference_scope import InferenceScope, inference_scope
from .model_authority import TaskModelAuthority
from .runtime_plan_compiler import CompiledRuntimePlan
from .task_contract import TaskContract

RUNTIME_NODE_AUTHORITY_SCHEMA = "workspace-runtime-node-authority/v1"
RUNTIME_BUDGET_OWNERSHIP_SCHEMA = "workspace-runtime-budget-ownership/v1"


class RuntimeNodeAuthorityError(RuntimeError):
    pass


@dataclass(frozen=True)
class RuntimeBudgetOwnership:
    """Single-owner accounting policy for the governed execution path."""

    step_owner: str = "scheduler"
    tool_call_owner: str = "capability_boundary"
    retry_owner: str = "model_router"
    escalation_owner: str = "model_router"
    schema_version: str = RUNTIME_BUDGET_OWNERSHIP_SCHEMA

    def validate(self) -> "RuntimeBudgetOwnership":
        if self.step_owner != "scheduler":
            raise RuntimeNodeAuthorityError("RUNTIME_STEP_OWNER_INVALID")
        if self.tool_call_owner != "capability_boundary":
            raise RuntimeNodeAuthorityError("RUNTIME_TOOL_CALL_OWNER_INVALID")
        if self.retry_owner != "model_router" or self.escalation_owner != "model_router":
            raise RuntimeNodeAuthorityError("RUNTIME_MODEL_BUDGET_OWNER_INVALID")
        return self

    def metadata(self) -> dict[str, str]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "step_owner": self.step_owner,
            "tool_call_owner": self.tool_call_owner,
            "retry_owner": self.retry_owner,
            "escalation_owner": self.escalation_owner,
        }


@dataclass(frozen=True)
class RuntimeNodeAuthority:
    """Least-privilege authority compiled for exactly one execution-plan node.

    Capability execution nodes are NO_LLM scopes. They receive exactly one tool,
    no write scope unless the node itself writes, and no network scope unless the
    node itself is the reviewed network-read capability. This prevents a tool
    adapter from inheriting the full task authority merely because the parent task
    is broad.
    """

    task_id: str
    plan_id: str
    plan_fingerprint: str
    node_id: str
    capability: str
    parent_authority_fingerprint: str
    model_authority: TaskModelAuthority
    capability_authority: TaskCapabilityAuthority
    schema_version: str = RUNTIME_NODE_AUTHORITY_SCHEMA

    @classmethod
    def compile(
        cls,
        *,
        task_contract: TaskContract,
        compiled_plan: CompiledRuntimePlan,
        node_id: str,
        registry: CapabilityRegistry | None = None,
    ) -> "RuntimeNodeAuthority":
        active_registry = registry or CapabilityRegistry.default()
        compiled_plan.validate_current(
            task_contract=task_contract,
            registry=active_registry,
        )
        by_id = {node.node_id: node for node in compiled_plan.plan.nodes}
        try:
            node = by_id[str(node_id).strip()]
        except KeyError as exc:
            raise RuntimeNodeAuthorityError("RUNTIME_NODE_NOT_IN_PLAN") from exc
        descriptor = active_registry.descriptor(node.capability)
        if node.effect != descriptor.effect or node.resource_kind != descriptor.resource_kind:
            raise RuntimeNodeAuthorityError("RUNTIME_NODE_DESCRIPTOR_DRIFT")

        parent_model = TaskModelAuthority.from_contract(task_contract)
        parent_capability = TaskCapabilityAuthority.from_contract(task_contract)
        child_write: str | tuple[str, ...] = (
            (node.resource_ref,) if node.effect == "write" else "none"
        )
        child_network = (
            parent_capability.network_scope
            if node.effect == "network_read"
            else "deny"
        )
        child_model = parent_model.delegate(
            task_id=task_contract.task_id,
            allowed_tools=(node.capability,),
            write_scope=child_write,
            network_scope=child_network,
            initial_model_tier="none",
            max_model_tier="none",
            escalation_allowed=False,
        )
        child_capability = parent_capability.delegate(
            task_id=task_contract.task_id,
            sensitivity=child_model.sensitivity,
            allowed_sources=child_model.allowed_sources,
            allowed_tools=child_model.allowed_tools,
            write_scope=child_model.write_scope,
            network_scope=child_model.network_scope,
        )
        projected = TaskCapabilityAuthority.from_model_authority(child_model)
        if projected.fingerprint != child_capability.fingerprint:
            raise RuntimeNodeAuthorityError("RUNTIME_NODE_AUTHORITY_BINDING_MISMATCH")
        if not child_model.is_subset_of(parent_model):
            raise RuntimeNodeAuthorityError("RUNTIME_NODE_MODEL_AUTHORITY_WIDENED")
        if not child_capability.is_subset_of(parent_capability):
            raise RuntimeNodeAuthorityError("RUNTIME_NODE_CAPABILITY_AUTHORITY_WIDENED")

        return cls(
            task_id=task_contract.task_id,
            plan_id=compiled_plan.plan.plan_id,
            plan_fingerprint=compiled_plan.plan.fingerprint,
            node_id=node.node_id,
            capability=node.capability,
            parent_authority_fingerprint=parent_capability.fingerprint,
            model_authority=child_model,
            capability_authority=child_capability,
        )

    @property
    def fingerprint(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "plan_id": self.plan_id,
            "plan_fingerprint": self.plan_fingerprint,
            "node_id": self.node_id,
            "capability": self.capability,
            "parent_authority_fingerprint": self.parent_authority_fingerprint,
            "model_authority_fingerprint": self.model_authority.fingerprint,
            "capability_authority_fingerprint": self.capability_authority.fingerprint,
        }
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    def metadata(self) -> dict[str, str | bool]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "plan_id": self.plan_id,
            "plan_fingerprint": self.plan_fingerprint,
            "node_id": self.node_id,
            "capability": self.capability,
            "parent_authority_fingerprint": self.parent_authority_fingerprint,
            "node_authority_fingerprint": self.fingerprint,
            "model_authority_fingerprint": self.model_authority.fingerprint,
            "capability_authority_fingerprint": self.capability_authority.fingerprint,
            "model_calls_allowed": False,
        }

    @contextmanager
    def scope(
        self,
        execution_budget: TaskExecutionBudgetState,
    ) -> Iterator[InferenceScope]:
        if execution_budget.task_id != self.task_id:
            raise RuntimeNodeAuthorityError("RUNTIME_NODE_BUDGET_TASK_MISMATCH")
        RuntimeBudgetOwnership().validate()
        with inference_scope(
            self.task_id,
            agent_id="runtime_node",
            stage=self.node_id,
            execution_budget=execution_budget,
            model_authority=self.model_authority,
            capability_authority=self.capability_authority,
        ) as active:
            yield active
