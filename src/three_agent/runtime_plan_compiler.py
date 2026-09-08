from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable

from .capability_authority import TaskCapabilityAuthority
from .capability_registry import CapabilityRegistry, CapabilityRegistryError
from .runtime_execution_plan import ExecutionNode, RuntimeExecutionPlan
from .task_contract import TaskContract

RUNTIME_PLAN_COMPILER_SCHEMA = "workspace-runtime-plan-compiler/v1"
COMPILED_RUNTIME_PLAN_SCHEMA = "workspace-compiled-runtime-plan/v1"


class RuntimePlanCompilerError(ValueError):
    """Planner output cannot be bound safely to registry, authority, and budgets."""


def _canonical_sha256(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class CompiledRuntimePlan:
    plan: RuntimeExecutionPlan
    registry_fingerprint: str
    planner_context_sha256: str
    schema_version: str = COMPILED_RUNTIME_PLAN_SCHEMA

    @property
    def fingerprint(self) -> str:
        return _canonical_sha256(self.metadata())

    def metadata(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "plan_id": self.plan.plan_id,
            "task_id": self.plan.task_id,
            "plan_fingerprint": self.plan.fingerprint,
            "authority_fingerprint": self.plan.authority_fingerprint,
            "registry_fingerprint": self.registry_fingerprint,
            "planner_context_sha256": self.planner_context_sha256,
        }

    def validate_current(
        self,
        *,
        task_contract: TaskContract,
        registry: CapabilityRegistry,
    ) -> "CompiledRuntimePlan":
        task_contract.validate()
        authority = TaskCapabilityAuthority.from_contract(task_contract)
        if self.plan.task_id != task_contract.task_id:
            raise RuntimePlanCompilerError("COMPILED_PLAN_TASK_MISMATCH")
        if self.plan.authority_fingerprint != authority.fingerprint:
            raise RuntimePlanCompilerError("COMPILED_PLAN_AUTHORITY_CHANGED")
        if self.registry_fingerprint != registry.fingerprint:
            raise RuntimePlanCompilerError("COMPILED_PLAN_REGISTRY_CHANGED")
        self.plan.validate(authority)
        return self


class RuntimePlanCompiler:
    """Bind planner-visible capabilities to an immutable executable DAG.

    The planner receives only authority-filtered registry metadata. Compilation
    rejects capability IDs that were not discoverable, descriptor semantic drift,
    and plans exceeding the TaskContract execution budget before delegating final
    resource authorization and graph checks to ``RuntimeExecutionPlan``.
    """

    def __init__(self, registry: CapabilityRegistry | None = None):
        self.registry = registry or CapabilityRegistry.default()

    def planner_context(self, task_contract: TaskContract) -> dict[str, object]:
        task_contract.validate()
        authority = TaskCapabilityAuthority.from_contract(task_contract)
        registry_payload = self.registry.planner_metadata(authority)
        budget = task_contract.execution_budget
        return {
            "schema_version": RUNTIME_PLAN_COMPILER_SCHEMA,
            "task_id": task_contract.task_id,
            "risk_level": task_contract.risk_level,
            "evidence_required": task_contract.evidence_required,
            "authority_fingerprint": authority.fingerprint,
            "registry_fingerprint": self.registry.fingerprint,
            "execution_budget": {
                "max_steps": budget.max_steps,
                "max_tool_calls": budget.max_tool_calls,
                "max_retries": budget.max_retries,
                "max_wall_time_ms": budget.max_wall_time_ms,
            },
            "capabilities": registry_payload["capabilities"],
        }

    def compile(
        self,
        *,
        plan_id: str,
        task_contract: TaskContract,
        nodes: Iterable[ExecutionNode],
        max_parallel: int = 4,
    ) -> CompiledRuntimePlan:
        task_contract.validate()
        authority = TaskCapabilityAuthority.from_contract(task_contract)
        node_rows = tuple(nodes)
        budget = task_contract.execution_budget
        if len(node_rows) > budget.max_steps:
            raise RuntimePlanCompilerError("PLAN_EXCEEDS_MAX_STEPS")
        if len(node_rows) > budget.max_tool_calls:
            raise RuntimePlanCompilerError("PLAN_EXCEEDS_MAX_TOOL_CALLS")

        try:
            available = {
                item.capability_id: item for item in self.registry.discover(authority)
            }
        except CapabilityRegistryError as exc:
            raise RuntimePlanCompilerError(str(exc)) from exc

        for node in node_rows:
            descriptor = available.get(node.capability)
            if descriptor is None:
                raise RuntimePlanCompilerError(
                    f"PLAN_CAPABILITY_NOT_DISCOVERED:{node.node_id}:{node.capability}"
                )
            if node.effect != descriptor.effect:
                raise RuntimePlanCompilerError(
                    f"PLAN_CAPABILITY_EFFECT_MISMATCH:{node.node_id}"
                )
            if node.resource_kind != descriptor.resource_kind:
                raise RuntimePlanCompilerError(
                    f"PLAN_RESOURCE_KIND_MISMATCH:{node.node_id}"
                )

        planner_context = self.planner_context(task_contract)
        plan = RuntimeExecutionPlan.compile(
            plan_id=plan_id,
            task_contract=task_contract,
            nodes=node_rows,
            max_parallel=max_parallel,
        )
        compiled = CompiledRuntimePlan(
            plan=plan,
            registry_fingerprint=self.registry.fingerprint,
            planner_context_sha256=_canonical_sha256(planner_context),
        )
        return compiled.validate_current(task_contract=task_contract, registry=self.registry)
