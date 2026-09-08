from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Protocol

from .capability_registry import CapabilityDescriptor, CapabilityRegistry
from .runtime_checkpoint import RuntimeCheckpoint, RuntimeCheckpointError, RuntimeCheckpointStore
from .runtime_execution_plan import ExecutionNode, ExecutionObservation, RuntimeExecutionPlanError
from .runtime_plan_compiler import CompiledRuntimePlan
from .task_contract import TaskContract

RUNTIME_SCHEDULER_RESULT_SCHEMA = "workspace-runtime-scheduler-result/v2"
_REASON_RE = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{0,127}$")
_MUTATING_EFFECTS = {"write", "network_write", "destructive"}
_TIMEOUT_MODES = {"hard", "cooperative"}


class RuntimeSchedulerError(RuntimeError):
    pass


class ExecutionBudgetLike(Protocol):
    task_id: str

    def reserve(
        self,
        *,
        steps: int = 0,
        tool_calls: int = 0,
        retries: int = 0,
        escalations: int = 0,
    ) -> None: ...

    def assert_active(self) -> None: ...


@dataclass(frozen=True)
class NodeExecutionResult:
    result: Any
    evidence_refs: tuple[str, ...] = ()
    reason_code: str = "EXECUTION_OK"


@dataclass(frozen=True)
class CapabilityInvocation:
    node: ExecutionNode
    started_monotonic: float
    deadline_monotonic: float

    @property
    def timeout_ms(self) -> int:
        return self.node.timeout_ms

    def remaining_seconds(self) -> float:
        return max(0.0, self.deadline_monotonic - time.monotonic())

    def assert_active(self) -> None:
        if self.remaining_seconds() <= 0.0:
            raise TimeoutError("CAPABILITY_INVOCATION_DEADLINE_EXCEEDED")


CapabilityAdapter = Callable[[CapabilityInvocation], NodeExecutionResult]


@dataclass(frozen=True)
class _AdapterBinding:
    handler: CapabilityAdapter
    timeout_mode: str


class CapabilityAdapterRegistry:
    """Runtime-owned adapter table; planner output can never register executable code.

    ``hard`` adapters must enforce ``CapabilityInvocation.remaining_seconds()`` at
    their transport/process boundary. Mutating or serialized capabilities require
    this mode because Python worker threads cannot safely kill a side-effecting
    handler after its deadline.
    """

    def __init__(self, capability_registry: CapabilityRegistry | None = None):
        self.capability_registry = capability_registry or CapabilityRegistry.default()
        self._handlers: dict[str, _AdapterBinding] = {}

    def register(
        self,
        capability_id: str,
        handler: CapabilityAdapter,
        *,
        timeout_mode: str,
    ) -> None:
        descriptor = self.capability_registry.descriptor(capability_id)
        mode = str(timeout_mode).strip().lower()
        if not callable(handler):
            raise RuntimeSchedulerError("CAPABILITY_ADAPTER_NOT_CALLABLE")
        if mode not in _TIMEOUT_MODES:
            raise RuntimeSchedulerError("CAPABILITY_ADAPTER_TIMEOUT_MODE_INVALID")
        if (
            descriptor.effect in _MUTATING_EFFECTS
            or descriptor.concurrency_mode == "serialized"
        ) and mode != "hard":
            raise RuntimeSchedulerError("MUTATING_ADAPTER_REQUIRES_HARD_TIMEOUT")
        if descriptor.capability_id in self._handlers:
            raise RuntimeSchedulerError(
                f"CAPABILITY_ADAPTER_ALREADY_REGISTERED:{descriptor.capability_id}"
            )
        self._handlers[descriptor.capability_id] = _AdapterBinding(handler, mode)

    def invoke(self, invocation: CapabilityInvocation) -> NodeExecutionResult:
        try:
            binding = self._handlers[invocation.node.capability]
        except KeyError as exc:
            raise RuntimeSchedulerError(
                f"CAPABILITY_ADAPTER_NOT_REGISTERED:{invocation.node.capability}"
            ) from exc
        invocation.assert_active()
        result = binding.handler(invocation)
        if not isinstance(result, NodeExecutionResult):
            raise RuntimeSchedulerError("CAPABILITY_ADAPTER_RESULT_INVALID")
        return result


@dataclass(frozen=True)
class RuntimeSchedulerResult:
    status: str
    task_id: str
    plan_id: str
    completed_node_ids: tuple[str, ...]
    failed_node_ids: tuple[str, ...]
    observations: tuple[ExecutionObservation, ...]
    checkpoint: RuntimeCheckpoint
    durability: str
    schema_version: str = RUNTIME_SCHEDULER_RESULT_SCHEMA

    def metadata(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "task_id": self.task_id,
            "plan_id": self.plan_id,
            "completed_node_ids": list(self.completed_node_ids),
            "failed_node_ids": list(self.failed_node_ids),
            "observations": [o.metadata() for o in self.observations],
            "checkpoint": self.checkpoint.metadata(),
            "durability": self.durability,
        }


class RuntimeDAGScheduler:
    """Bounded fail-fast DAG scheduler with crash-safe checkpoint semantics."""

    def __init__(
        self,
        *,
        registry: CapabilityRegistry | None = None,
        adapters: CapabilityAdapterRegistry | None = None,
        checkpoint_store: RuntimeCheckpointStore | None = None,
    ):
        self.registry = registry or CapabilityRegistry.default()
        self.adapters = adapters or CapabilityAdapterRegistry(self.registry)
        self.checkpoint_store = checkpoint_store
        if self.adapters.capability_registry.fingerprint != self.registry.fingerprint:
            raise RuntimeSchedulerError("SCHEDULER_ADAPTER_REGISTRY_MISMATCH")

    @staticmethod
    def _budget_reason(exc: Exception) -> str:
        code = str(getattr(exc, "reason_code", "") or "").strip().upper()
        return code if code and _REASON_RE.fullmatch(code) else "EXECUTION_BUDGET_DENIED"

    @staticmethod
    def _safe_reason(value: str) -> str:
        code = str(value or "").strip().upper()
        return code if _REASON_RE.fullmatch(code) else "ADAPTER_RESULT_INVALID"

    def _descriptor(self, node: ExecutionNode) -> CapabilityDescriptor:
        return self.registry.descriptor(node.capability)

    def _requires_durability(self, compiled_plan: CompiledRuntimePlan) -> bool:
        return any(
            node.effect in _MUTATING_EFFECTS or not node.idempotent
            for node in compiled_plan.plan.nodes
        )

    def _persist(self, checkpoint: RuntimeCheckpoint) -> None:
        if self.checkpoint_store is not None:
            self.checkpoint_store.save(checkpoint)

    def _checkpoint(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        status: str,
        completed: set[str],
        running: Iterable[str] = (),
        failed: Iterable[str] = (),
        observations: Iterable[ExecutionObservation] = (),
        prior_observation_ids: Iterable[str] = (),
    ) -> RuntimeCheckpoint:
        checkpoint = RuntimeCheckpoint.capture(
            compiled_plan=compiled_plan,
            status=status,
            completed_node_ids=completed,
            running_node_ids=running,
            failed_node_ids=failed,
            observations=observations,
            prior_observation_ids=prior_observation_ids,
        )
        self._persist(checkpoint)
        return checkpoint

    def _invoke_node(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        node: ExecutionNode,
        budget: ExecutionBudgetLike,
    ) -> tuple[ExecutionObservation, bool]:
        try:
            budget.assert_active()
            budget.reserve(steps=1, tool_calls=1)
        except Exception as exc:
            return (
                ExecutionObservation.capture(
                    plan=compiled_plan.plan,
                    node_id=node.node_id,
                    status="denied",
                    reason_code=self._budget_reason(exc),
                    result={"execution": "budget_denied"},
                ),
                False,
            )

        started = time.monotonic()
        invocation = CapabilityInvocation(
            node=node,
            started_monotonic=started,
            deadline_monotonic=started + node.timeout_ms / 1000.0,
        )
        try:
            result = self.adapters.invoke(invocation)
        except TimeoutError:
            return (
                ExecutionObservation.capture(
                    plan=compiled_plan.plan,
                    node_id=node.node_id,
                    status="failed",
                    reason_code="ADAPTER_TIMEOUT",
                    result={"execution": "timeout"},
                ),
                False,
            )
        except Exception as exc:
            return (
                ExecutionObservation.capture(
                    plan=compiled_plan.plan,
                    node_id=node.node_id,
                    status="failed",
                    reason_code="ADAPTER_EXCEPTION",
                    result={"exception_type": type(exc).__name__},
                ),
                False,
            )

        if time.monotonic() > invocation.deadline_monotonic:
            return (
                ExecutionObservation.capture(
                    plan=compiled_plan.plan,
                    node_id=node.node_id,
                    status="failed",
                    reason_code="ADAPTER_TIMEOUT_EXCEEDED",
                    result={"execution": "late_result_discarded"},
                ),
                False,
            )

        reason = self._safe_reason(result.reason_code)
        if reason == "ADAPTER_RESULT_INVALID":
            return (
                ExecutionObservation.capture(
                    plan=compiled_plan.plan,
                    node_id=node.node_id,
                    status="failed",
                    reason_code=reason,
                    result={"execution": "invalid_adapter_result"},
                ),
                False,
            )
        evidence_refs = tuple(result.evidence_refs)
        descriptor = self._descriptor(node)
        if (compiled_plan.plan.evidence_required or descriptor.evidence_default) and not evidence_refs:
            return (
                ExecutionObservation.capture(
                    plan=compiled_plan.plan,
                    node_id=node.node_id,
                    status="failed",
                    reason_code="EVIDENCE_REQUIRED_MISSING",
                    result={"execution": "evidence_missing"},
                ),
                False,
            )
        try:
            observation = ExecutionObservation.capture(
                plan=compiled_plan.plan,
                node_id=node.node_id,
                status="succeeded",
                reason_code=reason,
                result=result.result,
                evidence_refs=evidence_refs,
            )
        except RuntimeExecutionPlanError:
            observation = ExecutionObservation.capture(
                plan=compiled_plan.plan,
                node_id=node.node_id,
                status="failed",
                reason_code="ADAPTER_RESULT_INVALID",
                result={"execution": "invalid_evidence_metadata"},
            )
            return observation, False
        return observation, True

    def _ready_round(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        completed: set[str],
        approved: set[str],
    ) -> tuple[ExecutionNode, ...]:
        ready = compiled_plan.plan.ready_nodes(completed=completed, approved=approved)
        if not ready:
            return ()
        serialized = [
            node for node in ready
            if self._descriptor(node).concurrency_mode == "serialized"
        ]
        if serialized:
            return (sorted(serialized, key=lambda node: node.node_id)[0],)
        return ready

    def run(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        task_contract: TaskContract,
        budget: ExecutionBudgetLike,
        approved_node_ids: Iterable[str] = (),
        checkpoint: RuntimeCheckpoint | None = None,
    ) -> RuntimeSchedulerResult:
        compiled_plan.validate_current(task_contract=task_contract, registry=self.registry)
        if budget.task_id != compiled_plan.plan.task_id:
            raise RuntimeSchedulerError("SCHEDULER_BUDGET_TASK_MISMATCH")
        if self._requires_durability(compiled_plan) and self.checkpoint_store is None:
            raise RuntimeSchedulerError("DURABLE_CHECKPOINT_REQUIRED_FOR_MUTATION")

        completed: set[str] = set()
        observations: list[ExecutionObservation] = []
        prior_observation_ids: tuple[str, ...] = ()
        if checkpoint is not None:
            try:
                checkpoint.validate(compiled_plan)
            except RuntimeCheckpointError as exc:
                raise RuntimeSchedulerError(str(exc)) from exc
            if checkpoint.running_node_ids:
                raise RuntimeSchedulerError("INFLIGHT_CHECKPOINT_REQUIRES_RECONCILIATION")
            if checkpoint.failed_node_ids:
                raise RuntimeSchedulerError("FAILED_CHECKPOINT_REQUIRES_RECONCILIATION")
            completed.update(checkpoint.completed_node_ids)
            prior_observation_ids = checkpoint.observation_ids

        known = {node.node_id for node in compiled_plan.plan.nodes}
        approved = set(approved_node_ids)
        if not approved.issubset(known):
            raise RuntimeSchedulerError("SCHEDULER_APPROVAL_CONTAINS_UNKNOWN_NODE")
        durability = "durable" if self.checkpoint_store else "ephemeral"

        if completed == known:
            final_checkpoint = self._checkpoint(
                compiled_plan=compiled_plan,
                status="completed",
                completed=completed,
                prior_observation_ids=prior_observation_ids,
            )
            return RuntimeSchedulerResult(
                "completed", compiled_plan.plan.task_id, compiled_plan.plan.plan_id,
                tuple(sorted(completed)), (), (), final_checkpoint, durability,
            )

        failed: set[str] = set()
        while completed != known:
            ready = self._ready_round(
                compiled_plan=compiled_plan,
                completed=completed,
                approved=approved,
            )
            if not ready:
                blocked = self._checkpoint(
                    compiled_plan=compiled_plan,
                    status="blocked",
                    completed=completed,
                    observations=observations,
                    prior_observation_ids=prior_observation_ids,
                )
                return RuntimeSchedulerResult(
                    "blocked", compiled_plan.plan.task_id, compiled_plan.plan.plan_id,
                    tuple(sorted(completed)), (), tuple(observations), blocked, durability,
                )

            running_ids = tuple(node.node_id for node in ready)
            self._checkpoint(
                compiled_plan=compiled_plan,
                status="running",
                completed=completed,
                running=running_ids,
                observations=observations,
                prior_observation_ids=prior_observation_ids,
            )

            results: dict[str, tuple[ExecutionObservation, bool]] = {}
            if len(ready) == 1:
                node = ready[0]
                results[node.node_id] = self._invoke_node(
                    compiled_plan=compiled_plan, node=node, budget=budget
                )
            else:
                with ThreadPoolExecutor(
                    max_workers=min(len(ready), compiled_plan.plan.max_parallel)
                ) as pool:
                    futures = {
                        pool.submit(
                            self._invoke_node,
                            compiled_plan=compiled_plan,
                            node=node,
                            budget=budget,
                        ): node.node_id
                        for node in ready
                    }
                    for future in as_completed(futures):
                        node_id = futures[future]
                        try:
                            results[node_id] = future.result()
                        except Exception as exc:
                            results[node_id] = (
                                ExecutionObservation.capture(
                                    plan=compiled_plan.plan,
                                    node_id=node_id,
                                    status="failed",
                                    reason_code="SCHEDULER_WORKER_EXCEPTION",
                                    result={"exception_type": type(exc).__name__},
                                ),
                                False,
                            )

            round_failed = False
            for node_id in sorted(results):
                observation, succeeded = results[node_id]
                observations.append(observation)
                if succeeded:
                    completed.add(node_id)
                else:
                    failed.add(node_id)
                    round_failed = True

            cumulative_ids = tuple(dict.fromkeys(
                (*prior_observation_ids, *(o.observation_id for o in observations))
            ))
            if round_failed:
                failed_checkpoint = self._checkpoint(
                    compiled_plan=compiled_plan,
                    status="failed",
                    completed=completed,
                    failed=failed,
                    prior_observation_ids=cumulative_ids,
                )
                return RuntimeSchedulerResult(
                    "failed", compiled_plan.plan.task_id, compiled_plan.plan.plan_id,
                    tuple(sorted(completed)), tuple(sorted(failed)),
                    tuple(observations), failed_checkpoint, durability,
                )

            status = "completed" if completed == known else "ready"
            current_checkpoint = self._checkpoint(
                compiled_plan=compiled_plan,
                status=status,
                completed=completed,
                prior_observation_ids=cumulative_ids,
            )
            prior_observation_ids = current_checkpoint.observation_ids

        return RuntimeSchedulerResult(
            "completed", compiled_plan.plan.task_id, compiled_plan.plan.plan_id,
            tuple(sorted(completed)), (), tuple(observations), current_checkpoint, durability,
        )
