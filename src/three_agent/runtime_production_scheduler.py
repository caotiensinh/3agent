from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Iterable

from .capability_authority import CapabilityAuthorityDenied
from .execution_budget import ExecutionBudgetExceeded
from .runtime_audited_scheduler import AuditedRuntimeDAGScheduler
from .runtime_capability_boundary import RuntimeCapabilityBoundaryError
from .runtime_checkpoint import RuntimeCheckpoint
from .runtime_execution_plan import ExecutionNode, ExecutionObservation, RuntimeExecutionPlanError
from .runtime_invocation import RuntimeInvocationBundle
from .runtime_invocation_binding import (
    RuntimeInvocationBindingError,
    RuntimeInvocationBindingStore,
)
from .runtime_plan_compiler import CompiledRuntimePlan
from .runtime_scheduler import (
    CapabilityAdapterRegistry,
    CapabilityInvocation,
    ExecutionBudgetLike,
    NodeExecutionResult,
    RuntimeSchedulerError,
    RuntimeSchedulerResult,
)
from .runtime_source_authority import (
    RuntimeSourceAuthorityDenied,
    RuntimeSourceBindingBundle,
)
from .runtime_source_binding_store import (
    RuntimeSourceBindingStore,
    RuntimeSourceBindingStoreError,
)
from .task_contract import TaskContract

RUNTIME_PRODUCTION_SCHEDULER_SCHEMA = "workspace-runtime-production-scheduler/v2"
_REASON_RE = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{0,127}$")
_DENIAL_ERRORS = (
    CapabilityAuthorityDenied,
    ExecutionBudgetExceeded,
    RuntimeCapabilityBoundaryError,
    RuntimeSourceAuthorityDenied,
)


@dataclass(frozen=True)
class ProductionNodeExecutionResult(NodeExecutionResult):
    """Adapter outcome with explicit success semantics for production execution."""

    succeeded: bool = True


class ProductionAuditedRuntimeDAGScheduler(AuditedRuntimeDAGScheduler):
    """Audited scheduler where capability boundaries own tool-call accounting.

    The legacy scheduler charges one tool call per node for compatibility. The
    production path cannot do that because one typed node may invoke a reviewed
    boundary exactly once and that boundary must atomically authorize, re-check
    revocation, and charge the real tool call. This subclass therefore charges
    only the scheduler step and requires a registry explicitly marked as
    boundary-accounted.

    Production execution additionally requires immutable durable invocation
    semantics. Source-scoped adapters also require a second create-only recovery
    binding so the same DAG/invocation cannot resume against a different trusted
    source root or source class. Both are bound before RUNNING checkpoints.
    """

    schema_version = RUNTIME_PRODUCTION_SCHEDULER_SCHEMA

    def __init__(
        self,
        *,
        adapters: CapabilityAdapterRegistry,
        invocation_binding_store: RuntimeInvocationBindingStore,
        source_binding_store: RuntimeSourceBindingStore | None = None,
        **kwargs,
    ):
        if not bool(getattr(adapters, "boundary_accounted", False)):
            raise RuntimeSchedulerError("PRODUCTION_ADAPTERS_MUST_BE_BOUNDARY_ACCOUNTED")
        if invocation_binding_store is None or not bool(
            getattr(invocation_binding_store, "durable", False)
        ):
            raise RuntimeSchedulerError("DURABLE_INVOCATION_BINDING_STORE_REQUIRED")
        invocation_bundle = getattr(adapters, "invocation_bundle", None)
        if not isinstance(invocation_bundle, RuntimeInvocationBundle):
            raise RuntimeSchedulerError("PRODUCTION_INVOCATION_BUNDLE_REQUIRED")

        source_bundle = getattr(adapters, "source_binding_bundle", None)
        if source_bundle is not None:
            if not isinstance(source_bundle, RuntimeSourceBindingBundle):
                raise RuntimeSchedulerError("PRODUCTION_SOURCE_BINDING_BUNDLE_INVALID")
            if source_binding_store is None or not bool(
                getattr(source_binding_store, "durable", False)
            ):
                raise RuntimeSchedulerError("DURABLE_SOURCE_BINDING_STORE_REQUIRED")

        self.invocation_binding_store = invocation_binding_store
        self.invocation_bundle = invocation_bundle
        self.source_binding_store = source_binding_store
        self.source_binding_bundle = source_bundle
        super().__init__(adapters=adapters, **kwargs)

    @staticmethod
    def _reason_from_exception(exc: Exception, fallback: str) -> str:
        code = str(getattr(exc, "reason_code", "") or "").strip().upper()
        if not code:
            candidate = str(exc).strip().upper()
            code = candidate if _REASON_RE.fullmatch(candidate) else fallback
        return code if _REASON_RE.fullmatch(code) else fallback

    def _bind_invocations(self, compiled_plan: CompiledRuntimePlan) -> None:
        try:
            self.invocation_bundle.validate(compiled_plan)
            self.invocation_binding_store.bind(
                compiled_plan=compiled_plan,
                invocation_bundle=self.invocation_bundle,
            )
        except RuntimeInvocationBindingError as exc:
            raise RuntimeSchedulerError(str(exc)) from exc

    def _bind_sources(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        task_contract: TaskContract,
    ) -> None:
        if self.source_binding_bundle is None:
            return
        if self.source_binding_store is None:
            raise RuntimeSchedulerError("DURABLE_SOURCE_BINDING_STORE_REQUIRED")
        try:
            self.source_binding_bundle.validate(
                compiled_plan=compiled_plan,
                task_contract=task_contract,
                registry=self.registry,
            )
            self.source_binding_store.bind(
                compiled_plan=compiled_plan,
                task_contract=task_contract,
                source_binding_bundle=self.source_binding_bundle,
                registry=self.registry,
            )
        except (RuntimeSourceBindingStoreError, RuntimeSourceAuthorityDenied) as exc:
            raise RuntimeSchedulerError(str(exc)) from exc

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
        # Bind all semantic inputs before any RUNNING checkpoint or external I/O.
        self._bind_invocations(compiled_plan)
        self._bind_sources(
            compiled_plan=compiled_plan,
            task_contract=task_contract,
        )
        return super().run(
            compiled_plan=compiled_plan,
            task_contract=task_contract,
            budget=budget,
            approved_node_ids=approved_node_ids,
            checkpoint=checkpoint,
        )

    def _failed_observation(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        node: ExecutionNode,
        reason_code: str,
        result: object,
        denied: bool = False,
        evidence_refs: tuple[str, ...] = (),
    ) -> tuple[ExecutionObservation, bool]:
        try:
            observation = ExecutionObservation.capture(
                plan=compiled_plan.plan,
                node_id=node.node_id,
                status="denied" if denied else "failed",
                reason_code=reason_code,
                result=result,
                evidence_refs=evidence_refs,
            )
        except RuntimeExecutionPlanError:
            observation = ExecutionObservation.capture(
                plan=compiled_plan.plan,
                node_id=node.node_id,
                status="failed",
                reason_code="ADAPTER_RESULT_INVALID",
                result={"execution": "invalid_failure_metadata"},
            )
        return observation, False

    def _invoke_node(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        node: ExecutionNode,
        budget: ExecutionBudgetLike,
    ) -> tuple[ExecutionObservation, bool]:
        # Single-owner budget accounting: scheduler owns steps only. The reviewed
        # capability boundary owns tool_calls and charges after live authorization.
        try:
            budget.assert_active()
            budget.reserve(steps=1)
        except Exception as exc:
            return self._failed_observation(
                compiled_plan=compiled_plan,
                node=node,
                reason_code=self._reason_from_exception(exc, "EXECUTION_BUDGET_DENIED"),
                result={"execution": "step_budget_denied"},
                denied=True,
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
            return self._failed_observation(
                compiled_plan=compiled_plan,
                node=node,
                reason_code="ADAPTER_TIMEOUT",
                result={"execution": "timeout"},
            )
        except _DENIAL_ERRORS as exc:
            return self._failed_observation(
                compiled_plan=compiled_plan,
                node=node,
                reason_code=self._reason_from_exception(exc, "CAPABILITY_BOUNDARY_DENIED"),
                result={"execution": "capability_denied"},
                denied=True,
            )
        except Exception as exc:
            return self._failed_observation(
                compiled_plan=compiled_plan,
                node=node,
                reason_code=self._reason_from_exception(exc, "ADAPTER_EXCEPTION"),
                result={"exception_type": type(exc).__name__},
            )

        if time.monotonic() > invocation.deadline_monotonic:
            return self._failed_observation(
                compiled_plan=compiled_plan,
                node=node,
                reason_code="ADAPTER_TIMEOUT_EXCEEDED",
                result={"execution": "late_result_discarded"},
            )
        if not isinstance(result, ProductionNodeExecutionResult):
            return self._failed_observation(
                compiled_plan=compiled_plan,
                node=node,
                reason_code="PRODUCTION_ADAPTER_RESULT_REQUIRED",
                result={"execution": "legacy_result_rejected"},
            )
        if not isinstance(result.succeeded, bool):
            return self._failed_observation(
                compiled_plan=compiled_plan,
                node=node,
                reason_code="ADAPTER_RESULT_INVALID",
                result={"execution": "invalid_success_flag"},
            )

        reason = self._safe_reason(result.reason_code)
        if reason == "ADAPTER_RESULT_INVALID":
            return self._failed_observation(
                compiled_plan=compiled_plan,
                node=node,
                reason_code=reason,
                result={"execution": "invalid_reason_code"},
            )
        if not result.succeeded and reason == "EXECUTION_OK":
            return self._failed_observation(
                compiled_plan=compiled_plan,
                node=node,
                reason_code="PRODUCTION_FAILURE_REASON_REQUIRED",
                result={"execution": "missing_failure_reason"},
                evidence_refs=tuple(result.evidence_refs),
            )

        evidence_refs = tuple(result.evidence_refs)
        descriptor = self._descriptor(node)
        if result.succeeded and (
            compiled_plan.plan.evidence_required or descriptor.evidence_default
        ) and not evidence_refs:
            return self._failed_observation(
                compiled_plan=compiled_plan,
                node=node,
                reason_code="EVIDENCE_REQUIRED_MISSING",
                result={"execution": "evidence_missing"},
            )

        try:
            observation = ExecutionObservation.capture(
                plan=compiled_plan.plan,
                node_id=node.node_id,
                status="succeeded" if result.succeeded else "failed",
                reason_code=reason,
                result=result.result,
                evidence_refs=evidence_refs,
            )
        except RuntimeExecutionPlanError:
            return self._failed_observation(
                compiled_plan=compiled_plan,
                node=node,
                reason_code="ADAPTER_RESULT_INVALID",
                result={"execution": "invalid_adapter_metadata"},
            )
        return observation, result.succeeded
