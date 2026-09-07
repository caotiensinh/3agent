from __future__ import annotations

import re
import time
from dataclasses import dataclass

from .capability_authority import CapabilityAuthorityDenied
from .execution_budget import ExecutionBudgetExceeded
from .runtime_audited_scheduler import AuditedRuntimeDAGScheduler
from .runtime_capability_boundary import RuntimeCapabilityBoundaryError
from .runtime_execution_plan import ExecutionNode, ExecutionObservation, RuntimeExecutionPlanError
from .runtime_plan_compiler import CompiledRuntimePlan
from .runtime_scheduler import (
    CapabilityAdapterRegistry,
    CapabilityInvocation,
    ExecutionBudgetLike,
    NodeExecutionResult,
    RuntimeSchedulerError,
)

RUNTIME_PRODUCTION_SCHEDULER_SCHEMA = "workspace-runtime-production-scheduler/v1"
_REASON_RE = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{0,127}$")
_DENIAL_ERRORS = (
    CapabilityAuthorityDenied,
    ExecutionBudgetExceeded,
    RuntimeCapabilityBoundaryError,
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
    """

    schema_version = RUNTIME_PRODUCTION_SCHEDULER_SCHEMA

    def __init__(self, *, adapters: CapabilityAdapterRegistry, **kwargs):
        if not bool(getattr(adapters, "boundary_accounted", False)):
            raise RuntimeSchedulerError("PRODUCTION_ADAPTERS_MUST_BE_BOUNDARY_ACCOUNTED")
        super().__init__(adapters=adapters, **kwargs)

    @staticmethod
    def _reason_from_exception(exc: Exception, fallback: str) -> str:
        code = str(getattr(exc, "reason_code", "") or "").strip().upper()
        if not code:
            candidate = str(exc).strip().upper()
            code = candidate if _REASON_RE.fullmatch(candidate) else fallback
        return code if _REASON_RE.fullmatch(code) else fallback

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
