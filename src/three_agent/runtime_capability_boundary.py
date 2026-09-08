from __future__ import annotations

from dataclasses import dataclass

from .capability_authority import CapabilityAuthorityDenied, CapabilityDecision
from .capability_revocation import TaskCapabilityRevocationStore
from .inference_scope import (
    current_capability_authority,
    current_execution_budget,
    current_inference_scope,
)
from .resource_events import ResourceEventRecorder

RUNTIME_CAPABILITY_BOUNDARY_SCHEMA = "workspace-runtime-capability-boundary/v1"


class RuntimeCapabilityBoundaryError(RuntimeError):
    pass


@dataclass(frozen=True)
class RuntimeCapabilityBoundaryReceipt:
    task_id: str
    capability: str
    resource_kind: str
    resource_ref: str
    effect: str
    authority_fingerprint: str
    tool_call_charged: bool = True
    schema_version: str = RUNTIME_CAPABILITY_BOUNDARY_SCHEMA

    def metadata(self) -> dict[str, str | bool]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "capability": self.capability,
            "resource_kind": self.resource_kind,
            "resource_ref": self.resource_ref,
            "effect": self.effect,
            "authority_fingerprint": self.authority_fingerprint,
            "tool_call_charged": self.tool_call_charged,
        }


def require_runtime_capability(
    capability: str,
    *,
    task_id: str,
    resource_kind: str,
    resource_ref: str,
    effect: str,
    recorder: ResourceEventRecorder | None = None,
    actor_id: str = "runtime_node",
    action: str = "runtime_capability_call",
) -> tuple[CapabilityDecision, RuntimeCapabilityBoundaryReceipt]:
    """Authorize and meter one production runtime capability invocation.

    Unlike the compatibility-oriented legacy metered helpers, this production
    boundary fails closed when trusted scope, capability authority, or persistent
    execution budget is absent. Revocation is checked live immediately before the
    atomic tool-call reservation.
    """

    scope = current_inference_scope()
    authority = current_capability_authority()
    budget = current_execution_budget()
    normalized_task = str(task_id).strip()
    if scope is None:
        raise RuntimeCapabilityBoundaryError("RUNTIME_CAPABILITY_SCOPE_REQUIRED")
    if authority is None:
        raise RuntimeCapabilityBoundaryError("RUNTIME_CAPABILITY_AUTHORITY_REQUIRED")
    if budget is None:
        raise RuntimeCapabilityBoundaryError("RUNTIME_CAPABILITY_BUDGET_REQUIRED")
    if (
        not normalized_task
        or scope.task_id != normalized_task
        or authority.task_id != normalized_task
        or budget.task_id != normalized_task
    ):
        raise RuntimeCapabilityBoundaryError("RUNTIME_CAPABILITY_TASK_SCOPE_MISMATCH")

    decision = authority.require(
        capability,
        resource_kind=resource_kind,
        resource_ref=resource_ref,
        effect=effect,
    )
    if TaskCapabilityRevocationStore(budget.store).is_revoked(
        normalized_task,
        capability,
    ):
        raise CapabilityAuthorityDenied("CAPABILITY_REVOKED", decision)

    budget.assert_active()
    budget.reserve(tool_calls=1)
    if recorder is not None:
        recorder.record(
            "tool_call",
            task_id=normalized_task,
            actor_id=actor_id,
            action=action,
            reason_code="TOOL_CALL_ATTEMPT",
            target=capability,
        )
    return decision, RuntimeCapabilityBoundaryReceipt(
        task_id=normalized_task,
        capability=str(capability),
        resource_kind=str(resource_kind),
        resource_ref=str(resource_ref),
        effect=str(effect),
        authority_fingerprint=authority.fingerprint,
    )
