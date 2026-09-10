from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from .capability_registry import SecurityCapabilityRegistry
from .incident_timeline import build_incident_timeline
from .operation_binding import (
    DEFAULT_SECURITY_OPERATION_BINDINGS,
    SecurityBindingCoverage,
    SecurityOperationBinding,
    SecurityOperationBindingError,
    SecurityOperationHandlerUnbound,
    SecurityPlanBinding,
    SecurityStepBinding,
)
from .operation_plan import SecurityOperationPlan, SecurityOperationPlanError

INCIDENT_TIMELINE_HANDLER_ID = "analysis.incident_timeline.build"
INCIDENT_TIMELINE_OUTPUT_KIND = "incident_timeline"
INCIDENT_TIMELINE_OPERATION_KEY = (
    "security.incident_triage.analyze",
    "build_incident_timeline",
)


@dataclass(frozen=True)
class IncidentTimelineReviewedOperationBinding:
    capability_id: str
    operation_id: str
    status: str
    reason_code: str
    handler_id: str
    handler_kind: str = "pure_function"
    output_kind: str = INCIDENT_TIMELINE_OUTPUT_KIND
    schema_version: str = "workspace-security-operation-binding/v1"

    def validate(self) -> "IncidentTimelineReviewedOperationBinding":
        if (self.capability_id, self.operation_id) != INCIDENT_TIMELINE_OPERATION_KEY:
            raise SecurityOperationBindingError("incident timeline reviewed binding key mismatch")
        if self.status != "bound" or self.reason_code != "BOUND_TO_REVIEWED_RUNTIME_HANDLER":
            raise SecurityOperationBindingError("incident timeline reviewed binding must remain explicitly bound")
        if self.handler_id != INCIDENT_TIMELINE_HANDLER_ID:
            raise SecurityOperationBindingError("incident timeline reviewed binding handler mismatch")
        if self.handler_kind != "pure_function":
            raise SecurityOperationBindingError("incident timeline handler_kind must be pure_function")
        if self.output_kind != INCIDENT_TIMELINE_OUTPUT_KIND:
            raise SecurityOperationBindingError("incident timeline output_kind mismatch")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)


INCIDENT_TIMELINE_REVIEWED_BINDING = IncidentTimelineReviewedOperationBinding(
    capability_id=INCIDENT_TIMELINE_OPERATION_KEY[0],
    operation_id=INCIDENT_TIMELINE_OPERATION_KEY[1],
    status="bound",
    reason_code="BOUND_TO_REVIEWED_RUNTIME_HANDLER",
    handler_id=INCIDENT_TIMELINE_HANDLER_ID,
)


def reviewed_incident_timeline_runtime_handler_exists(handler_id: str) -> bool:
    if handler_id != INCIDENT_TIMELINE_HANDLER_ID:
        return False
    return callable(build_incident_timeline)


class IncidentTimelineSecurityOperationBindingRegistry:
    """Opt-in profile that replaces exactly the timeline debt record."""

    def __init__(self, registry: SecurityCapabilityRegistry | None = None) -> None:
        self.registry = registry or SecurityCapabilityRegistry()
        replacement = INCIDENT_TIMELINE_REVIEWED_BINDING.validate()
        rows: list[SecurityOperationBinding | IncidentTimelineReviewedOperationBinding] = []
        replacement_count = 0
        for raw in DEFAULT_SECURITY_OPERATION_BINDINGS:
            if (raw.capability_id, raw.operation_id) == INCIDENT_TIMELINE_OPERATION_KEY:
                rows.append(replacement)
                replacement_count += 1
            else:
                rows.append(raw.validate())
        if replacement_count != 1:
            raise SecurityOperationBindingError("incident timeline profile must replace exactly one default binding")

        expected = {
            (capability.capability_id, operation.operation_id)
            for capability in self.registry.list_approved()
            for operation in capability.operations
        }
        actual = {(row.capability_id, row.operation_id) for row in rows}
        if actual != expected:
            raise SecurityOperationBindingError("incident timeline profile does not exactly cover approved registry")
        for row in rows:
            self.registry.resolve(row.capability_id, row.operation_id)
        self._bindings = {(row.capability_id, row.operation_id): row for row in rows}

    @property
    def fingerprint(self) -> str:
        payload = [self._bindings[key].public_dict() for key in sorted(self._bindings)]
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def resolve(self, capability_id: str, operation_id: str):
        self.registry.resolve(capability_id, operation_id)
        row = self._bindings.get((capability_id, operation_id))
        if row is None:
            raise SecurityOperationBindingError("approved operation is missing incident timeline profile binding")
        return row

    def require_bound(self, capability_id: str, operation_id: str):
        row = self.resolve(capability_id, operation_id)
        if row.status != "bound":
            raise SecurityOperationHandlerUnbound(row.reason_code)
        return row

    def coverage(self) -> SecurityBindingCoverage:
        rows = tuple(self._bindings[key] for key in sorted(self._bindings))
        bound = tuple(row for row in rows if row.status == "bound")
        unbound = tuple(row for row in rows if row.status == "unbound")
        total = len(rows)
        return SecurityBindingCoverage(
            total_operations=total,
            bound_operations=len(bound),
            unbound_operations=len(unbound),
            bound_percent=round((len(bound) / total) * 100.0, 3),
            unbound_operation_refs=tuple(
                sorted(f"{row.capability_id}#{row.operation_id}" for row in unbound)
            ),
            registry_fingerprint=self.registry.fingerprint,
            binding_fingerprint=self.fingerprint,
        ).validate()

    def bind_plan(self, plan: SecurityOperationPlan) -> SecurityPlanBinding:
        plan.validate()
        if plan.registry_fingerprint != self.registry.fingerprint:
            raise SecurityOperationPlanError("PLAN_BINDING_REGISTRY_FINGERPRINT_MISMATCH")
        if plan.status != "planned":
            return SecurityPlanBinding(
                plan_fingerprint=plan.plan_fingerprint,
                status="not_planned",
                steps=(),
                binding_fingerprint=self.fingerprint,
            ).validate()

        rows: list[SecurityStepBinding] = []
        for step in plan.steps:
            binding = self.resolve(step.capability_id, step.operation_id)
            rows.append(
                SecurityStepBinding(
                    step_id=step.step_id,
                    capability_id=step.capability_id,
                    operation_id=step.operation_id,
                    status=binding.status,
                    reason_code=binding.reason_code,
                    handler_id=binding.handler_id if binding.status == "bound" else None,
                    handler_kind=binding.handler_kind if binding.status == "bound" else None,
                )
            )
        status = "all_bound" if all(row.status == "bound" for row in rows) else "partial"
        return SecurityPlanBinding(
            plan_fingerprint=plan.plan_fingerprint,
            status=status,
            steps=tuple(rows),
            binding_fingerprint=self.fingerprint,
        ).validate()
