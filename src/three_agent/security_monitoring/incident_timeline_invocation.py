from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from .capability_registry import SecurityCapabilityRegistry
from .contracts import MonitoringContractError, sha256_fingerprint
from .correlation_graph import CorrelationEvent
from .incident_timeline import MAX_INCIDENT_TIMELINE_EVENTS, IncidentTimeline, build_incident_timeline
from .incident_timeline_binding import (
    INCIDENT_TIMELINE_HANDLER_ID,
    INCIDENT_TIMELINE_OPERATION_KEY,
    INCIDENT_TIMELINE_OUTPUT_KIND,
    IncidentTimelineSecurityOperationBindingRegistry,
    reviewed_incident_timeline_runtime_handler_exists,
)
from .operation_invocation import (
    SecurityInvocationResult,
    SecurityOperationInvocationDenied,
    SecurityOperationInvocationError,
    SecurityOperationInvoker,
    SecurityTypedInvocationRequest,
)
from .operation_plan import SecurityOperationPlan, SecurityOperationStep

INCIDENT_TIMELINE_INVOCATION_RECEIPT_SCHEMA = "workspace-security-incident-timeline-invocation-receipt/v1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class IncidentTimelineInvocationRequest:
    """Typed normalized evidence only; never a path, target, credential or command."""

    events: tuple[CorrelationEvent, ...]

    def validate(self) -> "IncidentTimelineInvocationRequest":
        rows = tuple(self.events)
        if not rows or len(rows) > MAX_INCIDENT_TIMELINE_EVENTS:
            raise SecurityOperationInvocationError("incident timeline invocation event count is out of bounds")
        for item in rows:
            if not isinstance(item, CorrelationEvent):
                raise SecurityOperationInvocationError("incident timeline invocation requires CorrelationEvent")
            try:
                item.validate()
            except MonitoringContractError as exc:
                raise SecurityOperationInvocationError("incident timeline invocation contains invalid evidence") from exc
        object.__setattr__(self, "events", rows)
        return self

    @property
    def fingerprint(self) -> str:
        self.validate()
        rows = sorted(self.events, key=lambda item: (item.observed, item.event.event_id))
        return sha256_fingerprint(
            {
                "events": [
                    {
                        "event": asdict(item.event),
                        "context": item.context.public_dict(),
                        "stage": item.stage,
                    }
                    for item in rows
                ]
            }
        )


@dataclass(frozen=True)
class IncidentTimelineInvocationReceipt:
    invocation_id: str
    plan_fingerprint: str
    step_id: str
    capability_id: str
    operation_id: str
    handler_id: str
    handler_kind: str
    input_fingerprint: str
    output_fingerprint: str
    authority_domain: str
    authority_fingerprint: str
    authority_reason_code: str
    registry_fingerprint: str
    binding_fingerprint: str
    output_kind: str
    status: str = "completed"
    schema_version: str = INCIDENT_TIMELINE_INVOCATION_RECEIPT_SCHEMA

    def validate(self) -> "IncidentTimelineInvocationReceipt":
        if not re.fullmatch(r"invoke-[0-9a-f]{24}", self.invocation_id):
            raise SecurityOperationInvocationError("incident timeline invocation_id is invalid")
        for value in (
            self.plan_fingerprint,
            self.input_fingerprint,
            self.output_fingerprint,
            self.authority_fingerprint,
            self.registry_fingerprint,
            self.binding_fingerprint,
        ):
            if not _SHA256_RE.fullmatch(str(value or "")):
                raise SecurityOperationInvocationError("incident timeline receipt fingerprints must be SHA-256")
        if not re.fullmatch(r"step:[0-9a-f]{24}", self.step_id):
            raise SecurityOperationInvocationError("incident timeline receipt step_id is invalid")
        if (self.capability_id, self.operation_id) != INCIDENT_TIMELINE_OPERATION_KEY:
            raise SecurityOperationInvocationError("incident timeline receipt operation scope mismatch")
        if self.handler_id != INCIDENT_TIMELINE_HANDLER_ID or self.handler_kind != "pure_function":
            raise SecurityOperationInvocationError("incident timeline receipt handler is not reviewed")
        if self.output_kind != INCIDENT_TIMELINE_OUTPUT_KIND:
            raise SecurityOperationInvocationError("incident timeline receipt output_kind is invalid")
        if self.authority_domain != "internal":
            raise SecurityOperationInvocationError("incident timeline receipt must remain internal-domain")
        if self.authority_reason_code != "SECURITY_INTERNAL_OPERATION_AUTHORIZED":
            raise SecurityOperationInvocationError("incident timeline receipt requires internal authority")
        if self.status != "completed":
            raise SecurityOperationInvocationError("incident timeline v0.10 emits completed receipts only")
        expected = "invoke-" + sha256_fingerprint(self._identity_payload()).split(":", 1)[1][:24]
        if self.invocation_id != expected:
            raise SecurityOperationInvocationError("incident timeline invocation_id does not match receipt identity")
        return self

    def _identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "plan_fingerprint": self.plan_fingerprint,
            "step_id": self.step_id,
            "capability_id": self.capability_id,
            "operation_id": self.operation_id,
            "handler_id": self.handler_id,
            "handler_kind": self.handler_kind,
            "input_fingerprint": self.input_fingerprint,
            "output_fingerprint": self.output_fingerprint,
            "authority_domain": self.authority_domain,
            "authority_fingerprint": self.authority_fingerprint,
            "authority_reason_code": self.authority_reason_code,
            "registry_fingerprint": self.registry_fingerprint,
            "binding_fingerprint": self.binding_fingerprint,
            "output_kind": self.output_kind,
            "status": self.status,
        }

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {"invocation_id": self.invocation_id, **self._identity_payload()}


class IncidentTimelineSecurityOperationInvoker(SecurityOperationInvoker):
    """Opt-in internal L1 timeline builder over the existing deterministic gate."""

    def __init__(self, *, registry: SecurityCapabilityRegistry | None = None, **kwargs: Any) -> None:
        security_registry = registry or SecurityCapabilityRegistry()
        bindings = IncidentTimelineSecurityOperationBindingRegistry(security_registry)
        if "binding_registry" in kwargs:
            raise SecurityOperationInvocationError("incident timeline invoker owns its reviewed binding profile")
        super().__init__(registry=security_registry, binding_registry=bindings, **kwargs)

    def invoke(
        self,
        plan: SecurityOperationPlan,
        *,
        step_id: str,
        request: SecurityTypedInvocationRequest | IncidentTimelineInvocationRequest,
    ) -> SecurityInvocationResult:
        self._require_plan_integrity(plan)
        plan.validate()
        if plan.status != "planned":
            raise SecurityOperationInvocationDenied("INVOCATION_REQUIRES_PLANNED_OPERATION")
        if plan.registry_fingerprint != self.registry.fingerprint:
            raise SecurityOperationInvocationDenied("INVOCATION_REGISTRY_FINGERPRINT_MISMATCH")
        matching = [step for step in plan.steps if step.step_id == str(step_id or "").strip()]
        if len(matching) != 1:
            raise SecurityOperationInvocationDenied("INVOCATION_STEP_NOT_IN_PLAN")
        step = matching[0].validate()
        binding = self.binding_registry.require_bound(step.capability_id, step.operation_id)
        if binding.handler_id != INCIDENT_TIMELINE_HANDLER_ID:
            return super().invoke(plan, step_id=step.step_id, request=request)
        if not reviewed_incident_timeline_runtime_handler_exists(binding.handler_id):
            raise SecurityOperationInvocationDenied("INVOCATION_REVIEWED_HANDLER_UNAVAILABLE")
        if not isinstance(request, IncidentTimelineInvocationRequest):
            raise SecurityOperationInvocationDenied("INVOCATION_REQUEST_TYPE_MISMATCH")
        request.validate()

        expected_scope = (
            INCIDENT_TIMELINE_OPERATION_KEY[0],
            INCIDENT_TIMELINE_OPERATION_KEY[1],
            "security.incident_triage",
            "L1",
            "internal",
            None,
            "compute",
            "ready_internal",
        )
        actual_scope = (
            step.capability_id,
            step.operation_id,
            step.taxonomy_id,
            step.authority_level,
            step.authority_domain,
            step.backend_capability,
            step.effect,
            step.preflight_state,
        )
        if actual_scope != expected_scope:
            raise SecurityOperationInvocationDenied("INVOCATION_INCIDENT_TIMELINE_SCOPE_MISMATCH")

        authorization = self.compiler.authorize_internal_step(step)
        self._validate_authorization(step, authorization)
        output = build_incident_timeline(request.events)
        if not isinstance(output, IncidentTimeline):
            raise SecurityOperationInvocationError("incident timeline reviewed handler returned unexpected type")
        receipt = self._receipt(
            plan=plan,
            step=step,
            input_fingerprint=request.fingerprint,
            output_fingerprint=output.fingerprint,
            authority_fingerprint=authorization.authority_fingerprint,
            authority_reason_code=authorization.reason_code,
        )
        return SecurityInvocationResult(receipt=receipt, output=output)

    def _receipt(
        self,
        *,
        plan: SecurityOperationPlan,
        step: SecurityOperationStep,
        input_fingerprint: str,
        output_fingerprint: str,
        authority_fingerprint: str,
        authority_reason_code: str,
    ) -> IncidentTimelineInvocationReceipt:
        payload = {
            "schema_version": INCIDENT_TIMELINE_INVOCATION_RECEIPT_SCHEMA,
            "plan_fingerprint": plan.plan_fingerprint,
            "step_id": step.step_id,
            "capability_id": step.capability_id,
            "operation_id": step.operation_id,
            "handler_id": INCIDENT_TIMELINE_HANDLER_ID,
            "handler_kind": "pure_function",
            "input_fingerprint": input_fingerprint,
            "output_fingerprint": output_fingerprint,
            "authority_domain": "internal",
            "authority_fingerprint": authority_fingerprint,
            "authority_reason_code": authority_reason_code,
            "registry_fingerprint": self.registry.fingerprint,
            "binding_fingerprint": self.binding_registry.fingerprint,
            "output_kind": INCIDENT_TIMELINE_OUTPUT_KIND,
            "status": "completed",
        }
        invocation_id = "invoke-" + sha256_fingerprint(payload).split(":", 1)[1][:24]
        return IncidentTimelineInvocationReceipt(
            invocation_id=invocation_id,
            **{key: value for key, value in payload.items() if key != "schema_version"},
        ).validate()

    @property
    def runtime_fingerprint(self) -> str:
        return sha256_fingerprint(
            {
                "base_runtime_fingerprint": super().runtime_fingerprint,
                "incident_timeline_binding_fingerprint": self.binding_registry.fingerprint,
                "incident_timeline_handler_id": INCIDENT_TIMELINE_HANDLER_ID,
            }
        )
