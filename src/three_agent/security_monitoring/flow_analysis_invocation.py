from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any

from .capability_registry import SecurityCapabilityRegistry
from .contracts import MonitoringContractError, sha256_fingerprint
from .correlation_graph import CorrelationEvent
from .flow_analysis import (
    MAX_FLOW_ANALYSIS_EVENTS,
    FlowEvidenceAnalysis,
    analyze_flow_evidence,
)
from .operation_binding import (
    DEFAULT_SECURITY_OPERATION_BINDINGS,
    SecurityBindingCoverage,
    SecurityOperationBinding,
    SecurityOperationBindingError,
    SecurityOperationHandlerUnbound,
    SecurityPlanBinding,
    SecurityStepBinding,
)
from .operation_invocation import (
    SecurityInvocationResult,
    SecurityOperationInvocationDenied,
    SecurityOperationInvocationError,
    SecurityOperationInvoker,
    SecurityTypedInvocationRequest,
)
from .operation_plan import SecurityOperationPlan, SecurityOperationPlanError, SecurityOperationStep

FLOW_ANALYSIS_INVOCATION_RECEIPT_SCHEMA = "workspace-security-flow-analysis-invocation-receipt/v1"
FLOW_ANALYSIS_HANDLER_ID = "analysis.flow_evidence.analyze"
FLOW_ANALYSIS_OUTPUT_KIND = "flow_evidence_analysis"
_FLOW_ANALYSIS_KEY = ("network.flow.analyze", "analyze_flow_evidence")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class FlowAnalysisReviewedOperationBinding:
    capability_id: str
    operation_id: str
    status: str
    reason_code: str
    handler_id: str
    handler_kind: str = "pure_function"
    output_kind: str = FLOW_ANALYSIS_OUTPUT_KIND
    schema_version: str = "workspace-security-operation-binding/v1"

    def validate(self) -> "FlowAnalysisReviewedOperationBinding":
        if (self.capability_id, self.operation_id) != _FLOW_ANALYSIS_KEY:
            raise SecurityOperationBindingError("flow analysis reviewed binding key mismatch")
        if self.status != "bound" or self.reason_code != "BOUND_TO_REVIEWED_RUNTIME_HANDLER":
            raise SecurityOperationBindingError("flow analysis reviewed binding must remain explicitly bound")
        if self.handler_id != FLOW_ANALYSIS_HANDLER_ID:
            raise SecurityOperationBindingError("flow analysis reviewed binding handler mismatch")
        if self.handler_kind != "pure_function":
            raise SecurityOperationBindingError("flow analysis handler_kind must be pure_function")
        if self.output_kind != FLOW_ANALYSIS_OUTPUT_KIND:
            raise SecurityOperationBindingError("flow analysis output_kind mismatch")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)


FLOW_ANALYSIS_REVIEWED_BINDING = FlowAnalysisReviewedOperationBinding(
    capability_id=_FLOW_ANALYSIS_KEY[0],
    operation_id=_FLOW_ANALYSIS_KEY[1],
    status="bound",
    reason_code="BOUND_TO_REVIEWED_RUNTIME_HANDLER",
    handler_id=FLOW_ANALYSIS_HANDLER_ID,
)


def reviewed_flow_analysis_runtime_handler_exists(handler_id: str) -> bool:
    """Attest the single v0.9 flow handler with a direct trusted reference only."""

    if handler_id != FLOW_ANALYSIS_HANDLER_ID:
        return False
    return callable(analyze_flow_evidence)


class FlowAnalysisSecurityOperationBindingRegistry:
    """Opt-in profile that replaces only generic flow-analysis engineering debt."""

    def __init__(self, registry: SecurityCapabilityRegistry | None = None) -> None:
        self.registry = registry or SecurityCapabilityRegistry()
        replacement = FLOW_ANALYSIS_REVIEWED_BINDING.validate()
        rows: list[SecurityOperationBinding | FlowAnalysisReviewedOperationBinding] = []
        replacement_count = 0
        for raw in DEFAULT_SECURITY_OPERATION_BINDINGS:
            key = (raw.capability_id, raw.operation_id)
            if key == _FLOW_ANALYSIS_KEY:
                rows.append(replacement)
                replacement_count += 1
            else:
                rows.append(raw.validate())
        if replacement_count != 1:
            raise SecurityOperationBindingError("flow analysis profile must replace exactly one default binding")

        expected = {
            (capability.capability_id, operation.operation_id)
            for capability in self.registry.list_approved()
            for operation in capability.operations
        }
        actual = {(row.capability_id, row.operation_id) for row in rows}
        if actual != expected:
            raise SecurityOperationBindingError("flow analysis profile does not exactly cover approved registry")
        for row in rows:
            self.registry.resolve(row.capability_id, row.operation_id)
        self._bindings = {(row.capability_id, row.operation_id): row for row in rows}

    @property
    def fingerprint(self) -> str:
        payload = [self._bindings[key].public_dict() for key in sorted(self._bindings)]
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def resolve(self, capability_id: str, operation_id: str):
        self.registry.resolve(capability_id, operation_id)
        row = self._bindings.get((capability_id, operation_id))
        if row is None:
            raise SecurityOperationBindingError("approved operation is missing flow-analysis profile binding")
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
            unbound_operation_refs=tuple(sorted(f"{row.capability_id}#{row.operation_id}" for row in unbound)),
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


@dataclass(frozen=True)
class FlowAnalysisInvocationRequest:
    """Typed normalized evidence only; no path, target, credential or runtime selector."""

    events: tuple[CorrelationEvent, ...]

    def validate(self) -> "FlowAnalysisInvocationRequest":
        rows = tuple(self.events)
        if not rows or len(rows) > MAX_FLOW_ANALYSIS_EVENTS:
            raise SecurityOperationInvocationError("flow analysis invocation event count is out of bounds")
        for item in rows:
            if not isinstance(item, CorrelationEvent):
                raise SecurityOperationInvocationError("flow analysis invocation requires CorrelationEvent")
            try:
                item.validate()
            except MonitoringContractError as exc:
                raise SecurityOperationInvocationError("flow analysis invocation contains invalid evidence") from exc
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
class FlowAnalysisInvocationReceipt:
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
    schema_version: str = FLOW_ANALYSIS_INVOCATION_RECEIPT_SCHEMA

    def validate(self) -> "FlowAnalysisInvocationReceipt":
        if not re.fullmatch(r"invoke-[0-9a-f]{24}", self.invocation_id):
            raise SecurityOperationInvocationError("flow analysis invocation_id is invalid")
        for value in (
            self.plan_fingerprint,
            self.input_fingerprint,
            self.output_fingerprint,
            self.authority_fingerprint,
            self.registry_fingerprint,
            self.binding_fingerprint,
        ):
            if not _SHA256_RE.fullmatch(str(value or "")):
                raise SecurityOperationInvocationError("flow analysis receipt fingerprints must be SHA-256")
        if not re.fullmatch(r"step:[0-9a-f]{24}", self.step_id):
            raise SecurityOperationInvocationError("flow analysis receipt step_id is invalid")
        if (self.capability_id, self.operation_id) != _FLOW_ANALYSIS_KEY:
            raise SecurityOperationInvocationError("flow analysis receipt operation scope mismatch")
        if self.handler_id != FLOW_ANALYSIS_HANDLER_ID or self.handler_kind != "pure_function":
            raise SecurityOperationInvocationError("flow analysis receipt handler is not reviewed")
        if self.output_kind != FLOW_ANALYSIS_OUTPUT_KIND:
            raise SecurityOperationInvocationError("flow analysis receipt output_kind is invalid")
        if self.authority_domain != "internal":
            raise SecurityOperationInvocationError("flow analysis receipt must remain internal-domain")
        if self.authority_reason_code != "SECURITY_INTERNAL_OPERATION_AUTHORIZED":
            raise SecurityOperationInvocationError("flow analysis receipt requires internal authority")
        if self.status != "completed":
            raise SecurityOperationInvocationError("flow analysis v0.9 emits completed receipts only")
        expected = "invoke-" + sha256_fingerprint(self._identity_payload()).split(":", 1)[1][:24]
        if self.invocation_id != expected:
            raise SecurityOperationInvocationError("flow analysis invocation_id does not match receipt identity")
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


class FlowAnalysisSecurityOperationInvoker(SecurityOperationInvoker):
    """Opt-in internal L1 flow analyzer over the existing deterministic gate."""

    def __init__(
        self,
        *,
        registry: SecurityCapabilityRegistry | None = None,
        **kwargs: Any,
    ) -> None:
        security_registry = registry or SecurityCapabilityRegistry()
        bindings = FlowAnalysisSecurityOperationBindingRegistry(security_registry)
        if "binding_registry" in kwargs:
            raise SecurityOperationInvocationError("flow analysis invoker owns its reviewed binding profile")
        super().__init__(registry=security_registry, binding_registry=bindings, **kwargs)

    def invoke(
        self,
        plan: SecurityOperationPlan,
        *,
        step_id: str,
        request: SecurityTypedInvocationRequest | FlowAnalysisInvocationRequest,
    ) -> SecurityInvocationResult:
        plan.validate()
        self._require_plan_integrity(plan)
        if plan.status != "planned":
            raise SecurityOperationInvocationDenied("INVOCATION_REQUIRES_PLANNED_OPERATION")
        if plan.registry_fingerprint != self.registry.fingerprint:
            raise SecurityOperationInvocationDenied("INVOCATION_REGISTRY_FINGERPRINT_MISMATCH")
        matching = [step for step in plan.steps if step.step_id == str(step_id or "").strip()]
        if len(matching) != 1:
            raise SecurityOperationInvocationDenied("INVOCATION_STEP_NOT_IN_PLAN")
        step = matching[0].validate()
        binding = self.binding_registry.require_bound(step.capability_id, step.operation_id)
        if binding.handler_id != FLOW_ANALYSIS_HANDLER_ID:
            return super().invoke(plan, step_id=step.step_id, request=request)
        if not reviewed_flow_analysis_runtime_handler_exists(binding.handler_id):
            raise SecurityOperationInvocationDenied("INVOCATION_REVIEWED_HANDLER_UNAVAILABLE")
        if not isinstance(request, FlowAnalysisInvocationRequest):
            raise SecurityOperationInvocationDenied("INVOCATION_REQUEST_TYPE_MISMATCH")
        request.validate()
        expected_scope = (
            _FLOW_ANALYSIS_KEY[0],
            _FLOW_ANALYSIS_KEY[1],
            "network.flow",
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
            raise SecurityOperationInvocationDenied("INVOCATION_FLOW_ANALYSIS_SCOPE_MISMATCH")
        authorization = self.compiler.authorize_internal_step(step)
        self._validate_authorization(step, authorization)
        output = analyze_flow_evidence(request.events)
        if not isinstance(output, FlowEvidenceAnalysis):
            raise SecurityOperationInvocationError("flow analysis reviewed handler returned unexpected type")
        receipt = self._flow_receipt(
            plan=plan,
            step=step,
            input_fingerprint=request.fingerprint,
            output_fingerprint=output.fingerprint,
            authority_fingerprint=authorization.authority_fingerprint,
            authority_reason_code=authorization.reason_code,
        )
        return SecurityInvocationResult(receipt=receipt, output=output)

    def _flow_receipt(
        self,
        *,
        plan: SecurityOperationPlan,
        step: SecurityOperationStep,
        input_fingerprint: str,
        output_fingerprint: str,
        authority_fingerprint: str,
        authority_reason_code: str,
    ) -> FlowAnalysisInvocationReceipt:
        payload = {
            "schema_version": FLOW_ANALYSIS_INVOCATION_RECEIPT_SCHEMA,
            "plan_fingerprint": plan.plan_fingerprint,
            "step_id": step.step_id,
            "capability_id": step.capability_id,
            "operation_id": step.operation_id,
            "handler_id": FLOW_ANALYSIS_HANDLER_ID,
            "handler_kind": "pure_function",
            "input_fingerprint": input_fingerprint,
            "output_fingerprint": output_fingerprint,
            "authority_domain": "internal",
            "authority_fingerprint": authority_fingerprint,
            "authority_reason_code": authority_reason_code,
            "registry_fingerprint": self.registry.fingerprint,
            "binding_fingerprint": self.binding_registry.fingerprint,
            "output_kind": FLOW_ANALYSIS_OUTPUT_KIND,
            "status": "completed",
        }
        invocation_id = "invoke-" + sha256_fingerprint(payload).split(":", 1)[1][:24]
        return FlowAnalysisInvocationReceipt(
            invocation_id=invocation_id,
            **{key: value for key, value in payload.items() if key != "schema_version"},
        ).validate()
