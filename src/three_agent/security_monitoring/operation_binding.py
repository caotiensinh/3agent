from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Iterable

from .capability_registry import (
    SecurityCapabilityDenied,
    SecurityCapabilityError,
    SecurityCapabilityRegistry,
)
from .operation_plan import SecurityOperationPlan, SecurityOperationPlanError

SECURITY_OPERATION_BINDING_SCHEMA = "workspace-security-operation-binding/v1"
SECURITY_BINDING_COVERAGE_SCHEMA = "workspace-security-operation-binding-coverage/v1"
SECURITY_PLAN_BINDING_SCHEMA = "workspace-security-plan-binding/v1"
SECURITY_STEP_BINDING_SCHEMA = "workspace-security-step-binding/v1"

_BINDING_STATUSES = frozenset({"bound", "unbound"})
_HANDLER_KINDS = frozenset(
    {"typed_dispatch", "bounded_local_adapter", "pure_function", "advisory_service"}
)
_HANDLER_ID_RE = re.compile(r"^[a-z][a-z0-9_.-]{2,127}$")
_REASON_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")

# Closed symbolic IDs. These are deliberately not Python import paths and are never
# interpreted with importlib/eval/getattr. Runtime existence is attested through the
# explicit if/elif resolver at the bottom of this module.
CLOSED_HANDLER_IDS = frozenset(
    {
        "monitoring.dispatch.snmpv3_read",
        "monitoring.dispatch.local_net_read",
        "monitoring.passive_jsonl.read_batch",
        "analysis.dns_behavior.extract_features",
        "analysis.local_ai_analyst.analyze",
    }
)


class SecurityOperationBindingError(ValueError):
    """A binding manifest is invalid or inconsistent with the approved registry."""


class SecurityOperationHandlerUnbound(PermissionError):
    """A reviewed operation has no admitted runtime handler yet."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class SecurityOperationBinding:
    capability_id: str
    operation_id: str
    status: str
    reason_code: str
    handler_id: str | None = None
    handler_kind: str | None = None
    schema_version: str = SECURITY_OPERATION_BINDING_SCHEMA

    def validate(self) -> "SecurityOperationBinding":
        if self.status not in _BINDING_STATUSES:
            raise SecurityOperationBindingError(f"unsupported binding status: {self.status}")
        if not _REASON_RE.fullmatch(str(self.reason_code or "")):
            raise SecurityOperationBindingError("binding reason_code must be a compact constant")
        if self.status == "bound":
            if self.handler_id not in CLOSED_HANDLER_IDS:
                raise SecurityOperationBindingError("bound handler_id is not in the closed handler set")
            if not _HANDLER_ID_RE.fullmatch(str(self.handler_id or "")):
                raise SecurityOperationBindingError("handler_id must be a compact symbolic identifier")
            if self.handler_kind not in _HANDLER_KINDS:
                raise SecurityOperationBindingError("bound handler_kind is unsupported")
            if self.reason_code != "BOUND_TO_REVIEWED_RUNTIME_HANDLER":
                raise SecurityOperationBindingError("bound operation must use reviewed binding reason")
        else:
            if self.handler_id is not None or self.handler_kind is not None:
                raise SecurityOperationBindingError("unbound operation cannot expose a handler")
            if not self.reason_code.startswith("UNBOUND_"):
                raise SecurityOperationBindingError("unbound operation must declare explicit debt reason")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class SecurityBindingCoverage:
    total_operations: int
    bound_operations: int
    unbound_operations: int
    bound_percent: float
    unbound_operation_refs: tuple[str, ...]
    registry_fingerprint: str
    binding_fingerprint: str
    schema_version: str = SECURITY_BINDING_COVERAGE_SCHEMA

    def validate(self) -> "SecurityBindingCoverage":
        if self.total_operations < 1:
            raise SecurityOperationBindingError("binding coverage requires operations")
        if self.bound_operations + self.unbound_operations != self.total_operations:
            raise SecurityOperationBindingError("binding coverage counts are inconsistent")
        expected = round((self.bound_operations / self.total_operations) * 100.0, 3)
        if self.bound_percent != expected:
            raise SecurityOperationBindingError("binding coverage percent is inconsistent")
        if len(self.unbound_operation_refs) != self.unbound_operations:
            raise SecurityOperationBindingError("unbound operation refs do not match coverage count")
        if tuple(sorted(set(self.unbound_operation_refs))) != self.unbound_operation_refs:
            raise SecurityOperationBindingError("unbound operation refs must be sorted and unique")
        for value in (self.registry_fingerprint, self.binding_fingerprint):
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
                raise SecurityOperationBindingError("coverage fingerprints must be SHA-256")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "total_operations": self.total_operations,
            "bound_operations": self.bound_operations,
            "unbound_operations": self.unbound_operations,
            "bound_percent": self.bound_percent,
            "unbound_operation_refs": list(self.unbound_operation_refs),
            "registry_fingerprint": self.registry_fingerprint,
            "binding_fingerprint": self.binding_fingerprint,
        }


@dataclass(frozen=True)
class SecurityStepBinding:
    step_id: str
    capability_id: str
    operation_id: str
    status: str
    reason_code: str
    handler_id: str | None
    handler_kind: str | None
    schema_version: str = SECURITY_STEP_BINDING_SCHEMA

    def public_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class SecurityPlanBinding:
    plan_fingerprint: str
    status: str
    steps: tuple[SecurityStepBinding, ...]
    binding_fingerprint: str
    authority: str = "advisory"
    execution_authorized: bool = False
    schema_version: str = SECURITY_PLAN_BINDING_SCHEMA

    def validate(self) -> "SecurityPlanBinding":
        if self.status not in {"all_bound", "partial", "not_planned"}:
            raise SecurityOperationBindingError("unsupported plan binding status")
        if self.authority != "advisory" or self.execution_authorized:
            raise SecurityOperationBindingError("operation binding cannot authorize execution")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.plan_fingerprint):
            raise SecurityOperationBindingError("plan_fingerprint must be SHA-256")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.binding_fingerprint):
            raise SecurityOperationBindingError("binding_fingerprint must be SHA-256")
        if self.status == "not_planned" and self.steps:
            raise SecurityOperationBindingError("not_planned binding cannot contain steps")
        if self.status == "all_bound" and any(step.status != "bound" for step in self.steps):
            raise SecurityOperationBindingError("all_bound plan contains an unbound step")
        if self.status == "partial":
            if not self.steps or all(step.status == "bound" for step in self.steps):
                raise SecurityOperationBindingError("partial plan requires at least one unbound step")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "plan_fingerprint": self.plan_fingerprint,
            "status": self.status,
            "steps": [step.public_dict() for step in self.steps],
            "binding_fingerprint": self.binding_fingerprint,
            "authority": self.authority,
            "execution_authorized": self.execution_authorized,
        }


def _bound(
    capability_id: str,
    operation_id: str,
    handler_id: str,
    handler_kind: str,
) -> SecurityOperationBinding:
    return SecurityOperationBinding(
        capability_id=capability_id,
        operation_id=operation_id,
        status="bound",
        reason_code="BOUND_TO_REVIEWED_RUNTIME_HANDLER",
        handler_id=handler_id,
        handler_kind=handler_kind,
    )


def _unbound(
    capability_id: str,
    operation_id: str,
    reason_code: str,
) -> SecurityOperationBinding:
    return SecurityOperationBinding(
        capability_id=capability_id,
        operation_id=operation_id,
        status="unbound",
        reason_code=reason_code,
    )


# v0.4 intentionally binds only operations whose existing implementation contract
# matches the reviewed operation closely enough to be named without guesswork.
# Everything else remains explicit engineering debt rather than being mapped to a
# nearby-looking module.
DEFAULT_SECURITY_OPERATION_BINDINGS = (
    _unbound(
        "network.pcap.read",
        "read_capture",
        "UNBOUND_PCAP_EVIDENCE_READ_ADAPTER_REQUIRED",
    ),
    _unbound(
        "network.pcap.read",
        "read_capture_metadata",
        "UNBOUND_PCAP_METADATA_ADAPTER_REQUIRED",
    ),
    _unbound(
        "security.configuration_review.read",
        "read_configuration_snapshot",
        "UNBOUND_CONFIGURATION_EVIDENCE_ADAPTER_REQUIRED",
    ),
    _bound(
        "network.interface.observe",
        "read_interface_counters",
        "monitoring.dispatch.snmpv3_read",
        "typed_dispatch",
    ),
    _bound(
        "network.flow.observe",
        "read_local_flow_evidence",
        "monitoring.dispatch.local_net_read",
        "typed_dispatch",
    ),
    _bound(
        "security.telemetry.observe",
        "read_fixed_telemetry",
        "monitoring.passive_jsonl.read_batch",
        "bounded_local_adapter",
    ),
    _bound(
        "network.dns.analyze",
        "analyze_dns_evidence",
        "analysis.dns_behavior.extract_features",
        "pure_function",
    ),
    _unbound(
        "network.flow.analyze",
        "analyze_flow_evidence",
        "UNBOUND_GENERIC_FLOW_ANALYSIS_CONTRACT_REQUIRED",
    ),
    _unbound(
        "security.authentication.analyze",
        "analyze_authentication_evidence",
        "UNBOUND_AUTHENTICATION_ANALYSIS_CONTRACT_REQUIRED",
    ),
    _unbound(
        "security.endpoint.analyze",
        "analyze_endpoint_evidence",
        "UNBOUND_ENDPOINT_ANALYSIS_CONTRACT_REQUIRED",
    ),
    _unbound(
        "security.ids.analyze",
        "triage_ids_evidence",
        "UNBOUND_IDS_TRIAGE_CONTRACT_REQUIRED",
    ),
    _bound(
        "security.incident_triage.analyze",
        "triage_findings",
        "analysis.local_ai_analyst.analyze",
        "advisory_service",
    ),
    _unbound(
        "security.incident_triage.analyze",
        "build_incident_timeline",
        "UNBOUND_TIMELINE_ADAPTER_REQUIRED",
    ),
    _unbound(
        "security.threat_hunting.analyze",
        "hunt_reviewed_evidence",
        "UNBOUND_THREAT_HUNTING_CONTRACT_REQUIRED",
    ),
    _unbound(
        "security.forensics.analyze",
        "analyze_forensic_evidence",
        "UNBOUND_FORENSICS_ANALYSIS_CONTRACT_REQUIRED",
    ),
)


class SecurityOperationBindingRegistry:
    """Closed operation -> runtime-handler admission manifest.

    This layer describes whether a reviewed operation has a canonical WorkSpace
    implementation. It never invokes the implementation. Side-effect authority remains
    in TaskCapabilityAuthority/MonitoringPolicyEngine; execution is a later boundary.
    """

    def __init__(
        self,
        registry: SecurityCapabilityRegistry | None = None,
        bindings: Iterable[SecurityOperationBinding] = DEFAULT_SECURITY_OPERATION_BINDINGS,
    ):
        self.registry = registry or SecurityCapabilityRegistry()
        rows = tuple(binding.validate() for binding in bindings)
        keys = [(row.capability_id, row.operation_id) for row in rows]
        if len(keys) != len(set(keys)):
            raise SecurityOperationBindingError("operation binding keys must be unique")

        expected = {
            (capability.capability_id, operation.operation_id)
            for capability in self.registry.list_approved()
            for operation in capability.operations
        }
        actual = set(keys)
        if actual != expected:
            missing = sorted(expected - actual)
            extra = sorted(actual - expected)
            raise SecurityOperationBindingError(
                f"operation binding coverage mismatch: missing={missing!r} extra={extra!r}"
            )

        # Re-resolve every key so a manifest cannot retain a retired/unknown operation.
        for row in rows:
            self.registry.resolve(row.capability_id, row.operation_id)
        self._bindings = {(row.capability_id, row.operation_id): row for row in rows}

    @property
    def fingerprint(self) -> str:
        payload = [
            self._bindings[key].public_dict()
            for key in sorted(self._bindings)
        ]
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def resolve(self, capability_id: str, operation_id: str) -> SecurityOperationBinding:
        self.registry.resolve(capability_id, operation_id)
        binding = self._bindings.get((capability_id, operation_id))
        if binding is None:
            raise SecurityOperationBindingError("approved operation is missing its binding record")
        return binding

    def require_bound(self, capability_id: str, operation_id: str) -> SecurityOperationBinding:
        binding = self.resolve(capability_id, operation_id)
        if binding.status != "bound":
            raise SecurityOperationHandlerUnbound(binding.reason_code)
        return binding

    def coverage(self) -> SecurityBindingCoverage:
        rows = tuple(self._bindings[key] for key in sorted(self._bindings))
        bound = tuple(row for row in rows if row.status == "bound")
        unbound = tuple(row for row in rows if row.status == "unbound")
        refs = tuple(
            sorted(f"{row.capability_id}#{row.operation_id}" for row in unbound)
        )
        total = len(rows)
        return SecurityBindingCoverage(
            total_operations=total,
            bound_operations=len(bound),
            unbound_operations=len(unbound),
            bound_percent=round((len(bound) / total) * 100.0, 3),
            unbound_operation_refs=refs,
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
                    handler_id=binding.handler_id,
                    handler_kind=binding.handler_kind,
                )
            )
        status = "all_bound" if all(row.status == "bound" for row in rows) else "partial"
        return SecurityPlanBinding(
            plan_fingerprint=plan.plan_fingerprint,
            status=status,
            steps=tuple(rows),
            binding_fingerprint=self.fingerprint,
        ).validate()


def reviewed_runtime_handler_exists(handler_id: str) -> bool:
    """Attest a CLOSED handler ID against a directly imported trusted target.

    No model output, manifest string, importlib, eval, executable lookup or shell is
    involved. Adding a new handler requires a code review that edits this function.
    """

    if handler_id not in CLOSED_HANDLER_IDS:
        return False
    if handler_id == "monitoring.dispatch.snmpv3_read":
        from .dispatch import DefaultCollectorDispatcher

        return callable(DefaultCollectorDispatcher)
    if handler_id == "monitoring.dispatch.local_net_read":
        from .dispatch import DefaultCollectorDispatcher

        return callable(DefaultCollectorDispatcher)
    if handler_id == "monitoring.passive_jsonl.read_batch":
        from .passive_sensors import PassiveJsonlSensorAdapter

        return callable(PassiveJsonlSensorAdapter.read_batch)
    if handler_id == "analysis.dns_behavior.extract_features":
        from .dns_behavior import extract_dns_behavior_features

        return callable(extract_dns_behavior_features)
    if handler_id == "analysis.local_ai_analyst.analyze":
        from .ai_analyst import LocalAIAnalyst

        return callable(LocalAIAnalyst.analyze)
    return False


def verify_reviewed_runtime_handlers(
    binding_registry: SecurityOperationBindingRegistry | None = None,
) -> dict[str, bool]:
    registry = binding_registry or SecurityOperationBindingRegistry()
    handler_ids = sorted(
        {
            binding.handler_id
            for binding in registry._bindings.values()
            if binding.status == "bound" and binding.handler_id is not None
        }
    )
    return {handler_id: reviewed_runtime_handler_exists(handler_id) for handler_id in handler_ids}
