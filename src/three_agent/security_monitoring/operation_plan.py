from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass

from ..capability_authority import TaskCapabilityAuthority
from .capability_registry import (
    SecurityCapabilityDenied,
    SecurityCapabilityRegistry,
    SecurityOperationAuthorization,
)
from .capability_router import SecurityRoutingDecision
from .contracts import AssetInventoryRecord, SecretReference
from .policy import MonitoringPolicyEngine

SECURITY_OPERATION_PLAN_SCHEMA = "workspace-security-operation-plan/v1"
SECURITY_OPERATION_STEP_SCHEMA = "workspace-security-operation-step/v1"
MAX_SECURITY_OPERATION_STEPS = 6
_PLAN_STATUSES = frozenset({"planned", "no_route", "denied"})
_PREFLIGHT_STATES = frozenset({"ready_internal", "authority_required"})
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class SecurityOperationPlanError(ValueError):
    """The routed security plan is invalid, stale or internally inconsistent."""


@dataclass(frozen=True)
class SecurityOperationStep:
    step_id: str
    sequence: int
    taxonomy_id: str
    capability_id: str
    operation_id: str
    authority_level: str
    authority_domain: str
    backend_capability: str | None
    effect: str
    evidence_required: bool
    preflight_state: str
    schema_version: str = SECURITY_OPERATION_STEP_SCHEMA

    def validate(self) -> "SecurityOperationStep":
        if not re.fullmatch(r"step:[0-9a-f]{24}", self.step_id):
            raise SecurityOperationPlanError("step_id must be a deterministic typed digest")
        if not 1 <= int(self.sequence) <= MAX_SECURITY_OPERATION_STEPS:
            raise SecurityOperationPlanError("step sequence is outside the supported bound")
        if self.authority_level not in {"L0", "L1"}:
            raise SecurityOperationPlanError("operation plan v0.3 admits only L0/L1")
        if self.authority_domain not in {"internal", "task", "monitoring"}:
            raise SecurityOperationPlanError("unsupported authority domain")
        if self.preflight_state not in _PREFLIGHT_STATES:
            raise SecurityOperationPlanError("unsupported preflight state")
        if self.authority_domain == "internal":
            if self.backend_capability is not None:
                raise SecurityOperationPlanError("internal steps must not expose a backend capability")
            if self.effect != "compute" or self.preflight_state != "ready_internal":
                raise SecurityOperationPlanError("internal steps must be compute-only and ready_internal")
        else:
            if not self.backend_capability:
                raise SecurityOperationPlanError("task/monitoring steps require a reviewed backend capability")
            if self.preflight_state != "authority_required":
                raise SecurityOperationPlanError("side-effecting steps must require authority preflight")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class SecurityOperationPlan:
    request_sha256: str
    route_status: str
    status: str
    steps: tuple[SecurityOperationStep, ...]
    registry_fingerprint: str
    plan_fingerprint: str
    reason_codes: tuple[str, ...]
    authority: str = "advisory"
    auto_execute: bool = False
    schema_version: str = SECURITY_OPERATION_PLAN_SCHEMA

    def validate(self) -> "SecurityOperationPlan":
        if not _SHA256_RE.fullmatch(self.request_sha256):
            raise SecurityOperationPlanError("request_sha256 must be a SHA-256 fingerprint")
        if not _SHA256_RE.fullmatch(self.registry_fingerprint):
            raise SecurityOperationPlanError("registry_fingerprint must be a SHA-256 fingerprint")
        if not _SHA256_RE.fullmatch(self.plan_fingerprint):
            raise SecurityOperationPlanError("plan_fingerprint must be a SHA-256 fingerprint")
        if self.status not in _PLAN_STATUSES:
            raise SecurityOperationPlanError("unsupported plan status")
        if self.route_status not in {"routed", "no_route", "denied"}:
            raise SecurityOperationPlanError("unsupported route status")
        if self.authority != "advisory" or self.auto_execute:
            raise SecurityOperationPlanError("security operation plans cannot grant execution authority")
        if len(self.steps) > MAX_SECURITY_OPERATION_STEPS:
            raise SecurityOperationPlanError("security operation plan step bound exceeded")
        if self.status == "planned" and not self.steps:
            raise SecurityOperationPlanError("planned operation plans require at least one step")
        if self.status != "planned" and self.steps:
            raise SecurityOperationPlanError("non-planned operation plans cannot contain steps")
        if self.status == "planned" and self.route_status != "routed":
            raise SecurityOperationPlanError("planned status requires a routed decision")
        if self.status == "no_route" and self.route_status != "no_route":
            raise SecurityOperationPlanError("no_route plan must originate from no_route routing")
        if self.status == "denied" and self.route_status != "denied":
            raise SecurityOperationPlanError("denied plan must originate from denied routing")
        if not self.reason_codes:
            raise SecurityOperationPlanError("operation plan requires reason_codes")
        for expected, step in enumerate(self.steps, 1):
            step.validate()
            if step.sequence != expected:
                raise SecurityOperationPlanError("operation plan steps must be contiguous and ordered")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "request_sha256": self.request_sha256,
            "route_status": self.route_status,
            "status": self.status,
            "steps": [step.public_dict() for step in self.steps],
            "registry_fingerprint": self.registry_fingerprint,
            "plan_fingerprint": self.plan_fingerprint,
            "reason_codes": list(self.reason_codes),
            "authority": self.authority,
            "auto_execute": self.auto_execute,
        }


class SecurityOperationPlanCompiler:
    """Compile a closed routing decision into a deterministic, non-executing plan.

    The compiler is the WorkSpace equivalent of a safe `/goal` planning boundary:
    each routed operation becomes one reviewed step, but task/monitoring side effects
    remain blocked until their existing authority engines approve the exact resource.
    No command text, argv, target, credential or model-supplied executable is stored.
    """

    def __init__(self, registry: SecurityCapabilityRegistry | None = None):
        self.registry = registry or SecurityCapabilityRegistry()

    def compile(self, decision: SecurityRoutingDecision) -> SecurityOperationPlan:
        decision.validate()
        if decision.registry_fingerprint != self.registry.fingerprint:
            raise SecurityOperationPlanError("ROUTING_REGISTRY_FINGERPRINT_MISMATCH")

        if decision.status == "denied":
            return self._plan(
                decision,
                status="denied",
                steps=(),
                reasons=tuple(decision.reason_codes) + ("PLAN_DENIED_BY_ROUTER",),
            )
        if decision.status == "no_route":
            return self._plan(
                decision,
                status="no_route",
                steps=(),
                reasons=tuple(decision.reason_codes) + ("PLAN_HAS_NO_APPROVED_ROUTE",),
            )

        steps: list[SecurityOperationStep] = []
        for sequence, selection in enumerate(decision.selections, 1):
            capability, operation = self.registry.resolve(
                selection.capability_id,
                selection.operation_id,
            )
            if capability.taxonomy_id != selection.taxonomy_id:
                raise SecurityCapabilityDenied("PLAN_TAXONOMY_CAPABILITY_MISMATCH")
            if capability.authority_level != selection.authority_level:
                raise SecurityOperationPlanError("PLAN_AUTHORITY_LEVEL_MISMATCH")
            if capability.authority_domain != selection.authority_domain:
                raise SecurityOperationPlanError("PLAN_AUTHORITY_DOMAIN_MISMATCH")
            if capability.evidence_required != selection.evidence_required:
                raise SecurityOperationPlanError("PLAN_EVIDENCE_CONTRACT_MISMATCH")
            if capability.authority_level not in {"L0", "L1"}:
                raise SecurityCapabilityDenied("PLAN_AUTHORITY_LEVEL_NOT_ADMITTED_V03")
            preflight_state = (
                "ready_internal"
                if capability.authority_domain == "internal"
                else "authority_required"
            )
            step = SecurityOperationStep(
                step_id=self._step_id(
                    decision.request_sha256,
                    sequence,
                    capability.capability_id,
                    operation.operation_id,
                ),
                sequence=sequence,
                taxonomy_id=capability.taxonomy_id,
                capability_id=capability.capability_id,
                operation_id=operation.operation_id,
                authority_level=capability.authority_level,
                authority_domain=capability.authority_domain,
                backend_capability=operation.backend_capability,
                effect=operation.effect,
                evidence_required=capability.evidence_required,
                preflight_state=preflight_state,
            ).validate()
            steps.append(step)

        return self._plan(
            decision,
            status="planned",
            steps=tuple(steps),
            reasons=tuple(decision.reason_codes) + ("DETERMINISTIC_OPERATION_PLAN_COMPILED",),
        )

    def authorize_internal_step(self, step: SecurityOperationStep) -> SecurityOperationAuthorization:
        step.validate()
        if step.authority_domain != "internal":
            raise SecurityCapabilityDenied("PLAN_STEP_AUTHORITY_DOMAIN_MISMATCH")
        return self.registry.authorize_internal(step.capability_id, step.operation_id)

    def require_task_step_authority(
        self,
        authority: TaskCapabilityAuthority,
        step: SecurityOperationStep,
        *,
        resource_kind: str,
        resource_ref: str,
    ) -> SecurityOperationAuthorization:
        step.validate()
        if step.authority_domain != "task":
            raise SecurityCapabilityDenied("PLAN_STEP_AUTHORITY_DOMAIN_MISMATCH")
        return self.registry.require_task_authority(
            authority,
            step.capability_id,
            step.operation_id,
            resource_kind=resource_kind,
            resource_ref=resource_ref,
        )

    def require_monitoring_step_authority(
        self,
        engine: MonitoringPolicyEngine,
        asset: AssetInventoryRecord,
        step: SecurityOperationStep,
        *,
        target_host: str,
        target_port: int | None = None,
        credential_ref: SecretReference | None = None,
    ) -> SecurityOperationAuthorization:
        step.validate()
        if step.authority_domain != "monitoring":
            raise SecurityCapabilityDenied("PLAN_STEP_AUTHORITY_DOMAIN_MISMATCH")
        return self.registry.require_monitoring_authority(
            engine,
            asset,
            step.capability_id,
            step.operation_id,
            target_host=target_host,
            target_port=target_port,
            credential_ref=credential_ref,
        )

    def _plan(
        self,
        decision: SecurityRoutingDecision,
        *,
        status: str,
        steps: tuple[SecurityOperationStep, ...],
        reasons: tuple[str, ...],
    ) -> SecurityOperationPlan:
        plan_fingerprint = self._plan_fingerprint(
            request_sha256=decision.request_sha256,
            route_status=decision.status,
            status=status,
            steps=steps,
            registry_fingerprint=self.registry.fingerprint,
            reason_codes=reasons,
        )
        return SecurityOperationPlan(
            request_sha256=decision.request_sha256,
            route_status=decision.status,
            status=status,
            steps=steps,
            registry_fingerprint=self.registry.fingerprint,
            plan_fingerprint=plan_fingerprint,
            reason_codes=reasons,
        ).validate()

    @staticmethod
    def _step_id(
        request_sha256: str,
        sequence: int,
        capability_id: str,
        operation_id: str,
    ) -> str:
        payload = f"{request_sha256}|{sequence}|{capability_id}|{operation_id}".encode("utf-8")
        return "step:" + hashlib.sha256(payload).hexdigest()[:24]

    @staticmethod
    def _plan_fingerprint(
        *,
        request_sha256: str,
        route_status: str,
        status: str,
        steps: tuple[SecurityOperationStep, ...],
        registry_fingerprint: str,
        reason_codes: tuple[str, ...],
    ) -> str:
        payload = {
            "request_sha256": request_sha256,
            "route_status": route_status,
            "status": status,
            "steps": [step.public_dict() for step in steps],
            "registry_fingerprint": registry_fingerprint,
            "reason_codes": list(reason_codes),
        }
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()
