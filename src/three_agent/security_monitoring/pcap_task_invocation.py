from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any

from three_agent.capability_authority import CapabilityAuthorityDenied, TaskCapabilityAuthority
from three_agent.task_contract import TaskContract

from .capability_registry import SecurityCapabilityRegistry
from .contracts import sha256_fingerprint
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
from .pcap_evidence import BoundedPCAPEvidenceReader, PCAPCaptureEvidence, PCAPResourceRegistry

PCAP_TASK_INVOCATION_RECEIPT_SCHEMA = "workspace-security-pcap-task-invocation-receipt/v1"
PCAP_CAPTURE_HANDLER_ID = "analysis.pcap_evidence.read_capture"
PCAP_METADATA_HANDLER_ID = "analysis.pcap_evidence.read_capture_metadata"
PCAP_HANDLER_IDS = frozenset({PCAP_CAPTURE_HANDLER_ID, PCAP_METADATA_HANDLER_ID})
PCAP_OUTPUT_KINDS = {
    PCAP_CAPTURE_HANDLER_ID: "pcap_capture_evidence",
    PCAP_METADATA_HANDLER_ID: "pcap_metadata_evidence",
}
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_RESOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,127}$")


@dataclass(frozen=True)
class PCAPReviewedOperationBinding:
    capability_id: str
    operation_id: str
    status: str
    reason_code: str
    handler_id: str
    handler_kind: str = "bounded_local_adapter"
    schema_version: str = "workspace-security-operation-binding/v1"

    def validate(self) -> "PCAPReviewedOperationBinding":
        expected = {
            ("network.pcap.read", "read_capture"): PCAP_CAPTURE_HANDLER_ID,
            ("network.pcap.read", "read_capture_metadata"): PCAP_METADATA_HANDLER_ID,
        }
        handler = expected.get((self.capability_id, self.operation_id))
        if handler != self.handler_id:
            raise SecurityOperationBindingError("PCAP reviewed binding key/handler mismatch")
        if self.status != "bound" or self.reason_code != "BOUND_TO_REVIEWED_RUNTIME_HANDLER":
            raise SecurityOperationBindingError("PCAP reviewed binding must remain explicitly bound")
        if self.handler_kind != "bounded_local_adapter":
            raise SecurityOperationBindingError("PCAP handler_kind must be bounded_local_adapter")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)


PCAP_REVIEWED_BINDINGS = (
    PCAPReviewedOperationBinding(
        capability_id="network.pcap.read",
        operation_id="read_capture",
        status="bound",
        reason_code="BOUND_TO_REVIEWED_RUNTIME_HANDLER",
        handler_id=PCAP_CAPTURE_HANDLER_ID,
    ),
    PCAPReviewedOperationBinding(
        capability_id="network.pcap.read",
        operation_id="read_capture_metadata",
        status="bound",
        reason_code="BOUND_TO_REVIEWED_RUNTIME_HANDLER",
        handler_id=PCAP_METADATA_HANDLER_ID,
    ),
)


class PCAPSecurityOperationBindingRegistry:
    """Opt-in binding profile that admits only the reviewed PCAP task handlers."""

    def __init__(self, registry: SecurityCapabilityRegistry | None = None) -> None:
        self.registry = registry or SecurityCapabilityRegistry()
        replacements = {
            (row.capability_id, row.operation_id): row.validate()
            for row in PCAP_REVIEWED_BINDINGS
        }
        rows: list[SecurityOperationBinding | PCAPReviewedOperationBinding] = []
        for raw in DEFAULT_SECURITY_OPERATION_BINDINGS:
            key = (raw.capability_id, raw.operation_id)
            rows.append(replacements.get(key, raw.validate()))
        expected = {
            (capability.capability_id, operation.operation_id)
            for capability in self.registry.list_approved()
            for operation in capability.operations
        }
        actual = {(row.capability_id, row.operation_id) for row in rows}
        if actual != expected:
            raise SecurityOperationBindingError("PCAP binding profile does not exactly cover approved registry")
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
            raise SecurityOperationBindingError("approved operation is missing PCAP profile binding")
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


@dataclass(frozen=True)
class PCAPEvidenceInvocationRequest:
    """Request carries only a trusted resource identifier, never a file path."""

    resource_ref: str

    def validate(self) -> "PCAPEvidenceInvocationRequest":
        text = str(self.resource_ref or "").strip()
        if not text or not _RESOURCE_RE.fullmatch(text) or "://" in text or ".." in text.split("/"):
            raise SecurityOperationInvocationError("PCAP invocation resource_ref is invalid")
        object.__setattr__(self, "resource_ref", text)
        return self

    @property
    def fingerprint(self) -> str:
        self.validate()
        return sha256_fingerprint({"resource_ref": self.resource_ref})


@dataclass(frozen=True)
class PCAPTaskInvocationReceipt:
    invocation_id: str
    plan_fingerprint: str
    step_id: str
    capability_id: str
    operation_id: str
    handler_id: str
    handler_kind: str
    input_fingerprint: str
    authority_domain: str
    authority_fingerprint: str
    authority_reason_code: str
    registry_fingerprint: str
    binding_fingerprint: str
    output_kind: str
    resource_registry_fingerprint: str
    task_id_sha256: str
    status: str = "completed"
    schema_version: str = PCAP_TASK_INVOCATION_RECEIPT_SCHEMA

    def validate(self) -> "PCAPTaskInvocationReceipt":
        if not re.fullmatch(r"invoke-[0-9a-f]{24}", self.invocation_id):
            raise SecurityOperationInvocationError("PCAP invocation_id is invalid")
        for value in (
            self.plan_fingerprint,
            self.input_fingerprint,
            self.authority_fingerprint,
            self.registry_fingerprint,
            self.binding_fingerprint,
            self.resource_registry_fingerprint,
            self.task_id_sha256,
        ):
            if not _SHA256_RE.fullmatch(str(value or "")):
                raise SecurityOperationInvocationError("PCAP receipt fingerprints must be SHA-256")
        if not re.fullmatch(r"step:[0-9a-f]{24}", self.step_id):
            raise SecurityOperationInvocationError("PCAP receipt step_id is invalid")
        if self.authority_domain != "task":
            raise SecurityOperationInvocationError("PCAP task receipt must remain task-domain")
        if self.handler_id not in PCAP_HANDLER_IDS:
            raise SecurityOperationInvocationError("PCAP receipt handler_id is not reviewed")
        if self.handler_kind != "bounded_local_adapter":
            raise SecurityOperationInvocationError("PCAP receipt handler_kind is invalid")
        if self.output_kind not in set(PCAP_OUTPUT_KINDS.values()):
            raise SecurityOperationInvocationError("PCAP receipt output_kind is invalid")
        if self.authority_reason_code != "SECURITY_TASK_AUTHORITY_CONFIRMED":
            raise SecurityOperationInvocationError("PCAP receipt requires confirmed task authority")
        if self.status != "completed":
            raise SecurityOperationInvocationError("PCAP v0.7 emits completed receipts only")
        expected = "invoke-" + sha256_fingerprint(self._identity_payload()).split(":", 1)[1][:24]
        if self.invocation_id != expected:
            raise SecurityOperationInvocationError("PCAP invocation_id does not match receipt identity")
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
            "authority_domain": self.authority_domain,
            "authority_fingerprint": self.authority_fingerprint,
            "authority_reason_code": self.authority_reason_code,
            "registry_fingerprint": self.registry_fingerprint,
            "binding_fingerprint": self.binding_fingerprint,
            "output_kind": self.output_kind,
            "resource_registry_fingerprint": self.resource_registry_fingerprint,
            "task_id_sha256": self.task_id_sha256,
            "status": self.status,
        }

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {"invocation_id": self.invocation_id, **self._identity_payload()}


class PCAPTaskSecurityOperationInvoker(SecurityOperationInvoker):
    """Opt-in task-authorized PCAP extension over the v0.5 invocation gate.

    The constructor accepts a validated TaskContract, not a pre-forged authority
    object. The authority projection, resource map and parser remain trusted runtime
    dependencies. All non-PCAP operations continue through the original v0.5 invoker.
    """

    def __init__(
        self,
        *,
        task_contract: TaskContract,
        pcap_registry: PCAPResourceRegistry,
        registry: SecurityCapabilityRegistry | None = None,
        **kwargs: Any,
    ) -> None:
        contract = task_contract.validate()
        if not isinstance(pcap_registry, PCAPResourceRegistry):
            raise SecurityOperationInvocationError("PCAP task invoker requires PCAPResourceRegistry")
        security_registry = registry or SecurityCapabilityRegistry()
        bindings = PCAPSecurityOperationBindingRegistry(security_registry)
        if "binding_registry" in kwargs:
            raise SecurityOperationInvocationError("PCAP task invoker owns its reviewed binding profile")
        super().__init__(registry=security_registry, binding_registry=bindings, **kwargs)
        self.task_contract = contract
        self.task_authority = TaskCapabilityAuthority.from_contract(contract)
        self.pcap_registry = pcap_registry
        self.pcap_reader = BoundedPCAPEvidenceReader(pcap_registry)

    def invoke(
        self,
        plan: SecurityOperationPlan,
        *,
        step_id: str,
        request: SecurityTypedInvocationRequest | PCAPEvidenceInvocationRequest,
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
        if binding.handler_id not in PCAP_HANDLER_IDS:
            return super().invoke(plan, step_id=step.step_id, request=request)
        if not isinstance(request, PCAPEvidenceInvocationRequest):
            raise SecurityOperationInvocationDenied("INVOCATION_REQUEST_TYPE_MISMATCH")
        request.validate()
        if step.authority_domain != "task" or step.backend_capability != "read_file" or step.effect != "read":
            raise SecurityOperationInvocationDenied("INVOCATION_PCAP_TASK_SCOPE_MISMATCH")
        resource, _path = self.pcap_registry.resolve(request.resource_ref)
        try:
            authorization = self.compiler.require_task_step_authority(
                self.task_authority,
                step,
                resource_kind="file",
                resource_ref=resource.relative_path,
            )
        except CapabilityAuthorityDenied as exc:
            reason = getattr(exc, "reason_code", "CAPABILITY_NOT_ALLOWED")
            raise SecurityOperationInvocationDenied(f"INVOCATION_TASK_{reason}") from exc
        self._validate_authorization(step, authorization)
        if binding.handler_id == PCAP_CAPTURE_HANDLER_ID:
            output = self.pcap_reader.read_capture(request.resource_ref)
        elif binding.handler_id == PCAP_METADATA_HANDLER_ID:
            output = self.pcap_reader.read_metadata(request.resource_ref)
        else:  # pragma: no cover - closed handler set makes this unreachable
            raise SecurityOperationInvocationDenied("INVOCATION_PCAP_HANDLER_NOT_REVIEWED")
        if not isinstance(output, PCAPCaptureEvidence):
            raise SecurityOperationInvocationError("PCAP reviewed handler returned unexpected type")
        receipt = self._pcap_receipt(
            plan=plan,
            step=step,
            handler_id=binding.handler_id,
            handler_kind=binding.handler_kind,
            input_fingerprint=request.fingerprint,
            authority_fingerprint=authorization.authority_fingerprint,
            authority_reason_code=authorization.reason_code,
        )
        return SecurityInvocationResult(receipt=receipt, output=output)

    def _pcap_receipt(
        self,
        *,
        plan: SecurityOperationPlan,
        step: SecurityOperationStep,
        handler_id: str,
        handler_kind: str,
        input_fingerprint: str,
        authority_fingerprint: str,
        authority_reason_code: str,
    ) -> PCAPTaskInvocationReceipt:
        payload = {
            "schema_version": PCAP_TASK_INVOCATION_RECEIPT_SCHEMA,
            "plan_fingerprint": plan.plan_fingerprint,
            "step_id": step.step_id,
            "capability_id": step.capability_id,
            "operation_id": step.operation_id,
            "handler_id": handler_id,
            "handler_kind": handler_kind,
            "input_fingerprint": input_fingerprint,
            "authority_domain": "task",
            "authority_fingerprint": authority_fingerprint,
            "authority_reason_code": authority_reason_code,
            "registry_fingerprint": self.registry.fingerprint,
            "binding_fingerprint": self.binding_registry.fingerprint,
            "output_kind": PCAP_OUTPUT_KINDS[handler_id],
            "resource_registry_fingerprint": self.pcap_registry.fingerprint,
            "task_id_sha256": "sha256:" + hashlib.sha256(self.task_contract.task_id.encode("utf-8")).hexdigest(),
            "status": "completed",
        }
        invocation_id = "invoke-" + sha256_fingerprint(payload).split(":", 1)[1][:24]
        return PCAPTaskInvocationReceipt(
            invocation_id=invocation_id,
            **{key: value for key, value in payload.items() if key != "schema_version"},
        ).validate()

    @property
    def runtime_fingerprint(self) -> str:
        return sha256_fingerprint(
            {
                "base_runtime_fingerprint": super().runtime_fingerprint,
                "task_authority_fingerprint": self.task_authority.fingerprint,
                "pcap_resource_registry_fingerprint": self.pcap_registry.fingerprint,
                "pcap_binding_fingerprint": self.binding_registry.fingerprint,
                "pcap_handler_ids": sorted(PCAP_HANDLER_IDS),
            }
        )
