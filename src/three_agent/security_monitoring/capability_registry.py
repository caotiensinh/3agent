from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Iterable

from ..capability_authority import TaskCapabilityAuthority
from .contracts import AssetInventoryRecord, SecretReference
from .policy import MonitoringPolicyEngine

SECURITY_CAPABILITY_SCHEMA = "workspace-security-capability/v1"
SECURITY_AUTHORIZATION_SCHEMA = "workspace-security-operation-authorization/v1"

SECURITY_TAXONOMY = frozenset(
    {
        "network.inventory",
        "network.health",
        "network.latency",
        "network.path",
        "network.interface",
        "network.dns",
        "network.flow",
        "network.pcap",
        "network.device",
        "network.service",
        "security.ids",
        "security.authentication",
        "security.endpoint",
        "security.threat_hunting",
        "security.incident_triage",
        "security.forensics",
        "security.vulnerability_assessment",
        "security.configuration_review",
    }
)

AUTHORITY_LEVELS = frozenset({"L0", "L1", "L2", "L3"})
AUTHORITY_DOMAINS = frozenset({"internal", "task", "monitoring"})
CAPABILITY_STATUSES = frozenset({"approved", "candidate", "retired"})
_ALLOWED_EFFECTS = frozenset({"read", "compute", "local_read", "network_read", "execute_readonly"})
_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-=]{0,255}$")


class SecurityCapabilityError(ValueError):
    """A security capability definition or operation request is invalid."""


class SecurityCapabilityDenied(PermissionError):
    """A security capability request is not admitted by the reviewed registry."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _compact(value: str, field: str, *, max_len: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or not _COMPACT_RE.fullmatch(text):
        raise SecurityCapabilityError(f"{field} must be a compact identifier")
    if "://" in text:
        raise SecurityCapabilityError(f"{field} must not contain a raw URL")
    return text


def validate_security_taxonomy_id(value: str) -> str:
    taxonomy_id = _compact(value, "taxonomy_id", max_len=96)
    if taxonomy_id not in SECURITY_TAXONOMY:
        raise SecurityCapabilityError(f"unknown taxonomy_id: {taxonomy_id}")
    return taxonomy_id


@dataclass(frozen=True)
class CuratedSecurityOperation:
    """One reviewed operation. It is an operation ID, never a shell command."""

    operation_id: str
    effect: str
    backend_capability: str | None = None

    def validate(self) -> "CuratedSecurityOperation":
        object.__setattr__(
            self,
            "operation_id",
            _compact(self.operation_id, "operation_id", max_len=96),
        )
        if self.effect not in _ALLOWED_EFFECTS:
            raise SecurityCapabilityError(f"unsupported effect: {self.effect}")
        if self.backend_capability is not None:
            object.__setattr__(
                self,
                "backend_capability",
                _compact(self.backend_capability, "backend_capability", max_len=96),
            )
        return self


@dataclass(frozen=True)
class SecurityCapability:
    """WorkSpace-native security capability definition.

    The registry contains reviewed knowledge about operations and backends. It does
    not grant runtime authority. Task and monitoring side effects are delegated to
    their existing deterministic authority engines.
    """

    capability_id: str
    taxonomy_id: str
    name: str
    authority_level: str
    authority_domain: str
    operations: tuple[CuratedSecurityOperation, ...]
    status: str = "approved"
    evidence_required: bool = True
    schema_version: str = SECURITY_CAPABILITY_SCHEMA

    def validate(self) -> "SecurityCapability":
        object.__setattr__(
            self,
            "capability_id",
            _compact(self.capability_id, "capability_id", max_len=128),
        )
        object.__setattr__(
            self,
            "taxonomy_id",
            validate_security_taxonomy_id(self.taxonomy_id),
        )
        if self.authority_level not in AUTHORITY_LEVELS:
            raise SecurityCapabilityError(
                f"unsupported authority_level: {self.authority_level}"
            )
        if self.authority_domain not in AUTHORITY_DOMAINS:
            raise SecurityCapabilityError(
                f"unsupported authority_domain: {self.authority_domain}"
            )
        if self.status not in CAPABILITY_STATUSES:
            raise SecurityCapabilityError(f"unsupported status: {self.status}")
        name = str(self.name or "").strip()
        if not name or len(name) > 160:
            raise SecurityCapabilityError("name is required and must be <= 160 chars")
        object.__setattr__(self, "name", name)

        operations = tuple(op.validate() for op in self.operations)
        if not operations:
            raise SecurityCapabilityError("security capabilities require curated operations")
        operation_ids = [op.operation_id for op in operations]
        if len(operation_ids) != len(set(operation_ids)):
            raise SecurityCapabilityError("operation_id values must be unique")
        object.__setattr__(self, "operations", operations)

        if self.authority_domain == "internal":
            if any(op.backend_capability is not None for op in operations):
                raise SecurityCapabilityError(
                    "internal operations must not name executable backend capabilities"
                )
            if any(op.effect != "compute" for op in operations):
                raise SecurityCapabilityError("internal operations must be compute-only")
        else:
            if any(op.backend_capability is None for op in operations):
                raise SecurityCapabilityError(
                    "task/monitoring operations require a reviewed backend capability"
                )
        return self

    def operation(self, operation_id: str) -> CuratedSecurityOperation | None:
        wanted = _compact(operation_id, "operation_id", max_len=96)
        return next((op for op in self.operations if op.operation_id == wanted), None)

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["operations"] = [asdict(op) for op in self.operations]
        return payload


@dataclass(frozen=True)
class SecurityOperationAuthorization:
    capability_id: str
    operation_id: str
    taxonomy_id: str
    authority_level: str
    authority_domain: str
    backend_capability: str
    effect: str
    allowed: bool
    reason_code: str
    authority_fingerprint: str
    schema_version: str = SECURITY_AUTHORIZATION_SCHEMA

    def metadata(self) -> dict[str, str | bool]:
        return {
            "schema_version": self.schema_version,
            "capability_id": self.capability_id,
            "operation_id": self.operation_id,
            "taxonomy_id": self.taxonomy_id,
            "authority_level": self.authority_level,
            "authority_domain": self.authority_domain,
            "backend_capability": self.backend_capability,
            "effect": self.effect,
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "authority_fingerprint": self.authority_fingerprint,
        }


def _op(
    operation_id: str,
    effect: str,
    backend_capability: str | None = None,
) -> CuratedSecurityOperation:
    return CuratedSecurityOperation(operation_id, effect, backend_capability)


DEFAULT_SECURITY_CAPABILITIES = (
    SecurityCapability(
        "network.pcap.read",
        "network.pcap",
        "Passive PCAP Evidence Read",
        "L0",
        "task",
        (
            _op("read_capture", "read", "read_file"),
            _op("read_capture_metadata", "read", "read_file"),
        ),
    ),
    SecurityCapability(
        "security.configuration_review.read",
        "security.configuration_review",
        "Configuration Snapshot Read",
        "L0",
        "task",
        (_op("read_configuration_snapshot", "read", "read_file"),),
    ),
    SecurityCapability(
        "network.interface.observe",
        "network.interface",
        "Interface Counter Observation",
        "L0",
        "monitoring",
        (_op("read_interface_counters", "network_read", "snmpv3_read"),),
    ),
    SecurityCapability(
        "network.flow.observe",
        "network.flow",
        "Local Flow Evidence Observation",
        "L0",
        "monitoring",
        (_op("read_local_flow_evidence", "local_read", "local_net_read"),),
    ),
    SecurityCapability(
        "security.telemetry.observe",
        "security.ids",
        "Fixed Read-only Telemetry Adapter",
        "L0",
        "monitoring",
        (_op("read_fixed_telemetry", "execute_readonly", "fixed_readonly_adapter"),),
    ),
    SecurityCapability(
        "network.dns.analyze",
        "network.dns",
        "DNS Evidence Analysis",
        "L1",
        "internal",
        (_op("analyze_dns_evidence", "compute"),),
    ),
    SecurityCapability(
        "network.flow.analyze",
        "network.flow",
        "Flow Evidence Analysis",
        "L1",
        "internal",
        (_op("analyze_flow_evidence", "compute"),),
    ),
    SecurityCapability(
        "security.authentication.analyze",
        "security.authentication",
        "Authentication Evidence Analysis",
        "L1",
        "internal",
        (_op("analyze_authentication_evidence", "compute"),),
    ),
    SecurityCapability(
        "security.endpoint.analyze",
        "security.endpoint",
        "Endpoint Evidence Analysis",
        "L1",
        "internal",
        (_op("analyze_endpoint_evidence", "compute"),),
    ),
    SecurityCapability(
        "security.ids.analyze",
        "security.ids",
        "IDS Evidence Analysis",
        "L1",
        "internal",
        (_op("triage_ids_evidence", "compute"),),
    ),
    SecurityCapability(
        "security.incident_triage.analyze",
        "security.incident_triage",
        "Evidence-bound Incident Triage",
        "L1",
        "internal",
        (
            _op("triage_findings", "compute"),
            _op("build_incident_timeline", "compute"),
        ),
    ),
    SecurityCapability(
        "security.threat_hunting.analyze",
        "security.threat_hunting",
        "Evidence-bound Threat Hunting",
        "L1",
        "internal",
        (_op("hunt_reviewed_evidence", "compute"),),
    ),
    SecurityCapability(
        "security.forensics.analyze",
        "security.forensics",
        "Read-only Forensic Evidence Analysis",
        "L1",
        "internal",
        (_op("analyze_forensic_evidence", "compute"),),
    ),
)


class SecurityCapabilityRegistry:
    """Closed, reviewed registry for WorkSpace security operations."""

    def __init__(
        self,
        capabilities: Iterable[SecurityCapability] = DEFAULT_SECURITY_CAPABILITIES,
    ):
        rows = tuple(cap.validate() for cap in capabilities)
        ids = [cap.capability_id for cap in rows]
        if len(ids) != len(set(ids)):
            raise SecurityCapabilityError("capability_id values must be unique")
        self._capabilities = {cap.capability_id: cap for cap in rows}

    @property
    def fingerprint(self) -> str:
        payload = [
            self._capabilities[key].to_dict()
            for key in sorted(self._capabilities)
        ]
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def list_approved(self) -> tuple[SecurityCapability, ...]:
        return tuple(
            cap
            for _, cap in sorted(self._capabilities.items())
            if cap.status == "approved"
        )

    def capabilities_for_taxonomy(
        self,
        taxonomy_id: str,
    ) -> tuple[SecurityCapability, ...]:
        wanted = validate_security_taxonomy_id(taxonomy_id)
        return tuple(
            cap
            for cap in self.list_approved()
            if cap.taxonomy_id == wanted
        )

    def get(self, capability_id: str) -> SecurityCapability | None:
        cap_id = _compact(capability_id, "capability_id", max_len=128)
        return self._capabilities.get(cap_id)

    def resolve(
        self,
        capability_id: str,
        operation_id: str,
    ) -> tuple[SecurityCapability, CuratedSecurityOperation]:
        cap = self.get(capability_id)
        if cap is None:
            raise SecurityCapabilityDenied("SECURITY_CAPABILITY_UNKNOWN")
        if cap.status != "approved":
            raise SecurityCapabilityDenied("SECURITY_CAPABILITY_NOT_APPROVED")
        operation = cap.operation(operation_id)
        if operation is None:
            raise SecurityCapabilityDenied("SECURITY_OPERATION_NOT_CURATED")
        return cap, operation

    def authorize_internal(
        self,
        capability_id: str,
        operation_id: str,
    ) -> SecurityOperationAuthorization:
        cap, operation = self.resolve(capability_id, operation_id)
        if cap.authority_domain != "internal":
            raise SecurityCapabilityDenied("SECURITY_AUTHORITY_DOMAIN_MISMATCH")
        return self._authorization(
            cap,
            operation,
            backend_capability="internal_compute",
            reason_code="SECURITY_INTERNAL_OPERATION_AUTHORIZED",
            authority_fingerprint=self.fingerprint,
        )

    def require_task_authority(
        self,
        authority: TaskCapabilityAuthority,
        capability_id: str,
        operation_id: str,
        *,
        resource_kind: str,
        resource_ref: str,
    ) -> SecurityOperationAuthorization:
        cap, operation = self.resolve(capability_id, operation_id)
        if cap.authority_domain != "task" or operation.backend_capability is None:
            raise SecurityCapabilityDenied("SECURITY_AUTHORITY_DOMAIN_MISMATCH")
        decision = authority.require(
            operation.backend_capability,
            resource_kind=resource_kind,
            resource_ref=resource_ref,
            effect=operation.effect,
        )
        return self._authorization(
            cap,
            operation,
            backend_capability=operation.backend_capability,
            reason_code="SECURITY_TASK_AUTHORITY_CONFIRMED",
            authority_fingerprint=decision.authority_fingerprint,
        )

    def require_monitoring_authority(
        self,
        engine: MonitoringPolicyEngine,
        asset: AssetInventoryRecord,
        capability_id: str,
        operation_id: str,
        *,
        target_host: str,
        target_port: int | None = None,
        credential_ref: SecretReference | None = None,
    ) -> SecurityOperationAuthorization:
        cap, operation = self.resolve(capability_id, operation_id)
        if cap.authority_domain != "monitoring" or operation.backend_capability is None:
            raise SecurityCapabilityDenied("SECURITY_AUTHORITY_DOMAIN_MISMATCH")
        decision = engine.require(
            asset,
            capability=operation.backend_capability,
            effect=operation.effect,
            target_host=target_host,
            target_port=target_port,
            credential_ref=credential_ref,
        )
        authority_fingerprint = self._monitoring_authority_fingerprint(
            decision.policy_fingerprint,
            decision.asset_fingerprint,
        )
        return self._authorization(
            cap,
            operation,
            backend_capability=operation.backend_capability,
            reason_code="SECURITY_MONITORING_AUTHORITY_CONFIRMED",
            authority_fingerprint=authority_fingerprint,
        )

    def _authorization(
        self,
        cap: SecurityCapability,
        operation: CuratedSecurityOperation,
        *,
        backend_capability: str,
        reason_code: str,
        authority_fingerprint: str,
    ) -> SecurityOperationAuthorization:
        return SecurityOperationAuthorization(
            capability_id=cap.capability_id,
            operation_id=operation.operation_id,
            taxonomy_id=cap.taxonomy_id,
            authority_level=cap.authority_level,
            authority_domain=cap.authority_domain,
            backend_capability=backend_capability,
            effect=operation.effect,
            allowed=True,
            reason_code=reason_code,
            authority_fingerprint=authority_fingerprint,
        )

    @staticmethod
    def _monitoring_authority_fingerprint(
        policy_fingerprint: str,
        asset_fingerprint: str,
    ) -> str:
        payload = f"{policy_fingerprint}|{asset_fingerprint}".encode("utf-8")
        return "sha256:" + hashlib.sha256(payload).hexdigest()
