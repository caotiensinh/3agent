from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from .contracts import MonitoringContractError, _compact, canonical_json, sha256_fingerprint
from .entity_context import approved_asset_ref, opaque_entity_ref

FLOW_TUPLE_SCHEMA = "workspace-security-monitoring/flow-tuple-evidence-v1"
SOCKET_PROCESS_SCHEMA = "workspace-security-monitoring/socket-process-observation-v1"
_ENDPOINT_REF_RE = re.compile(r"^endpoint:(tcp|udp):sha256:[0-9a-f]{64}$")
_PROCESS_REF_RE = re.compile(r"^entity:process:sha256:[0-9a-f]{64}$")
_USER_REF_RE = re.compile(r"^entity:user:sha256:[0-9a-f]{64}$")
_ASSET_REF_RE = re.compile(r"^asset:[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,127}$")


def _utc(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise MonitoringContractError(f"{field_name} must include timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _protocol(value: str) -> str:
    protocol = str(value or "").strip().lower()
    if protocol not in {"tcp", "udp"}:
        raise MonitoringContractError("endpoint protocol must be tcp or udp")
    return protocol


def endpoint_ref(*, protocol: str, ip: str, port: int) -> str:
    """Return a typed endpoint hash without retaining raw IP/port in contracts."""

    proto = _protocol(protocol)
    try:
        normalized_ip = str(ipaddress.ip_address(str(ip or "").strip()))
    except ValueError as exc:
        raise MonitoringContractError("endpoint IP must be a literal address") from exc
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise MonitoringContractError("endpoint port must be an integer within 1..65535")
    digest = hashlib.sha256(
        f"workspace-endpoint-v1:{proto}:{normalized_ip}:{port}".encode("utf-8")
    ).hexdigest()
    return f"endpoint:{proto}:sha256:{digest}"


def _validate_endpoint_ref(value: str, field_name: str) -> str:
    ref = str(value or "").strip().lower()
    if _ENDPOINT_REF_RE.fullmatch(ref) is None:
        raise MonitoringContractError(f"{field_name} must be a typed endpoint hash")
    return ref


@dataclass(frozen=True)
class FlowTupleEvidence:
    """Privacy-preserving exact network tuple derived from already-authorized sensor evidence."""

    event_id: str
    observed_at: str
    source_endpoint_ref: str
    destination_endpoint_ref: str
    evidence_ref: str
    authority: str = "evidence_only"
    schema_version: str = FLOW_TUPLE_SCHEMA

    @classmethod
    def build(
        cls,
        *,
        event_id: str,
        observed_at: str,
        protocol: str,
        source_ip: str,
        source_port: int,
        destination_ip: str,
        destination_port: int,
        evidence_ref: str,
    ) -> "FlowTupleEvidence":
        return cls(
            event_id=event_id,
            observed_at=observed_at,
            source_endpoint_ref=endpoint_ref(protocol=protocol, ip=source_ip, port=source_port),
            destination_endpoint_ref=endpoint_ref(protocol=protocol, ip=destination_ip, port=destination_port),
            evidence_ref=evidence_ref,
        ).validate()

    def validate(self) -> "FlowTupleEvidence":
        object.__setattr__(self, "event_id", _compact(self.event_id, "event_id", max_len=128))
        object.__setattr__(self, "observed_at", _utc(self.observed_at, "observed_at"))
        source = _validate_endpoint_ref(self.source_endpoint_ref, "source_endpoint_ref")
        destination = _validate_endpoint_ref(self.destination_endpoint_ref, "destination_endpoint_ref")
        if source.split(":", 2)[1] != destination.split(":", 2)[1]:
            raise MonitoringContractError("flow endpoints must use the same protocol")
        if source == destination:
            raise MonitoringContractError("flow endpoints must be distinct")
        object.__setattr__(self, "source_endpoint_ref", source)
        object.__setattr__(self, "destination_endpoint_ref", destination)
        object.__setattr__(self, "evidence_ref", _compact(self.evidence_ref, "evidence_ref", max_len=256))
        if self.authority != "evidence_only":
            raise MonitoringContractError("flow tuple authority must remain evidence_only")
        if self.schema_version != FLOW_TUPLE_SCHEMA:
            raise MonitoringContractError("unsupported flow tuple schema")
        return self

    @property
    def protocol(self) -> str:
        self.validate()
        return self.source_endpoint_ref.split(":", 2)[1]

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "authority": self.authority,
            "destination_endpoint_ref": self.destination_endpoint_ref,
            "event_id": self.event_id,
            "evidence_ref": self.evidence_ref,
            "observed_at": self.observed_at,
            "schema_version": self.schema_version,
            "source_endpoint_ref": self.source_endpoint_ref,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


@dataclass(frozen=True)
class SocketProcessObservation:
    """Caller-supplied read-only socket/process snapshot with no acquisition authority."""

    asset_ref: str
    observed_at: str
    local_endpoint_ref: str
    remote_endpoint_ref: str
    process_ref: str
    evidence_ref: str
    user_ref: str | None = None
    authority: str = "evidence_only"
    schema_version: str = SOCKET_PROCESS_SCHEMA

    @classmethod
    def build(
        cls,
        *,
        approved_asset_id: str,
        observed_at: str,
        protocol: str,
        local_ip: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
        process_image: str,
        evidence_ref: str,
        user: str | None = None,
    ) -> "SocketProcessObservation":
        return cls(
            asset_ref=approved_asset_ref(approved_asset_id),
            observed_at=observed_at,
            local_endpoint_ref=endpoint_ref(protocol=protocol, ip=local_ip, port=local_port),
            remote_endpoint_ref=endpoint_ref(protocol=protocol, ip=remote_ip, port=remote_port),
            process_ref=opaque_entity_ref("process", process_image),
            user_ref=opaque_entity_ref("user", user) if user is not None else None,
            evidence_ref=evidence_ref,
        ).validate()

    def validate(self) -> "SocketProcessObservation":
        asset = str(self.asset_ref or "").strip()
        if _ASSET_REF_RE.fullmatch(asset) is None:
            raise MonitoringContractError("socket observation asset_ref must be an approved asset reference")
        object.__setattr__(self, "asset_ref", asset)
        object.__setattr__(self, "observed_at", _utc(self.observed_at, "observed_at"))
        local = _validate_endpoint_ref(self.local_endpoint_ref, "local_endpoint_ref")
        remote = _validate_endpoint_ref(self.remote_endpoint_ref, "remote_endpoint_ref")
        if local.split(":", 2)[1] != remote.split(":", 2)[1]:
            raise MonitoringContractError("socket endpoints must use the same protocol")
        if local == remote:
            raise MonitoringContractError("socket endpoints must be distinct")
        object.__setattr__(self, "local_endpoint_ref", local)
        object.__setattr__(self, "remote_endpoint_ref", remote)
        process = str(self.process_ref or "").strip().lower()
        if _PROCESS_REF_RE.fullmatch(process) is None:
            raise MonitoringContractError("process_ref must be a typed process hash")
        object.__setattr__(self, "process_ref", process)
        if self.user_ref is not None:
            user = str(self.user_ref or "").strip().lower()
            if _USER_REF_RE.fullmatch(user) is None:
                raise MonitoringContractError("user_ref must be a typed user hash")
            object.__setattr__(self, "user_ref", user)
        object.__setattr__(self, "evidence_ref", _compact(self.evidence_ref, "evidence_ref", max_len=256))
        if self.authority != "evidence_only":
            raise MonitoringContractError("socket observation authority must remain evidence_only")
        if self.schema_version != SOCKET_PROCESS_SCHEMA:
            raise MonitoringContractError("unsupported socket process schema")
        return self

    @property
    def protocol(self) -> str:
        self.validate()
        return self.local_endpoint_ref.split(":", 2)[1]

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "asset_ref": self.asset_ref,
            "authority": self.authority,
            "evidence_ref": self.evidence_ref,
            "local_endpoint_ref": self.local_endpoint_ref,
            "observed_at": self.observed_at,
            "process_ref": self.process_ref,
            "remote_endpoint_ref": self.remote_endpoint_ref,
            "schema_version": self.schema_version,
            "user_ref": self.user_ref,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())
