from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from .contracts import MonitoringContractError, _compact, canonical_json, sha256_fingerprint

EDGE_AGENT_DESCRIPTOR_SCHEMA = "workspace-security-monitoring/edge-agent-descriptor-v1"
EDGE_COLLECTION_REQUEST_SCHEMA = "workspace-security-monitoring/edge-collection-request-v1"
EDGE_EVIDENCE_ITEM_SCHEMA = "workspace-security-monitoring/edge-evidence-item-v1"
EDGE_EVIDENCE_ENVELOPE_SCHEMA = "workspace-security-monitoring/edge-evidence-envelope-v1"
AUTHENTICATED_EDGE_ENVELOPE_SCHEMA = "workspace-security-monitoring/authenticated-edge-envelope-v1"
EDGE_READ_ONLY_CAPABILITIES = frozenset({"local_net_read", "fixed_readonly_adapter"})

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HMAC_RE = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
_ASSET_REF_RE = re.compile(r"^asset:[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,127}$")


class EdgeBackpressure(RuntimeError):
    pass


def _utc(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise MonitoringContractError(f"{field_name} must include timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _fingerprint(value: str, field_name: str) -> str:
    text = str(value or "").strip().lower()
    if _SHA256_RE.fullmatch(text) is None:
        raise MonitoringContractError(f"{field_name} must be a SHA-256 fingerprint")
    return text


def _asset_ref(value: str) -> str:
    text = str(value or "").strip()
    if _ASSET_REF_RE.fullmatch(text) is None:
        raise MonitoringContractError("edge agent asset_ref must be an approved asset reference")
    return text


def _bounded_int(value: int, field_name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise MonitoringContractError(f"{field_name} must be within {minimum}..{maximum}")
    return value


def _auth_key(authentication_key: bytes) -> bytes:
    if not isinstance(authentication_key, bytes) or not 32 <= len(authentication_key) <= 128:
        raise MonitoringContractError("edge authentication key must contain 32..128 bytes")
    return authentication_key


@dataclass(frozen=True)
class EdgeAgentDescriptor:
    agent_id: str
    asset_ref: str
    allowed_capabilities: tuple[str, ...]
    policy_fingerprint: str
    config_fingerprint: str
    auth_key_id: str
    schema_version: str = EDGE_AGENT_DESCRIPTOR_SCHEMA

    def validate(self) -> "EdgeAgentDescriptor":
        object.__setattr__(self, "agent_id", _compact(self.agent_id, "agent_id", max_len=128))
        object.__setattr__(self, "asset_ref", _asset_ref(self.asset_ref))
        capabilities = tuple(sorted(set(str(value or "").strip() for value in self.allowed_capabilities)))
        if not capabilities or any(value not in EDGE_READ_ONLY_CAPABILITIES for value in capabilities):
            raise MonitoringContractError("edge agent capabilities must remain local read-only")
        object.__setattr__(self, "allowed_capabilities", capabilities)
        object.__setattr__(self, "policy_fingerprint", _fingerprint(self.policy_fingerprint, "policy_fingerprint"))
        object.__setattr__(self, "config_fingerprint", _fingerprint(self.config_fingerprint, "config_fingerprint"))
        object.__setattr__(self, "auth_key_id", _compact(self.auth_key_id, "auth_key_id", max_len=128))
        if self.schema_version != EDGE_AGENT_DESCRIPTOR_SCHEMA:
            raise MonitoringContractError("unsupported edge agent descriptor schema")
        return self

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "agent_id": self.agent_id,
            "allowed_capabilities": list(self.allowed_capabilities),
            "asset_ref": self.asset_ref,
            "auth_key_id": self.auth_key_id,
            "config_fingerprint": self.config_fingerprint,
            "policy_fingerprint": self.policy_fingerprint,
            "schema_version": self.schema_version,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


@dataclass(frozen=True)
class EdgeCollectionRequest:
    request_id: str
    agent_id: str
    asset_ref: str
    capability: str
    issued_at: str
    expires_at: str
    policy_fingerprint: str
    config_fingerprint: str
    max_records: int = 1000
    max_payload_bytes: int = 4 * 1024 * 1024
    authority: str = "read_only"
    schema_version: str = EDGE_COLLECTION_REQUEST_SCHEMA

    def validate(self) -> "EdgeCollectionRequest":
        object.__setattr__(self, "request_id", _compact(self.request_id, "request_id", max_len=128))
        object.__setattr__(self, "agent_id", _compact(self.agent_id, "agent_id", max_len=128))
        object.__setattr__(self, "asset_ref", _asset_ref(self.asset_ref))
        capability = str(self.capability or "").strip()
        if capability not in EDGE_READ_ONLY_CAPABILITIES:
            raise MonitoringContractError("edge collection capability must remain local read-only")
        object.__setattr__(self, "capability", capability)
        issued = _utc(self.issued_at, "issued_at")
        expires = _utc(self.expires_at, "expires_at")
        if _dt(expires) <= _dt(issued):
            raise MonitoringContractError("edge request expires_at must be after issued_at")
        if (_dt(expires) - _dt(issued)).total_seconds() > 3600:
            raise MonitoringContractError("edge request lifetime cannot exceed one hour")
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)
        object.__setattr__(self, "policy_fingerprint", _fingerprint(self.policy_fingerprint, "policy_fingerprint"))
        object.__setattr__(self, "config_fingerprint", _fingerprint(self.config_fingerprint, "config_fingerprint"))
        _bounded_int(self.max_records, "max_records", 1, 10000)
        _bounded_int(self.max_payload_bytes, "max_payload_bytes", 1, 16 * 1024 * 1024)
        if self.authority != "read_only":
            raise MonitoringContractError("edge collection authority must remain read_only")
        if self.schema_version != EDGE_COLLECTION_REQUEST_SCHEMA:
            raise MonitoringContractError("unsupported edge collection request schema")
        return self

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "agent_id": self.agent_id,
            "asset_ref": self.asset_ref,
            "authority": self.authority,
            "capability": self.capability,
            "config_fingerprint": self.config_fingerprint,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "max_payload_bytes": self.max_payload_bytes,
            "max_records": self.max_records,
            "policy_fingerprint": self.policy_fingerprint,
            "request_id": self.request_id,
            "schema_version": self.schema_version,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


def authorize_edge_request(
    *,
    descriptor: EdgeAgentDescriptor,
    request: EdgeCollectionRequest,
    evaluated_at: str,
) -> EdgeCollectionRequest:
    descriptor = descriptor.validate()
    request = request.validate()
    evaluated = _utc(evaluated_at, "evaluated_at")
    if request.agent_id != descriptor.agent_id:
        raise PermissionError("EDGE_AGENT_ID_MISMATCH")
    if request.asset_ref != descriptor.asset_ref:
        raise PermissionError("EDGE_ASSET_NOT_APPROVED")
    if request.capability not in descriptor.allowed_capabilities:
        raise PermissionError("EDGE_CAPABILITY_NOT_APPROVED")
    if request.policy_fingerprint != descriptor.policy_fingerprint:
        raise PermissionError("EDGE_POLICY_FINGERPRINT_MISMATCH")
    if request.config_fingerprint != descriptor.config_fingerprint:
        raise PermissionError("EDGE_CONFIG_FINGERPRINT_MISMATCH")
    if not _dt(request.issued_at) <= _dt(evaluated) <= _dt(request.expires_at):
        raise PermissionError("EDGE_REQUEST_EXPIRED_OR_NOT_YET_VALID")
    return request


@dataclass(frozen=True, order=True)
class EdgeEvidenceItem:
    sequence: int
    evidence_ref: str
    observed_at: str
    payload_sha256: str
    payload_bytes: int
    schema_version: str = EDGE_EVIDENCE_ITEM_SCHEMA

    def validate(self) -> "EdgeEvidenceItem":
        _bounded_int(self.sequence, "sequence", 0, 2**63 - 1)
        object.__setattr__(self, "evidence_ref", _compact(self.evidence_ref, "evidence_ref", max_len=256))
        object.__setattr__(self, "observed_at", _utc(self.observed_at, "observed_at"))
        object.__setattr__(self, "payload_sha256", _fingerprint(self.payload_sha256, "payload_sha256"))
        _bounded_int(self.payload_bytes, "payload_bytes", 1, 1024 * 1024)
        if self.schema_version != EDGE_EVIDENCE_ITEM_SCHEMA:
            raise MonitoringContractError("unsupported edge evidence item schema")
        return self

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "evidence_ref": self.evidence_ref,
            "observed_at": self.observed_at,
            "payload_bytes": self.payload_bytes,
            "payload_sha256": self.payload_sha256,
            "schema_version": self.schema_version,
            "sequence": self.sequence,
        }


@dataclass(frozen=True)
class EdgeEvidenceEnvelope:
    agent_id: str
    asset_ref: str
    request_id: str
    policy_fingerprint: str
    config_fingerprint: str
    created_at: str
    items: tuple[EdgeEvidenceItem, ...]
    previous_envelope_fingerprint: str | None = None
    authority: str = "evidence_only"
    schema_version: str = EDGE_EVIDENCE_ENVELOPE_SCHEMA

    def validate(self) -> "EdgeEvidenceEnvelope":
        object.__setattr__(self, "agent_id", _compact(self.agent_id, "agent_id", max_len=128))
        object.__setattr__(self, "asset_ref", _asset_ref(self.asset_ref))
        object.__setattr__(self, "request_id", _compact(self.request_id, "request_id", max_len=128))
        object.__setattr__(self, "policy_fingerprint", _fingerprint(self.policy_fingerprint, "policy_fingerprint"))
        object.__setattr__(self, "config_fingerprint", _fingerprint(self.config_fingerprint, "config_fingerprint"))
        object.__setattr__(self, "created_at", _utc(self.created_at, "created_at"))
        validated = tuple(item.validate() for item in self.items)
        if not validated or len(validated) > 10000:
            raise MonitoringContractError("edge evidence envelope must contain 1..10000 items")
        if tuple(sorted(validated, key=lambda item: item.sequence)) != validated:
            raise MonitoringContractError("edge evidence items must be ordered by sequence")
        sequences = tuple(item.sequence for item in validated)
        if len(set(sequences)) != len(sequences):
            raise MonitoringContractError("edge evidence sequences must be unique")
        if any(right != left + 1 for left, right in zip(sequences, sequences[1:])):
            raise MonitoringContractError("edge evidence sequences must be contiguous")
        object.__setattr__(self, "items", validated)
        if self.previous_envelope_fingerprint is not None:
            object.__setattr__(
                self,
                "previous_envelope_fingerprint",
                _fingerprint(self.previous_envelope_fingerprint, "previous_envelope_fingerprint"),
            )
        if self.authority != "evidence_only":
            raise MonitoringContractError("edge evidence authority must remain evidence_only")
        if self.schema_version != EDGE_EVIDENCE_ENVELOPE_SCHEMA:
            raise MonitoringContractError("unsupported edge evidence envelope schema")
        return self

    @property
    def payload_bytes(self) -> int:
        self.validate()
        return sum(item.payload_bytes for item in self.items)

    @property
    def first_sequence(self) -> int:
        self.validate()
        return self.items[0].sequence

    @property
    def last_sequence(self) -> int:
        self.validate()
        return self.items[-1].sequence

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "agent_id": self.agent_id,
            "asset_ref": self.asset_ref,
            "authority": self.authority,
            "config_fingerprint": self.config_fingerprint,
            "created_at": self.created_at,
            "items": [item.to_dict() for item in self.items],
            "policy_fingerprint": self.policy_fingerprint,
            "previous_envelope_fingerprint": self.previous_envelope_fingerprint,
            "request_id": self.request_id,
            "schema_version": self.schema_version,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


@dataclass(frozen=True)
class AuthenticatedEdgeEnvelope:
    envelope: EdgeEvidenceEnvelope
    auth_key_id: str
    auth_tag: str
    schema_version: str = AUTHENTICATED_EDGE_ENVELOPE_SCHEMA

    def validate(self) -> "AuthenticatedEdgeEnvelope":
        self.envelope.validate()
        object.__setattr__(self, "auth_key_id", _compact(self.auth_key_id, "auth_key_id", max_len=128))
        tag = str(self.auth_tag or "").strip().lower()
        if _HMAC_RE.fullmatch(tag) is None:
            raise MonitoringContractError("edge auth_tag must be an HMAC-SHA256 digest")
        object.__setattr__(self, "auth_tag", tag)
        if self.schema_version != AUTHENTICATED_EDGE_ENVELOPE_SCHEMA:
            raise MonitoringContractError("unsupported authenticated edge envelope schema")
        return self

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "auth_key_id": self.auth_key_id,
            "auth_tag": self.auth_tag,
            "envelope": self.envelope.to_dict(),
            "schema_version": self.schema_version,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


def build_edge_envelope(
    *,
    descriptor: EdgeAgentDescriptor,
    request: EdgeCollectionRequest,
    evaluated_at: str,
    created_at: str,
    items: tuple[EdgeEvidenceItem, ...],
    previous_envelope_fingerprint: str | None = None,
) -> EdgeEvidenceEnvelope:
    authorize_edge_request(descriptor=descriptor, request=request, evaluated_at=evaluated_at)
    validated_items = tuple(item.validate() for item in items)
    if len(validated_items) > request.max_records:
        raise MonitoringContractError("edge request record bound exceeded")
    if sum(item.payload_bytes for item in validated_items) > request.max_payload_bytes:
        raise MonitoringContractError("edge request payload byte bound exceeded")
    return EdgeEvidenceEnvelope(
        agent_id=descriptor.agent_id,
        asset_ref=descriptor.asset_ref,
        request_id=request.request_id,
        policy_fingerprint=descriptor.policy_fingerprint,
        config_fingerprint=descriptor.config_fingerprint,
        created_at=created_at,
        items=validated_items,
        previous_envelope_fingerprint=previous_envelope_fingerprint,
    ).validate()


def seal_edge_envelope(
    *,
    envelope: EdgeEvidenceEnvelope,
    auth_key_id: str,
    authentication_key: bytes,
) -> AuthenticatedEdgeEnvelope:
    envelope = envelope.validate()
    key_id = _compact(auth_key_id, "auth_key_id", max_len=128)
    key = _auth_key(authentication_key)
    digest = hmac.new(key, envelope.to_json().encode("utf-8"), hashlib.sha256).hexdigest()
    return AuthenticatedEdgeEnvelope(
        envelope=envelope,
        auth_key_id=key_id,
        auth_tag="hmac-sha256:" + digest,
    ).validate()


def verify_edge_envelope(
    *,
    sealed: AuthenticatedEdgeEnvelope,
    descriptor: EdgeAgentDescriptor,
    authentication_key: bytes,
) -> bool:
    sealed = sealed.validate()
    descriptor = descriptor.validate()
    key = _auth_key(authentication_key)
    if sealed.auth_key_id != descriptor.auth_key_id:
        return False
    if sealed.envelope.agent_id != descriptor.agent_id or sealed.envelope.asset_ref != descriptor.asset_ref:
        return False
    if sealed.envelope.policy_fingerprint != descriptor.policy_fingerprint:
        return False
    if sealed.envelope.config_fingerprint != descriptor.config_fingerprint:
        return False
    expected = hmac.new(
        key,
        sealed.envelope.to_json().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(sealed.auth_tag, "hmac-sha256:" + expected)


@dataclass(frozen=True)
class EdgeQueuePolicy:
    max_envelopes: int = 128
    max_total_payload_bytes: int = 16 * 1024 * 1024

    def validate(self) -> "EdgeQueuePolicy":
        _bounded_int(self.max_envelopes, "max_envelopes", 1, 1024)
        _bounded_int(
            self.max_total_payload_bytes,
            "max_total_payload_bytes",
            1,
            128 * 1024 * 1024,
        )
        return self


class BoundedEdgeEnvelopeQueue:
    """In-memory offline queue with explicit authentication, chain and backpressure bounds."""

    def __init__(
        self,
        *,
        descriptor: EdgeAgentDescriptor,
        policy: EdgeQueuePolicy | None = None,
        expected_previous_fingerprint: str | None = None,
    ) -> None:
        self.descriptor = descriptor.validate()
        self.policy = (policy or EdgeQueuePolicy()).validate()
        self._expected_previous_fingerprint = (
            _fingerprint(expected_previous_fingerprint, "expected_previous_fingerprint")
            if expected_previous_fingerprint is not None
            else None
        )
        self._items: list[AuthenticatedEdgeEnvelope] = []
        self._payload_bytes = 0

    @property
    def pending_count(self) -> int:
        return len(self._items)

    @property
    def pending_payload_bytes(self) -> int:
        return self._payload_bytes

    def append(self, sealed: AuthenticatedEdgeEnvelope, *, authentication_key: bytes) -> None:
        sealed = sealed.validate()
        if not verify_edge_envelope(
            sealed=sealed,
            descriptor=self.descriptor,
            authentication_key=authentication_key,
        ):
            raise MonitoringContractError("edge envelope authentication failed")
        expected_previous = (
            self._items[-1].envelope.fingerprint
            if self._items
            else self._expected_previous_fingerprint
        )
        if sealed.envelope.previous_envelope_fingerprint != expected_previous:
            raise MonitoringContractError("edge envelope hash chain discontinuity")
        if self._items and sealed.envelope.first_sequence != self._items[-1].envelope.last_sequence + 1:
            raise MonitoringContractError("edge envelope sequence discontinuity")
        if self.pending_count + 1 > self.policy.max_envelopes:
            raise EdgeBackpressure("EDGE_QUEUE_BACKPRESSURE")
        if self._payload_bytes + sealed.envelope.payload_bytes > self.policy.max_total_payload_bytes:
            raise EdgeBackpressure("EDGE_QUEUE_BACKPRESSURE")
        self._items.append(sealed)
        self._payload_bytes += sealed.envelope.payload_bytes

    def peek(self, *, limit: int = 32) -> tuple[AuthenticatedEdgeEnvelope, ...]:
        _bounded_int(limit, "limit", 1, 256)
        return tuple(self._items[:limit])

    def ack(self, *, count: int) -> tuple[str, ...]:
        _bounded_int(count, "count", 1, 256)
        if count > len(self._items):
            raise MonitoringContractError("cannot acknowledge more edge envelopes than pending")
        removed = self._items[:count]
        del self._items[:count]
        self._payload_bytes -= sum(item.envelope.payload_bytes for item in removed)
        if removed:
            self._expected_previous_fingerprint = removed[-1].envelope.fingerprint
        return tuple(item.envelope.fingerprint for item in removed)
