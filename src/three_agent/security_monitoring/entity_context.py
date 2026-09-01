from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass

from .contracts import MonitoringContractError, _compact

ENTITY_CONTEXT_SCHEMA = "workspace-security-monitoring/event-entity-context-v1"
MAX_ENTITY_REFERENCES = 16
ENTITY_KINDS = {"ip", "dns", "user", "process", "asset", "service"}
ENTITY_ROLES = {
    "source_ip": "ip",
    "destination_ip": "ip",
    "dns_query": "dns",
    "dns_answer": "ip",
    "asset": "asset",
    "auth_user": "user",
    "process_image": "process",
    "service": "service",
}
_HASHED_REF_RE = re.compile(r"^entity:([a-z]+):sha256:([0-9a-f]{64})$")
_ASSET_REF_RE = re.compile(r"^asset:([A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,127})$")


def _normalize_entity_value(kind: str, value: str) -> str:
    if kind not in ENTITY_KINDS - {"asset"}:
        raise MonitoringContractError("unsupported opaque entity kind")
    text = str(value or "").strip()
    if not text or len(text) > 512:
        raise MonitoringContractError("entity value must contain 1..512 characters")
    if any(ord(ch) < 32 for ch in text):
        raise MonitoringContractError("entity value contains control characters")
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(text))
        except ValueError as exc:
            raise MonitoringContractError("IP entity must be a literal address") from exc
    if kind == "dns":
        normalized = text.rstrip(".").lower()
        if not normalized or len(normalized) > 253 or any(ch.isspace() for ch in normalized):
            raise MonitoringContractError("DNS entity is invalid")
        return normalized
    if kind == "service":
        normalized = text.lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9._:+\-/]{0,95}", normalized):
            raise MonitoringContractError("service entity is invalid")
        return normalized
    # User/process identifiers are intentionally not case-folded: identity
    # semantics differ across operating systems. Exact normalized input must
    # match exactly to create a future correlation edge.
    return text


def opaque_entity_ref(kind: str, value: str) -> str:
    """Return a deterministic typed fingerprint without retaining the raw value."""

    normalized = _normalize_entity_value(kind, value)
    digest = hashlib.sha256((f"workspace-entity-v1:{kind}:" + normalized).encode("utf-8")).hexdigest()
    return f"entity:{kind}:sha256:{digest}"


def approved_asset_ref(asset_id: str) -> str:
    """Approved inventory IDs may remain explicit; no discovered host is accepted here."""

    return "asset:" + _compact(asset_id, "asset_id", max_len=128)


@dataclass(frozen=True, order=True)
class EventEntityReference:
    kind: str
    role: str
    entity_ref: str

    def validate(self) -> "EventEntityReference":
        kind = str(self.kind or "").strip().lower()
        role = str(self.role or "").strip().lower()
        if kind not in ENTITY_KINDS:
            raise MonitoringContractError("unsupported entity kind")
        expected = ENTITY_ROLES.get(role)
        if expected != kind:
            raise MonitoringContractError("entity role/kind binding is invalid")
        ref = str(self.entity_ref or "").strip()
        if kind == "asset":
            if not _ASSET_REF_RE.fullmatch(ref):
                raise MonitoringContractError("asset entity_ref must be an approved asset reference")
        else:
            match = _HASHED_REF_RE.fullmatch(ref)
            if match is None or match.group(1) != kind:
                raise MonitoringContractError("sensitive entity_ref must be a typed SHA-256 reference")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "role", role)
        object.__setattr__(self, "entity_ref", ref)
        return self

    @classmethod
    def opaque(cls, *, kind: str, role: str, value: str) -> "EventEntityReference":
        return cls(kind=kind, role=role, entity_ref=opaque_entity_ref(kind, value)).validate()

    @classmethod
    def approved_asset(cls, *, role: str, asset_id: str) -> "EventEntityReference":
        return cls(kind="asset", role=role, entity_ref=approved_asset_ref(asset_id)).validate()


@dataclass(frozen=True)
class EventEntityContext:
    event_id: str
    references: tuple[EventEntityReference, ...]
    schema_version: str = ENTITY_CONTEXT_SCHEMA

    def validate(self) -> "EventEntityContext":
        event_id = _compact(self.event_id, "event_id", max_len=128)
        if self.schema_version != ENTITY_CONTEXT_SCHEMA:
            raise MonitoringContractError("unsupported event entity context schema")
        validated = tuple(reference.validate() for reference in self.references)
        unique = tuple(sorted(set(validated)))
        if len(unique) > MAX_ENTITY_REFERENCES:
            raise MonitoringContractError("event entity context exceeds reference bound")
        object.__setattr__(self, "event_id", event_id)
        object.__setattr__(self, "references", unique)
        return self

    def refs_for_role(self, role: str) -> tuple[str, ...]:
        role_name = str(role or "").strip().lower()
        if role_name not in ENTITY_ROLES:
            raise MonitoringContractError("unsupported entity role")
        self.validate()
        return tuple(reference.entity_ref for reference in self.references if reference.role == role_name)

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "references": [
                {"kind": reference.kind, "role": reference.role, "entity_ref": reference.entity_ref}
                for reference in self.references
            ],
        }
