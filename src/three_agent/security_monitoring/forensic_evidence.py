from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable

from .contracts import APPROVED_DATA_CLASSES, MonitoringContractError, sha256_fingerprint

FORENSIC_EVIDENCE_SCHEMA = "workspace-security-forensics/evidence-v1"
FORENSIC_EVIDENCE_REFERENCE_SCHEMA = "workspace-security-forensics/evidence-reference-v1"
FORENSIC_PROVENANCE_SCHEMA = "workspace-security-forensics/provenance-v1"
FORENSIC_EVENT_TIME_SCHEMA = "workspace-security-forensics/event-time-v1"
FORENSIC_DERIVED_EVIDENCE_SCHEMA = "workspace-security-forensics/derived-evidence-v1"
FORENSIC_CUSTODY_EVENT_SCHEMA = "workspace-security-forensics/custody-event-v1"
FORENSIC_CASE_AUTHORIZATION_SCHEMA = "workspace-security-forensics/case-authorization-v1"
FORENSIC_CASE_SCHEMA = "workspace-security-forensics/case-v1"
FORENSIC_COLLECTION_FOOTPRINT_SCHEMA = "workspace-security-forensics/collection-footprint-v1"

FORENSIC_EVIDENCE_TYPES = frozenset(
    {
        "network_event",
        "pcap",
        "dns",
        "flow",
        "authentication",
        "process",
        "ids",
        "host_log",
        "filesystem_artifact",
        "memory_artifact",
        "indicator",
        "timeline",
        "report",
        "other_metadata",
    }
)
FORENSIC_REFERENCE_RELATIONS = frozenset(
    {"source", "supports", "contradicts", "derived_from", "timeline", "scope"}
)
FORENSIC_CASE_STATUSES = frozenset({"open", "investigating", "closed"})
FORENSIC_CUSTODY_ACTIONS = frozenset(
    {"registered", "verified", "derived", "linked_to_case", "reviewed", "exported_metadata"}
)

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ACTOR_RE = re.compile(r"^actor:sha256:[0-9a-f]{64}$")

MAX_FORENSIC_EVIDENCE_BYTES = 1024 * 1024 * 1024 * 1024
MAX_CASE_EVIDENCE_REFS = 10_000
MAX_DERIVATION_INPUTS = 256
MAX_PROVENANCE_UPSTREAM_REFS = 256
MAX_CASE_ASSET_REFS = 4096


def _identifier(value: str, field_name: str, *, max_len: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or not _ID_RE.fullmatch(text):
        raise MonitoringContractError(f"{field_name} must be a compact identifier")
    if "://" in text or "\\" in text:
        raise MonitoringContractError(f"{field_name} must not contain a URL or filesystem path")
    return text


def _sha(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not _SHA256_RE.fullmatch(text):
        raise MonitoringContractError(f"{field_name} must be a SHA-256 fingerprint")
    return text


def _parse_timestamp(value: str, field_name: str) -> datetime:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MonitoringContractError(f"{field_name} must include timezone")
    return parsed


def _timestamp(value: str, field_name: str, *, normalize_utc: bool = True) -> str:
    text = str(value or "").strip()
    parsed = _parse_timestamp(text, field_name)
    if not normalize_utc:
        return text
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_ids(values: Iterable[str], field_name: str, *, limit: int) -> tuple[str, ...]:
    rows = tuple(_identifier(value, field_name) for value in values)
    if len(rows) > limit:
        raise MonitoringContractError(f"{field_name} bound exceeded")
    if len(rows) != len(set(rows)):
        raise MonitoringContractError(f"{field_name} values must be unique")
    return tuple(sorted(rows))


def _evidence_id(value: str) -> str:
    text = _identifier(value, "evidence_id", max_len=128)
    if not text.startswith("evidence:") or len(text) <= len("evidence:"):
        raise MonitoringContractError("evidence_id must start with evidence:")
    return text


@dataclass(frozen=True)
class ForensicEventTime:
    original_timestamp: str
    normalized_utc: str
    source_clock_ref: str
    uncertainty_ms: int = 0
    schema_version: str = FORENSIC_EVENT_TIME_SCHEMA

    def validate(self) -> "ForensicEventTime":
        original = _timestamp(self.original_timestamp, "original_timestamp", normalize_utc=False)
        normalized = _timestamp(self.normalized_utc, "normalized_utc")
        if _parse_timestamp(original, "original_timestamp").astimezone(timezone.utc) != _parse_timestamp(
            normalized, "normalized_utc"
        ).astimezone(timezone.utc):
            raise MonitoringContractError("normalized_utc must represent the same instant as original_timestamp")
        if isinstance(self.uncertainty_ms, bool) or not isinstance(self.uncertainty_ms, int):
            raise MonitoringContractError("uncertainty_ms must be an integer")
        if not 0 <= self.uncertainty_ms <= 86_400_000:
            raise MonitoringContractError("uncertainty_ms must be within 0..86400000")
        object.__setattr__(self, "original_timestamp", original)
        object.__setattr__(self, "normalized_utc", normalized)
        object.__setattr__(self, "source_clock_ref", _identifier(self.source_clock_ref, "source_clock_ref", max_len=128))
        if self.schema_version != FORENSIC_EVENT_TIME_SCHEMA:
            raise MonitoringContractError("unsupported forensic event-time schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


@dataclass(frozen=True)
class EvidenceProvenance:
    source_id: str
    source_type: str
    collected_at: str
    producer_id: str
    producer_version: str
    source_content_sha256: str
    upstream_evidence_refs: tuple[str, ...] = ()
    schema_version: str = FORENSIC_PROVENANCE_SCHEMA

    def validate(self) -> "EvidenceProvenance":
        object.__setattr__(self, "source_id", _identifier(self.source_id, "source_id", max_len=128))
        object.__setattr__(self, "source_type", _identifier(self.source_type, "source_type", max_len=64))
        object.__setattr__(self, "collected_at", _timestamp(self.collected_at, "collected_at"))
        object.__setattr__(self, "producer_id", _identifier(self.producer_id, "producer_id", max_len=128))
        object.__setattr__(self, "producer_version", _identifier(self.producer_version, "producer_version", max_len=96))
        object.__setattr__(self, "source_content_sha256", _sha(self.source_content_sha256, "source_content_sha256"))
        upstream = tuple(_evidence_id(value) for value in self.upstream_evidence_refs)
        if len(upstream) > MAX_PROVENANCE_UPSTREAM_REFS:
            raise MonitoringContractError("upstream_evidence_refs bound exceeded")
        if len(upstream) != len(set(upstream)):
            raise MonitoringContractError("upstream_evidence_refs must be unique")
        object.__setattr__(self, "upstream_evidence_refs", tuple(sorted(upstream)))
        if self.schema_version != FORENSIC_PROVENANCE_SCHEMA:
            raise MonitoringContractError("unsupported forensic provenance schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        payload = asdict(self)
        payload["upstream_evidence_refs"] = list(self.upstream_evidence_refs)
        return payload

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


@dataclass(frozen=True, order=True)
class EvidenceReference:
    evidence_id: str
    content_sha256: str
    relation: str = "source"
    schema_version: str = FORENSIC_EVIDENCE_REFERENCE_SCHEMA

    def validate(self) -> "EvidenceReference":
        object.__setattr__(self, "evidence_id", _evidence_id(self.evidence_id))
        object.__setattr__(self, "content_sha256", _sha(self.content_sha256, "content_sha256"))
        if self.relation not in FORENSIC_REFERENCE_RELATIONS:
            raise MonitoringContractError("unsupported forensic evidence relation")
        if self.schema_version != FORENSIC_EVIDENCE_REFERENCE_SCHEMA:
            raise MonitoringContractError("unsupported forensic evidence-reference schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class EvidenceObject:
    evidence_id: str
    evidence_type: str
    content_sha256: str
    byte_size: int
    data_class: str
    provenance: EvidenceProvenance
    event_time: ForensicEventTime | None = None
    parent_evidence_refs: tuple[str, ...] = ()
    derived: bool = False
    immutable: bool = True
    payload_embedded: bool = False
    schema_version: str = FORENSIC_EVIDENCE_SCHEMA

    def validate(self) -> "EvidenceObject":
        object.__setattr__(self, "evidence_id", _evidence_id(self.evidence_id))
        if self.evidence_type not in FORENSIC_EVIDENCE_TYPES:
            raise MonitoringContractError("unsupported forensic evidence_type")
        object.__setattr__(self, "content_sha256", _sha(self.content_sha256, "content_sha256"))
        if isinstance(self.byte_size, bool) or not isinstance(self.byte_size, int):
            raise MonitoringContractError("byte_size must be an integer")
        if not 0 <= self.byte_size <= MAX_FORENSIC_EVIDENCE_BYTES:
            raise MonitoringContractError("byte_size exceeds forensic evidence bound")
        if self.data_class not in APPROVED_DATA_CLASSES:
            raise MonitoringContractError("unsupported forensic evidence data_class")
        if not isinstance(self.provenance, EvidenceProvenance):
            raise MonitoringContractError("evidence provenance type is invalid")
        self.provenance.validate()
        if self.event_time is not None:
            if not isinstance(self.event_time, ForensicEventTime):
                raise MonitoringContractError("event_time type is invalid")
            self.event_time.validate()
        parents = tuple(_evidence_id(value) for value in self.parent_evidence_refs)
        if len(parents) > MAX_DERIVATION_INPUTS:
            raise MonitoringContractError("parent_evidence_refs bound exceeded")
        if len(parents) != len(set(parents)):
            raise MonitoringContractError("parent_evidence_refs must be unique")
        if self.evidence_id in parents:
            raise MonitoringContractError("evidence cannot derive from itself")
        parents = tuple(sorted(parents))
        object.__setattr__(self, "parent_evidence_refs", parents)
        if self.derived and not parents:
            raise MonitoringContractError("derived evidence requires parent_evidence_refs")
        if not self.derived and parents:
            raise MonitoringContractError("source evidence cannot declare derivation parents")
        if not self.immutable:
            raise MonitoringContractError("forensic evidence metadata must remain immutable")
        if self.payload_embedded:
            raise MonitoringContractError("raw evidence payload must not be embedded in the canonical contract")
        if self.schema_version != FORENSIC_EVIDENCE_SCHEMA:
            raise MonitoringContractError("unsupported forensic evidence schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "content_sha256": self.content_sha256,
            "byte_size": self.byte_size,
            "data_class": self.data_class,
            "provenance": self.provenance.public_dict(),
            "event_time": None if self.event_time is None else self.event_time.public_dict(),
            "parent_evidence_refs": list(self.parent_evidence_refs),
            "derived": self.derived,
            "immutable": self.immutable,
            "payload_embedded": self.payload_embedded,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())

    def reference(self, relation: str = "source") -> EvidenceReference:
        return EvidenceReference(self.evidence_id, self.content_sha256, relation).validate()


@dataclass(frozen=True)
class DerivedEvidence:
    evidence: EvidenceObject
    derivation_id: str
    input_evidence_refs: tuple[EvidenceReference, ...]
    authority: str = "advisory"
    schema_version: str = FORENSIC_DERIVED_EVIDENCE_SCHEMA

    def validate(self) -> "DerivedEvidence":
        if not isinstance(self.evidence, EvidenceObject):
            raise MonitoringContractError("derived evidence output type is invalid")
        self.evidence.validate()
        if not self.evidence.derived:
            raise MonitoringContractError("DerivedEvidence requires evidence.derived=true")
        object.__setattr__(self, "derivation_id", _identifier(self.derivation_id, "derivation_id", max_len=128))
        refs = tuple(ref.validate() for ref in self.input_evidence_refs)
        if not refs or len(refs) > MAX_DERIVATION_INPUTS:
            raise MonitoringContractError("derived evidence requires bounded input evidence")
        if len({ref.evidence_id for ref in refs}) != len(refs):
            raise MonitoringContractError("derived evidence inputs must have unique evidence_id values")
        if any(ref.relation != "derived_from" for ref in refs):
            raise MonitoringContractError("derived evidence inputs must use derived_from relation")
        refs = tuple(sorted(refs, key=lambda ref: ref.evidence_id))
        object.__setattr__(self, "input_evidence_refs", refs)
        expected = tuple(ref.evidence_id for ref in refs)
        if self.evidence.parent_evidence_refs != expected:
            raise MonitoringContractError("derived evidence parent refs must exactly match input evidence refs")
        if self.evidence.provenance.upstream_evidence_refs != expected:
            raise MonitoringContractError("derived evidence provenance must preserve exact upstream lineage")
        if self.authority != "advisory":
            raise MonitoringContractError("derived evidence must remain advisory")
        if self.schema_version != FORENSIC_DERIVED_EVIDENCE_SCHEMA:
            raise MonitoringContractError("unsupported derived evidence schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "evidence": self.evidence.public_dict(),
            "derivation_id": self.derivation_id,
            "input_evidence_refs": [ref.public_dict() for ref in self.input_evidence_refs],
            "authority": self.authority,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


@dataclass(frozen=True)
class CustodyEvent:
    event_index: int
    evidence_id: str
    action: str
    actor_ref: str
    occurred_at: str
    previous_event_sha256: str | None
    note_sha256: str | None = None
    record_sha256: str = ""
    schema_version: str = FORENSIC_CUSTODY_EVENT_SCHEMA

    def _identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "event_index": self.event_index,
            "evidence_id": self.evidence_id,
            "action": self.action,
            "actor_ref": self.actor_ref,
            "occurred_at": self.occurred_at,
            "previous_event_sha256": self.previous_event_sha256,
            "note_sha256": self.note_sha256,
        }

    def validate(self) -> "CustodyEvent":
        if isinstance(self.event_index, bool) or not isinstance(self.event_index, int) or self.event_index < 1:
            raise MonitoringContractError("custody event_index must be a positive integer")
        object.__setattr__(self, "evidence_id", _evidence_id(self.evidence_id))
        if self.action not in FORENSIC_CUSTODY_ACTIONS:
            raise MonitoringContractError("unsupported custody action")
        actor = str(self.actor_ref or "").strip()
        if not _ACTOR_RE.fullmatch(actor):
            raise MonitoringContractError("actor_ref must be a typed SHA-256 reference")
        object.__setattr__(self, "actor_ref", actor)
        object.__setattr__(self, "occurred_at", _timestamp(self.occurred_at, "occurred_at"))
        if self.previous_event_sha256 is not None:
            object.__setattr__(self, "previous_event_sha256", _sha(self.previous_event_sha256, "previous_event_sha256"))
        if self.note_sha256 is not None:
            object.__setattr__(self, "note_sha256", _sha(self.note_sha256, "note_sha256"))
        if self.schema_version != FORENSIC_CUSTODY_EVENT_SCHEMA:
            raise MonitoringContractError("unsupported custody event schema")
        if self.record_sha256 != sha256_fingerprint(self._identity_payload()):
            raise MonitoringContractError("custody record_sha256 does not match event content")
        return self

    @classmethod
    def build(
        cls,
        *,
        event_index: int,
        evidence_id: str,
        action: str,
        actor_ref: str,
        occurred_at: str,
        previous_event_sha256: str | None,
        note_sha256: str | None = None,
    ) -> "CustodyEvent":
        evidence = _evidence_id(evidence_id)
        actor = str(actor_ref or "").strip()
        if not _ACTOR_RE.fullmatch(actor):
            raise MonitoringContractError("actor_ref must be a typed SHA-256 reference")
        occurred = _timestamp(occurred_at, "occurred_at")
        previous = None if previous_event_sha256 is None else _sha(previous_event_sha256, "previous_event_sha256")
        note = None if note_sha256 is None else _sha(note_sha256, "note_sha256")
        base = cls(event_index, evidence, action, actor, occurred, previous, note)
        record_sha256 = sha256_fingerprint(base._identity_payload())
        return cls(**{**asdict(base), "record_sha256": record_sha256}).validate()

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {**self._identity_payload(), "record_sha256": self.record_sha256}


def verify_custody_chain(events: Iterable[CustodyEvent]) -> str:
    rows = tuple(events)
    if not rows:
        raise MonitoringContractError("custody chain requires at least one event")
    previous: str | None = None
    for index, event in enumerate(rows, 1):
        if not isinstance(event, CustodyEvent):
            raise MonitoringContractError("custody chain contains invalid event type")
        event.validate()
        if event.event_index != index:
            raise MonitoringContractError("custody event_index must be contiguous")
        if event.previous_event_sha256 != previous:
            raise MonitoringContractError("custody hash chain is broken")
        previous = event.record_sha256
    return str(previous)


@dataclass(frozen=True)
class CaseAuthorization:
    case_scope_id: str
    approved_asset_refs: tuple[str, ...]
    allowed_evidence_types: tuple[str, ...]
    read_only: bool = True
    advisory_only: bool = True
    case_grants_network_access: bool = False
    case_grants_collection: bool = False
    case_grants_remediation: bool = False
    schema_version: str = FORENSIC_CASE_AUTHORIZATION_SCHEMA

    def validate(self) -> "CaseAuthorization":
        object.__setattr__(self, "case_scope_id", _identifier(self.case_scope_id, "case_scope_id", max_len=128))
        assets = _canonical_ids(self.approved_asset_refs, "approved_asset_ref", limit=MAX_CASE_ASSET_REFS)
        if not assets:
            raise MonitoringContractError("forensic case requires explicit approved_asset_refs")
        object.__setattr__(self, "approved_asset_refs", assets)
        evidence_types = tuple(str(value or "").strip() for value in self.allowed_evidence_types)
        if not evidence_types or len(evidence_types) != len(set(evidence_types)):
            raise MonitoringContractError("allowed_evidence_types must be non-empty and unique")
        if set(evidence_types) - FORENSIC_EVIDENCE_TYPES:
            raise MonitoringContractError("allowed_evidence_types contains unsupported forensic evidence type")
        object.__setattr__(self, "allowed_evidence_types", tuple(sorted(evidence_types)))
        if not self.read_only or not self.advisory_only:
            raise MonitoringContractError("forensic case authority must remain read-only and advisory")
        if self.case_grants_network_access or self.case_grants_collection or self.case_grants_remediation:
            raise MonitoringContractError("forensic case metadata cannot grant network, collection or remediation authority")
        if self.schema_version != FORENSIC_CASE_AUTHORIZATION_SCHEMA:
            raise MonitoringContractError("unsupported forensic case authorization schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        payload = asdict(self)
        payload["approved_asset_refs"] = list(self.approved_asset_refs)
        payload["allowed_evidence_types"] = list(self.allowed_evidence_types)
        return payload

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


@dataclass(frozen=True)
class CollectionFootprint:
    collector_id: str
    collected_at: str
    object_count: int
    byte_count: int
    network_read_used: bool
    active_probe_used: bool
    authority_fingerprint: str | None = None
    schema_version: str = FORENSIC_COLLECTION_FOOTPRINT_SCHEMA

    def validate(self) -> "CollectionFootprint":
        object.__setattr__(self, "collector_id", _identifier(self.collector_id, "collector_id", max_len=128))
        object.__setattr__(self, "collected_at", _timestamp(self.collected_at, "collected_at"))
        for field_name, value, maximum in (
            ("object_count", self.object_count, 1_000_000),
            ("byte_count", self.byte_count, MAX_FORENSIC_EVIDENCE_BYTES),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
                raise MonitoringContractError(f"{field_name} is outside the forensic collection bound")
        if self.active_probe_used:
            raise MonitoringContractError("P0-A forensic collection footprint does not admit active probing")
        if self.network_read_used and self.authority_fingerprint is None:
            raise MonitoringContractError("network-read collection requires an authority fingerprint")
        if self.authority_fingerprint is not None:
            object.__setattr__(self, "authority_fingerprint", _sha(self.authority_fingerprint, "authority_fingerprint"))
        if self.schema_version != FORENSIC_COLLECTION_FOOTPRINT_SCHEMA:
            raise MonitoringContractError("unsupported forensic collection footprint schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


@dataclass(frozen=True)
class CaseRecord:
    case_id: str
    status: str
    created_at: str
    updated_at: str
    authorization_fingerprint: str
    evidence_refs: tuple[EvidenceReference, ...]
    custody_head_sha256: str | None = None
    timeline_fingerprint: str | None = None
    human_review_required: bool = True
    authority: str = "advisory"
    schema_version: str = FORENSIC_CASE_SCHEMA

    def validate(self) -> "CaseRecord":
        case_id = _identifier(self.case_id, "case_id", max_len=128)
        if not case_id.startswith("case:") or len(case_id) <= len("case:"):
            raise MonitoringContractError("case_id must start with case:")
        object.__setattr__(self, "case_id", case_id)
        if self.status not in FORENSIC_CASE_STATUSES:
            raise MonitoringContractError("unsupported forensic case status")
        created = _timestamp(self.created_at, "created_at")
        updated = _timestamp(self.updated_at, "updated_at")
        if _parse_timestamp(updated, "updated_at") < _parse_timestamp(created, "created_at"):
            raise MonitoringContractError("case updated_at cannot precede created_at")
        object.__setattr__(self, "created_at", created)
        object.__setattr__(self, "updated_at", updated)
        object.__setattr__(self, "authorization_fingerprint", _sha(self.authorization_fingerprint, "authorization_fingerprint"))
        refs = tuple(ref.validate() for ref in self.evidence_refs)
        if len(refs) > MAX_CASE_EVIDENCE_REFS:
            raise MonitoringContractError("case evidence reference bound exceeded")
        if len({ref.evidence_id for ref in refs}) != len(refs):
            raise MonitoringContractError("case evidence_refs must have unique evidence_id values")
        object.__setattr__(self, "evidence_refs", tuple(sorted(refs, key=lambda ref: ref.evidence_id)))
        if self.custody_head_sha256 is not None:
            object.__setattr__(self, "custody_head_sha256", _sha(self.custody_head_sha256, "custody_head_sha256"))
        if self.timeline_fingerprint is not None:
            object.__setattr__(self, "timeline_fingerprint", _sha(self.timeline_fingerprint, "timeline_fingerprint"))
        if not self.human_review_required:
            raise MonitoringContractError("forensic cases require human review")
        if self.authority != "advisory":
            raise MonitoringContractError("forensic case authority must remain advisory")
        if self.schema_version != FORENSIC_CASE_SCHEMA:
            raise MonitoringContractError("unsupported forensic case schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "authorization_fingerprint": self.authorization_fingerprint,
            "evidence_refs": [ref.public_dict() for ref in self.evidence_refs],
            "custody_head_sha256": self.custody_head_sha256,
            "timeline_fingerprint": self.timeline_fingerprint,
            "human_review_required": self.human_review_required,
            "authority": self.authority,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())
