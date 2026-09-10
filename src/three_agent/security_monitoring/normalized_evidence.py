from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Iterable

from .contracts import APPROVED_DATA_CLASSES, canonical_json, sha256_fingerprint

NORMALIZED_EVIDENCE_SCHEMA = "workspace-security-normalized-evidence/v1"
NORMALIZED_EVIDENCE_BATCH_SCHEMA = "workspace-security-normalized-evidence-batch/v1"
SUPPORTED_EVIDENCE_TYPES = frozenset(
    {
        "snmp_observation",
        "log_event",
        "pcap_summary",
        "dns_event",
        "network_flow",
        "authentication_event",
        "process_event",
        "correlation_result",
    }
)
MAX_METADATA_ITEMS = 24
MAX_PROVENANCE_REFS = 16
MAX_QUALITY_FLAGS = 16
MAX_BATCH_EVIDENCE = 256
MAX_STRING_LENGTH = 256

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_ID_RE = re.compile(r"^evidence:[0-9a-f]{24}$")
_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,255}$")
_METADATA_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")


class NormalizedEvidenceError(ValueError):
    """Normalized evidence is malformed, oversized, ambiguous, or has invalid lineage."""


def _compact(value: str, field_name: str, *, max_len: int = MAX_STRING_LENGTH) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or not _COMPACT_RE.fullmatch(text):
        raise NormalizedEvidenceError(f"{field_name} must be a bounded compact identifier")
    if "://" in text or ".." in text.split("/"):
        raise NormalizedEvidenceError(f"{field_name} must not contain a URL or path traversal")
    return text


def _sha256(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not _SHA256_RE.fullmatch(text):
        raise NormalizedEvidenceError(f"{field_name} must be SHA-256")
    return text


def _timestamp(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NormalizedEvidenceError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise NormalizedEvidenceError(f"{field_name} must include timezone")
    return text


def _confidence(value: float, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise NormalizedEvidenceError(f"{field_name} must be numeric")
    number = float(value)
    if not 0.0 <= number <= 1.0:
        raise NormalizedEvidenceError(f"{field_name} must be within [0,1]")
    return number


@dataclass(frozen=True)
class EvidenceObservationWindow:
    start_at: str
    end_at: str

    def validate(self) -> "EvidenceObservationWindow":
        start = _timestamp(self.start_at, "observation_window.start_at")
        end = _timestamp(self.end_at, "observation_window.end_at")
        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
        if end_dt < start_dt:
            raise NormalizedEvidenceError("observation window end precedes start")
        object.__setattr__(self, "start_at", start)
        object.__setattr__(self, "end_at", end)
        return self


@dataclass(frozen=True)
class EvidenceIntegrity:
    content_sha256: str
    source_record_sha256: str

    def validate(self) -> "EvidenceIntegrity":
        object.__setattr__(self, "content_sha256", _sha256(self.content_sha256, "content_sha256"))
        object.__setattr__(self, "source_record_sha256", _sha256(self.source_record_sha256, "source_record_sha256"))
        return self


@dataclass(frozen=True)
class EvidenceQuality:
    confidence: float
    completeness: float
    flags: tuple[str, ...] = field(default_factory=tuple)

    def validate(self) -> "EvidenceQuality":
        object.__setattr__(self, "confidence", _confidence(self.confidence, "quality.confidence"))
        object.__setattr__(self, "completeness", _confidence(self.completeness, "quality.completeness"))
        flags = tuple(_compact(value, "quality.flag", max_len=64) for value in self.flags)
        if len(flags) > MAX_QUALITY_FLAGS:
            raise NormalizedEvidenceError("too many quality flags")
        if len(set(flags)) != len(flags):
            raise NormalizedEvidenceError("quality flags must be unique")
        object.__setattr__(self, "flags", flags)
        return self


@dataclass(frozen=True)
class EvidenceProvenance:
    producer: str
    parser_version: str
    lineage_refs: tuple[str, ...]

    def validate(self) -> "EvidenceProvenance":
        object.__setattr__(self, "producer", _compact(self.producer, "provenance.producer", max_len=96))
        object.__setattr__(self, "parser_version", _compact(self.parser_version, "provenance.parser_version", max_len=96))
        refs = tuple(_sha256(value, "provenance.lineage_ref") for value in self.lineage_refs)
        if not refs:
            raise NormalizedEvidenceError("provenance lineage is required")
        if len(refs) > MAX_PROVENANCE_REFS:
            raise NormalizedEvidenceError("too many provenance lineage references")
        if len(set(refs)) != len(refs):
            raise NormalizedEvidenceError("provenance lineage references must be unique")
        object.__setattr__(self, "lineage_refs", refs)
        return self


@dataclass(frozen=True)
class EvidenceMetadataItem:
    key: str
    value_ref: str

    def validate(self) -> "EvidenceMetadataItem":
        key = str(self.key or "").strip()
        if not _METADATA_KEY_RE.fullmatch(key):
            raise NormalizedEvidenceError("metadata key is invalid")
        object.__setattr__(self, "key", key)
        object.__setattr__(self, "value_ref", _compact(self.value_ref, "metadata.value_ref", max_len=128))
        return self


@dataclass(frozen=True)
class NormalizedEvidence:
    evidence_id: str
    evidence_type: str
    source_type: str
    asset_ref: str
    task_ref_sha256: str
    authorization_ref_sha256: str
    collected_at: str
    observation_window: EvidenceObservationWindow
    integrity: EvidenceIntegrity
    sensitivity: str
    quality: EvidenceQuality
    raw_ref: str
    provenance: EvidenceProvenance
    metadata: tuple[EvidenceMetadataItem, ...] = field(default_factory=tuple)
    schema_version: str = NORMALIZED_EVIDENCE_SCHEMA

    @classmethod
    def create(
        cls,
        *,
        evidence_type: str,
        source_type: str,
        asset_ref: str,
        task_ref_sha256: str,
        authorization_ref_sha256: str,
        collected_at: str,
        observation_window: EvidenceObservationWindow,
        integrity: EvidenceIntegrity,
        sensitivity: str,
        quality: EvidenceQuality,
        raw_ref: str,
        provenance: EvidenceProvenance,
        metadata: Iterable[EvidenceMetadataItem] = (),
    ) -> "NormalizedEvidence":
        provisional = cls(
            evidence_id="evidence:" + "0" * 24,
            evidence_type=evidence_type,
            source_type=source_type,
            asset_ref=asset_ref,
            task_ref_sha256=task_ref_sha256,
            authorization_ref_sha256=authorization_ref_sha256,
            collected_at=collected_at,
            observation_window=observation_window,
            integrity=integrity,
            sensitivity=sensitivity,
            quality=quality,
            raw_ref=raw_ref,
            provenance=provenance,
            metadata=tuple(metadata),
        )
        provisional._validate_fields(check_id=False)
        evidence_id = "evidence:" + provisional.identity_sha256.split(":", 1)[1][:24]
        result = cls(**{**provisional.__dict__, "evidence_id": evidence_id})
        return result.validate()

    def _validate_fields(self, *, check_id: bool) -> "NormalizedEvidence":
        if self.schema_version != NORMALIZED_EVIDENCE_SCHEMA:
            raise NormalizedEvidenceError("unsupported normalized evidence schema")
        if self.evidence_type not in SUPPORTED_EVIDENCE_TYPES:
            raise NormalizedEvidenceError("unsupported evidence_type")
        object.__setattr__(self, "source_type", _compact(self.source_type, "source_type", max_len=64))
        object.__setattr__(self, "asset_ref", _compact(self.asset_ref, "asset_ref", max_len=128))
        object.__setattr__(self, "task_ref_sha256", _sha256(self.task_ref_sha256, "task_ref_sha256"))
        object.__setattr__(self, "authorization_ref_sha256", _sha256(self.authorization_ref_sha256, "authorization_ref_sha256"))
        object.__setattr__(self, "collected_at", _timestamp(self.collected_at, "collected_at"))
        self.observation_window.validate()
        collected_dt = datetime.fromisoformat(self.collected_at.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(self.observation_window.end_at.replace("Z", "+00:00"))
        if collected_dt < end_dt:
            raise NormalizedEvidenceError("collected_at cannot precede observation window end")
        self.integrity.validate()
        if self.sensitivity not in APPROVED_DATA_CLASSES:
            raise NormalizedEvidenceError("unsupported sensitivity classification")
        self.quality.validate()
        object.__setattr__(self, "raw_ref", _compact(self.raw_ref, "raw_ref", max_len=192))
        self.provenance.validate()
        metadata = tuple(item.validate() for item in self.metadata)
        if len(metadata) > MAX_METADATA_ITEMS:
            raise NormalizedEvidenceError("too many metadata items")
        keys = tuple(item.key for item in metadata)
        if len(set(keys)) != len(keys):
            raise NormalizedEvidenceError("metadata keys must be unique")
        object.__setattr__(self, "metadata", metadata)
        if check_id:
            if not _EVIDENCE_ID_RE.fullmatch(str(self.evidence_id or "")):
                raise NormalizedEvidenceError("evidence_id is invalid")
            expected = "evidence:" + self.identity_sha256.split(":", 1)[1][:24]
            if self.evidence_id != expected:
                raise NormalizedEvidenceError("evidence_id does not match canonical evidence identity")
        return self

    def validate(self) -> "NormalizedEvidence":
        return self._validate_fields(check_id=True)

    def identity_dict(self) -> dict[str, Any]:
        self._validate_fields(check_id=False)
        return {
            "schema_version": self.schema_version,
            "evidence_type": self.evidence_type,
            "source_type": self.source_type,
            "asset_ref": self.asset_ref,
            "task_ref_sha256": self.task_ref_sha256,
            "authorization_ref_sha256": self.authorization_ref_sha256,
            "collected_at": self.collected_at,
            "observation_window": asdict(self.observation_window),
            "integrity": asdict(self.integrity),
            "sensitivity": self.sensitivity,
            "quality": {"confidence": self.quality.confidence, "completeness": self.quality.completeness, "flags": list(self.quality.flags)},
            "raw_ref": self.raw_ref,
            "provenance": {"producer": self.provenance.producer, "parser_version": self.provenance.parser_version, "lineage_refs": list(self.provenance.lineage_refs)},
            "metadata": [asdict(item) for item in self.metadata],
        }

    @property
    def identity_sha256(self) -> str:
        return sha256_fingerprint(self.identity_dict())

    def public_dict(self) -> dict[str, Any]:
        self.validate()
        return {"evidence_id": self.evidence_id, **self.identity_dict()}

    def canonical_json(self) -> str:
        return canonical_json(self.public_dict())


@dataclass(frozen=True)
class NormalizedEvidenceBatch:
    evidence: tuple[NormalizedEvidence, ...]
    schema_version: str = NORMALIZED_EVIDENCE_BATCH_SCHEMA

    @classmethod
    def from_evidence(cls, rows: Iterable[NormalizedEvidence]) -> "NormalizedEvidenceBatch":
        ordered: list[NormalizedEvidence] = []
        by_id: dict[str, str] = {}
        for row in rows:
            row.validate()
            canonical = row.canonical_json()
            existing = by_id.get(row.evidence_id)
            if existing is None:
                by_id[row.evidence_id] = canonical
                ordered.append(row)
            elif existing != canonical:
                raise NormalizedEvidenceError("duplicate evidence_id has conflicting canonical content")
        return cls(tuple(ordered)).validate()

    def validate(self) -> "NormalizedEvidenceBatch":
        if self.schema_version != NORMALIZED_EVIDENCE_BATCH_SCHEMA:
            raise NormalizedEvidenceError("unsupported normalized evidence batch schema")
        if not self.evidence:
            raise NormalizedEvidenceError("normalized evidence batch cannot be empty")
        if len(self.evidence) > MAX_BATCH_EVIDENCE:
            raise NormalizedEvidenceError("normalized evidence batch bound exceeded")
        seen: set[str] = set()
        for row in self.evidence:
            row.validate()
            if row.evidence_id in seen:
                raise NormalizedEvidenceError("normalized evidence batch contains duplicate IDs")
            seen.add(row.evidence_id)
        return self

    @property
    def fingerprint(self) -> str:
        self.validate()
        return sha256_fingerprint(
            {
                "schema_version": self.schema_version,
                "evidence": [row.public_dict() for row in self.evidence],
            }
        )
