from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from .contracts import APPROVED_DATA_CLASSES, canonical_json, sha256_fingerprint
from .normalized_evidence import NormalizedEvidence, NormalizedEvidenceError

DFIR_CASE_SCHEMA = "workspace-dfir-case/v1"
DFIR_CASE_AUTH_SCHEMA = "workspace-dfir-case-authorization/v1"
DFIR_TIME_SCHEMA = "workspace-dfir-time-provenance/v1"
DFIR_EVIDENCE_SCHEMA = "workspace-dfir-evidence-object/v1"
DFIR_CUSTODY_SCHEMA = "workspace-dfir-custody-event/v1"
DFIR_CUSTODY_CHAIN_SCHEMA = "workspace-dfir-custody-chain/v1"

MAX_CASE_EVIDENCE_REFS = 512
MAX_CASE_ASSET_REFS = 512
MAX_CUSTODY_EVENTS = 2048
MAX_NOTE_REF_LENGTH = 160

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CASE_ID_RE = re.compile(r"^case:[0-9a-f]{24}$")
_EVIDENCE_ID_RE = re.compile(r"^evidence:[0-9a-f]{24}$")
_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,255}$")
_CUSTODY_EVENT_TYPES = frozenset({"REGISTERED", "ACQUIRED", "TRANSFERRED", "DERIVED", "VERIFIED"})
_EVIDENCE_KINDS = frozenset({"raw", "derived"})


class DFIRCaseEvidenceError(ValueError):
    """DFIR case/evidence/custody contract is malformed or violates lineage rules."""


def _sha(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not _SHA256_RE.fullmatch(text):
        raise DFIRCaseEvidenceError(f"{field_name} must be SHA-256")
    return text


def _compact(value: str, field_name: str, *, max_len: int = 128) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or not _COMPACT_RE.fullmatch(text):
        raise DFIRCaseEvidenceError(f"{field_name} must be a bounded compact identifier")
    if "://" in text or ".." in text.split("/"):
        raise DFIRCaseEvidenceError(f"{field_name} contains an unsafe reference")
    return text


def _timestamp(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DFIRCaseEvidenceError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DFIRCaseEvidenceError(f"{field_name} must include timezone")
    return text


def _utc(value: str, field_name: str) -> str:
    parsed = datetime.fromisoformat(_timestamp(value, field_name).replace("Z", "+00:00"))
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class CaseAuthorization:
    authorization_ref_sha256: str
    task_ref_sha256: str
    approved_asset_refs: tuple[str, ...]
    allowed_sensitivities: tuple[str, ...] = ("internal", "confidential", "restricted")
    read_only: bool = True
    remediation_allowed: bool = False
    network_execution_allowed: bool = False
    schema_version: str = DFIR_CASE_AUTH_SCHEMA

    def validate(self) -> "CaseAuthorization":
        if self.schema_version != DFIR_CASE_AUTH_SCHEMA:
            raise DFIRCaseEvidenceError("unsupported case authorization schema")
        object.__setattr__(self, "authorization_ref_sha256", _sha(self.authorization_ref_sha256, "authorization_ref_sha256"))
        object.__setattr__(self, "task_ref_sha256", _sha(self.task_ref_sha256, "task_ref_sha256"))
        assets = tuple(_compact(value, "approved_asset_ref") for value in self.approved_asset_refs)
        if not assets or len(assets) > MAX_CASE_ASSET_REFS or len(set(assets)) != len(assets):
            raise DFIRCaseEvidenceError("approved assets must be non-empty, unique, and bounded")
        sensitivities = tuple(str(value or "").strip() for value in self.allowed_sensitivities)
        if not sensitivities or len(set(sensitivities)) != len(sensitivities):
            raise DFIRCaseEvidenceError("allowed sensitivities must be non-empty and unique")
        if set(sensitivities) - APPROVED_DATA_CLASSES:
            raise DFIRCaseEvidenceError("unsupported sensitivity classification")
        if self.read_only is not True or self.remediation_allowed or self.network_execution_allowed:
            raise DFIRCaseEvidenceError("DFIR case authorization cannot grant remediation or network execution")
        object.__setattr__(self, "approved_asset_refs", assets)
        object.__setattr__(self, "allowed_sensitivities", sensitivities)
        return self

    @property
    def fingerprint(self) -> str:
        self.validate()
        return sha256_fingerprint(asdict(self))


@dataclass(frozen=True)
class ForensicTimeProvenance:
    original_timestamp: str
    original_timezone: str
    clock_source: str
    clock_uncertainty_ms: int
    normalized_utc: str
    schema_version: str = DFIR_TIME_SCHEMA

    def validate(self) -> "ForensicTimeProvenance":
        if self.schema_version != DFIR_TIME_SCHEMA:
            raise DFIRCaseEvidenceError("unsupported forensic time schema")
        original = _timestamp(self.original_timestamp, "original_timestamp")
        timezone_label = _compact(self.original_timezone, "original_timezone", max_len=64)
        clock_source = _compact(self.clock_source, "clock_source", max_len=96)
        if isinstance(self.clock_uncertainty_ms, bool) or not isinstance(self.clock_uncertainty_ms, int) or not 0 <= self.clock_uncertainty_ms <= 86_400_000:
            raise DFIRCaseEvidenceError("clock_uncertainty_ms is outside the supported bound")
        normalized = _utc(self.normalized_utc, "normalized_utc")
        original_utc = _utc(original, "original_timestamp")
        if normalized != original_utc:
            raise DFIRCaseEvidenceError("normalized_utc must represent original_timestamp in UTC")
        object.__setattr__(self, "original_timestamp", original)
        object.__setattr__(self, "original_timezone", timezone_label)
        object.__setattr__(self, "clock_source", clock_source)
        object.__setattr__(self, "normalized_utc", normalized)
        return self


@dataclass(frozen=True)
class ForensicEvidenceObject:
    case_id: str
    evidence_id: str
    evidence_kind: str
    normalized_evidence_sha256: str
    content_sha256: str
    acquisition_sha256: str
    transport_sha256: str
    provenance_sha256: str
    time_provenance: ForensicTimeProvenance
    source_evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    schema_version: str = DFIR_EVIDENCE_SCHEMA

    @classmethod
    def from_normalized(
        cls,
        *,
        case_id: str,
        evidence: NormalizedEvidence,
        evidence_kind: str,
        acquisition_sha256: str,
        transport_sha256: str,
        time_provenance: ForensicTimeProvenance,
        source_evidence_ids: Iterable[str] = (),
    ) -> "ForensicEvidenceObject":
        try:
            evidence.validate()
        except NormalizedEvidenceError as exc:
            raise DFIRCaseEvidenceError(f"normalized evidence rejected: {exc}") from exc
        return cls(
            case_id=case_id,
            evidence_id=evidence.evidence_id,
            evidence_kind=evidence_kind,
            normalized_evidence_sha256=evidence.identity_sha256,
            content_sha256=evidence.integrity.content_sha256,
            acquisition_sha256=acquisition_sha256,
            transport_sha256=transport_sha256,
            provenance_sha256=sha256_fingerprint(asdict(evidence.provenance)),
            time_provenance=time_provenance,
            source_evidence_ids=tuple(source_evidence_ids),
        ).validate()

    def validate(self) -> "ForensicEvidenceObject":
        if self.schema_version != DFIR_EVIDENCE_SCHEMA:
            raise DFIRCaseEvidenceError("unsupported forensic evidence schema")
        if not _CASE_ID_RE.fullmatch(str(self.case_id or "")):
            raise DFIRCaseEvidenceError("case_id is invalid")
        if not _EVIDENCE_ID_RE.fullmatch(str(self.evidence_id or "")):
            raise DFIRCaseEvidenceError("evidence_id is invalid")
        if self.evidence_kind not in _EVIDENCE_KINDS:
            raise DFIRCaseEvidenceError("evidence_kind must be raw or derived")
        for field_name, value in (
            ("normalized_evidence_sha256", self.normalized_evidence_sha256),
            ("content_sha256", self.content_sha256),
            ("acquisition_sha256", self.acquisition_sha256),
            ("transport_sha256", self.transport_sha256),
            ("provenance_sha256", self.provenance_sha256),
        ):
            _sha(value, field_name)
        self.time_provenance.validate()
        sources = tuple(str(value or "").strip() for value in self.source_evidence_ids)
        if len(sources) > MAX_CASE_EVIDENCE_REFS or len(set(sources)) != len(sources):
            raise DFIRCaseEvidenceError("source evidence refs must be unique and bounded")
        if any(not _EVIDENCE_ID_RE.fullmatch(value) for value in sources):
            raise DFIRCaseEvidenceError("source evidence ref is invalid")
        if self.evidence_kind == "raw" and sources:
            raise DFIRCaseEvidenceError("raw evidence cannot claim derived source evidence")
        if self.evidence_kind == "derived" and not sources:
            raise DFIRCaseEvidenceError("derived evidence requires source evidence refs")
        if self.evidence_id in sources:
            raise DFIRCaseEvidenceError("evidence cannot derive from itself")
        object.__setattr__(self, "source_evidence_ids", sources)
        return self

    @property
    def fingerprint(self) -> str:
        self.validate()
        return sha256_fingerprint(self.public_dict())

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind,
            "normalized_evidence_sha256": self.normalized_evidence_sha256,
            "content_sha256": self.content_sha256,
            "acquisition_sha256": self.acquisition_sha256,
            "transport_sha256": self.transport_sha256,
            "provenance_sha256": self.provenance_sha256,
            "time_provenance": asdict(self.time_provenance),
            "source_evidence_ids": list(self.source_evidence_ids),
        }


@dataclass(frozen=True)
class CaseRecord:
    case_id: str
    title_ref: str
    created_at: str
    authorization: CaseAuthorization
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    status: str = "open"
    authority: str = "advisory"
    schema_version: str = DFIR_CASE_SCHEMA

    @classmethod
    def create(
        cls,
        *,
        title_ref: str,
        created_at: str,
        authorization: CaseAuthorization,
        evidence_ids: Iterable[str] = (),
    ) -> "CaseRecord":
        authorization.validate()
        payload = {
            "schema_version": DFIR_CASE_SCHEMA,
            "title_ref": _compact(title_ref, "title_ref", max_len=MAX_NOTE_REF_LENGTH),
            "created_at": _utc(created_at, "created_at"),
            "authorization_fingerprint": authorization.fingerprint,
        }
        case_id = "case:" + sha256_fingerprint(payload).split(":", 1)[1][:24]
        return cls(
            case_id=case_id,
            title_ref=payload["title_ref"],
            created_at=payload["created_at"],
            authorization=authorization,
            evidence_ids=tuple(evidence_ids),
        ).validate()

    def validate(self) -> "CaseRecord":
        if self.schema_version != DFIR_CASE_SCHEMA:
            raise DFIRCaseEvidenceError("unsupported DFIR case schema")
        if not _CASE_ID_RE.fullmatch(str(self.case_id or "")):
            raise DFIRCaseEvidenceError("case_id is invalid")
        object.__setattr__(self, "title_ref", _compact(self.title_ref, "title_ref", max_len=MAX_NOTE_REF_LENGTH))
        object.__setattr__(self, "created_at", _utc(self.created_at, "created_at"))
        self.authorization.validate()
        evidence = tuple(str(value or "").strip() for value in self.evidence_ids)
        if len(evidence) > MAX_CASE_EVIDENCE_REFS or len(set(evidence)) != len(evidence):
            raise DFIRCaseEvidenceError("case evidence refs must be unique and bounded")
        if any(not _EVIDENCE_ID_RE.fullmatch(value) for value in evidence):
            raise DFIRCaseEvidenceError("case contains invalid evidence ref")
        if self.status not in {"open", "closed"}:
            raise DFIRCaseEvidenceError("unsupported case status")
        if self.authority != "advisory":
            raise DFIRCaseEvidenceError("DFIR case cannot grant execution authority")
        object.__setattr__(self, "evidence_ids", evidence)
        expected = CaseRecord.create(
            title_ref=self.title_ref,
            created_at=self.created_at,
            authorization=self.authorization,
            evidence_ids=(),
        ).case_id if self.case_id != "case:" + "0" * 24 else self.case_id
        if self.case_id != expected:
            raise DFIRCaseEvidenceError("case_id does not match canonical case identity")
        return self

    def admit_evidence(self, item: ForensicEvidenceObject, normalized: NormalizedEvidence) -> "CaseRecord":
        self.validate()
        item.validate()
        try:
            normalized.validate()
        except NormalizedEvidenceError as exc:
            raise DFIRCaseEvidenceError(f"normalized evidence rejected: {exc}") from exc
        if item.case_id != self.case_id or item.evidence_id != normalized.evidence_id:
            raise DFIRCaseEvidenceError("evidence object is not linked to this case/normalized evidence")
        if item.normalized_evidence_sha256 != normalized.identity_sha256:
            raise DFIRCaseEvidenceError("normalized evidence fingerprint mismatch")
        if item.content_sha256 != normalized.integrity.content_sha256:
            raise DFIRCaseEvidenceError("content hash mismatch")
        if normalized.task_ref_sha256 != self.authorization.task_ref_sha256:
            raise DFIRCaseEvidenceError("case task authorization mismatch")
        if normalized.authorization_ref_sha256 != self.authorization.authorization_ref_sha256:
            raise DFIRCaseEvidenceError("case authorization mismatch")
        if normalized.asset_ref not in self.authorization.approved_asset_refs:
            raise DFIRCaseEvidenceError("evidence asset is outside approved case scope")
        if normalized.sensitivity not in self.authorization.allowed_sensitivities:
            raise DFIRCaseEvidenceError("evidence sensitivity is outside approved case scope")
        refs = self.evidence_ids if item.evidence_id in self.evidence_ids else (*self.evidence_ids, item.evidence_id)
        return CaseRecord(
            case_id=self.case_id,
            title_ref=self.title_ref,
            created_at=self.created_at,
            authorization=self.authorization,
            evidence_ids=refs,
            status=self.status,
            authority=self.authority,
        ).validate()


@dataclass(frozen=True)
class CustodyEvent:
    event_index: int
    case_id: str
    evidence_id: str
    event_type: str
    occurred_at: str
    actor_ref_sha256: str
    evidence_fingerprint: str
    previous_event_sha256: str | None
    note_ref: str | None = None
    event_sha256: str = ""
    schema_version: str = DFIR_CUSTODY_SCHEMA

    @classmethod
    def build(
        cls,
        *,
        event_index: int,
        case_id: str,
        evidence_id: str,
        event_type: str,
        occurred_at: str,
        actor_ref_sha256: str,
        evidence_fingerprint: str,
        previous_event_sha256: str | None,
        note_ref: str | None = None,
    ) -> "CustodyEvent":
        base = cls(
            event_index=event_index,
            case_id=case_id,
            evidence_id=evidence_id,
            event_type=event_type,
            occurred_at=_utc(occurred_at, "occurred_at"),
            actor_ref_sha256=actor_ref_sha256,
            evidence_fingerprint=evidence_fingerprint,
            previous_event_sha256=previous_event_sha256,
            note_ref=note_ref,
        )
        event_sha256 = sha256_fingerprint(base._identity_payload())
        return cls(**{**base.__dict__, "event_sha256": event_sha256}).validate()

    def _identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "event_index": self.event_index,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at,
            "actor_ref_sha256": self.actor_ref_sha256,
            "evidence_fingerprint": self.evidence_fingerprint,
            "previous_event_sha256": self.previous_event_sha256,
            "note_ref": self.note_ref,
        }

    def validate(self) -> "CustodyEvent":
        if self.schema_version != DFIR_CUSTODY_SCHEMA:
            raise DFIRCaseEvidenceError("unsupported custody event schema")
        if isinstance(self.event_index, bool) or not isinstance(self.event_index, int) or self.event_index < 1:
            raise DFIRCaseEvidenceError("custody event_index must be positive")
        if not _CASE_ID_RE.fullmatch(str(self.case_id or "")) or not _EVIDENCE_ID_RE.fullmatch(str(self.evidence_id or "")):
            raise DFIRCaseEvidenceError("custody case/evidence reference is invalid")
        if self.event_type not in _CUSTODY_EVENT_TYPES:
            raise DFIRCaseEvidenceError("unsupported custody event type")
        object.__setattr__(self, "occurred_at", _utc(self.occurred_at, "occurred_at"))
        _sha(self.actor_ref_sha256, "actor_ref_sha256")
        _sha(self.evidence_fingerprint, "evidence_fingerprint")
        if self.previous_event_sha256 is not None:
            _sha(self.previous_event_sha256, "previous_event_sha256")
        if self.note_ref is not None:
            object.__setattr__(self, "note_ref", _compact(self.note_ref, "note_ref", max_len=MAX_NOTE_REF_LENGTH))
        expected = sha256_fingerprint(self._identity_payload())
        if self.event_sha256 != expected:
            raise DFIRCaseEvidenceError("custody event hash mismatch")
        return self


@dataclass(frozen=True)
class CustodyChain:
    events: tuple[CustodyEvent, ...]
    schema_version: str = DFIR_CUSTODY_CHAIN_SCHEMA

    @classmethod
    def from_events(cls, events: Iterable[CustodyEvent]) -> "CustodyChain":
        return cls(tuple(events)).validate()

    def validate(self) -> "CustodyChain":
        if self.schema_version != DFIR_CUSTODY_CHAIN_SCHEMA:
            raise DFIRCaseEvidenceError("unsupported custody chain schema")
        if not self.events or len(self.events) > MAX_CUSTODY_EVENTS:
            raise DFIRCaseEvidenceError("custody chain must be non-empty and bounded")
        previous: CustodyEvent | None = None
        case_id = self.events[0].case_id
        evidence_id = self.events[0].evidence_id
        for expected_index, event in enumerate(self.events, start=1):
            event.validate()
            if event.event_index != expected_index:
                raise DFIRCaseEvidenceError("custody chain event index gap")
            if event.case_id != case_id or event.evidence_id != evidence_id:
                raise DFIRCaseEvidenceError("custody chain cannot cross case/evidence identities")
            expected_previous = None if previous is None else previous.event_sha256
            if event.previous_event_sha256 != expected_previous:
                raise DFIRCaseEvidenceError("custody chain previous hash mismatch")
            if previous is not None and event.occurred_at < previous.occurred_at:
                raise DFIRCaseEvidenceError("custody event time cannot move backwards")
            previous = event
        return self

    @property
    def fingerprint(self) -> str:
        self.validate()
        return sha256_fingerprint(
            {
                "schema_version": self.schema_version,
                "event_sha256": [event.event_sha256 for event in self.events],
            }
        )

    def canonical_json(self) -> str:
        self.validate()
        return canonical_json(
            {
                "schema_version": self.schema_version,
                "events": [{**event._identity_payload(), "event_sha256": event.event_sha256} for event in self.events],
            }
        )
