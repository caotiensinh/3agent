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
_SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CASE_RE = re.compile(r"^case:[0-9a-f]{24}$")
_EVIDENCE_RE = re.compile(r"^evidence:[0-9a-f]{24}$")
_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,255}$")
_CUSTODY_TYPES = frozenset({"REGISTERED", "ACQUIRED", "TRANSFERRED", "DERIVED", "VERIFIED"})


class DFIRCaseEvidenceError(ValueError):
    """Case, evidence, time provenance, or custody lineage is invalid."""


def _sha(value: str, name: str) -> str:
    text = str(value or "").strip()
    if not _SHA_RE.fullmatch(text):
        raise DFIRCaseEvidenceError(f"{name} must be SHA-256")
    return text


def _compact(value: str, name: str, limit: int = 128) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit or not _COMPACT_RE.fullmatch(text):
        raise DFIRCaseEvidenceError(f"{name} must be a bounded compact identifier")
    if "://" in text or ".." in text.split("/"):
        raise DFIRCaseEvidenceError(f"{name} contains an unsafe reference")
    return text


def _aware(value: str, name: str) -> datetime:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DFIRCaseEvidenceError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DFIRCaseEvidenceError(f"{name} must include timezone")
    return parsed


def _utc(value: str, name: str) -> str:
    return _aware(value, name).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


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
        if not sensitivities or len(set(sensitivities)) != len(sensitivities) or set(sensitivities) - set(APPROVED_DATA_CLASSES):
            raise DFIRCaseEvidenceError("allowed sensitivities are invalid")
        if self.read_only is not True or self.remediation_allowed or self.network_execution_allowed:
            raise DFIRCaseEvidenceError("DFIR case authorization cannot grant execution/remediation")
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
        original = str(self.original_timestamp or "").strip()
        _aware(original, "original_timestamp")
        object.__setattr__(self, "original_timezone", _compact(self.original_timezone, "original_timezone", 64))
        object.__setattr__(self, "clock_source", _compact(self.clock_source, "clock_source", 96))
        if isinstance(self.clock_uncertainty_ms, bool) or not isinstance(self.clock_uncertainty_ms, int) or not 0 <= self.clock_uncertainty_ms <= 86_400_000:
            raise DFIRCaseEvidenceError("clock_uncertainty_ms is outside the supported bound")
        normalized = _utc(self.normalized_utc, "normalized_utc")
        if normalized != _utc(original, "original_timestamp"):
            raise DFIRCaseEvidenceError("normalized_utc must represent original_timestamp in UTC")
        object.__setattr__(self, "original_timestamp", original)
        object.__setattr__(self, "normalized_utc", normalized)
        return self


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

    @staticmethod
    def _identity(title_ref: str, created_at: str, authorization: CaseAuthorization) -> dict[str, str]:
        authorization.validate()
        return {
            "schema_version": DFIR_CASE_SCHEMA,
            "title_ref": _compact(title_ref, "title_ref", 160),
            "created_at": _utc(created_at, "created_at"),
            "authorization_fingerprint": authorization.fingerprint,
        }

    @classmethod
    def create(cls, *, title_ref: str, created_at: str, authorization: CaseAuthorization) -> "CaseRecord":
        identity = cls._identity(title_ref, created_at, authorization)
        case_id = "case:" + sha256_fingerprint(identity).split(":", 1)[1][:24]
        return cls(case_id, identity["title_ref"], identity["created_at"], authorization).validate()

    def validate(self) -> "CaseRecord":
        if self.schema_version != DFIR_CASE_SCHEMA or not _CASE_RE.fullmatch(str(self.case_id or "")):
            raise DFIRCaseEvidenceError("case schema or case_id is invalid")
        identity = self._identity(self.title_ref, self.created_at, self.authorization)
        expected = "case:" + sha256_fingerprint(identity).split(":", 1)[1][:24]
        if self.case_id != expected:
            raise DFIRCaseEvidenceError("case_id does not match canonical case identity")
        evidence = tuple(str(value or "").strip() for value in self.evidence_ids)
        if len(evidence) > MAX_CASE_EVIDENCE_REFS or len(set(evidence)) != len(evidence) or any(not _EVIDENCE_RE.fullmatch(value) for value in evidence):
            raise DFIRCaseEvidenceError("case evidence refs are invalid")
        if self.status not in {"open", "closed"} or self.authority != "advisory":
            raise DFIRCaseEvidenceError("case status/authority is invalid")
        object.__setattr__(self, "title_ref", identity["title_ref"])
        object.__setattr__(self, "created_at", identity["created_at"])
        object.__setattr__(self, "evidence_ids", evidence)
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
        if self.schema_version != DFIR_EVIDENCE_SCHEMA or not _CASE_RE.fullmatch(str(self.case_id or "")) or not _EVIDENCE_RE.fullmatch(str(self.evidence_id or "")):
            raise DFIRCaseEvidenceError("forensic evidence identity is invalid")
        if self.evidence_kind not in {"raw", "derived"}:
            raise DFIRCaseEvidenceError("evidence_kind must be raw or derived")
        for name in ("normalized_evidence_sha256", "content_sha256", "acquisition_sha256", "transport_sha256", "provenance_sha256"):
            _sha(getattr(self, name), name)
        self.time_provenance.validate()
        sources = tuple(str(value or "").strip() for value in self.source_evidence_ids)
        if len(sources) > MAX_CASE_EVIDENCE_REFS or len(set(sources)) != len(sources) or any(not _EVIDENCE_RE.fullmatch(value) for value in sources):
            raise DFIRCaseEvidenceError("source evidence refs are invalid")
        if self.evidence_kind == "raw" and sources:
            raise DFIRCaseEvidenceError("raw evidence cannot have source evidence")
        if self.evidence_kind == "derived" and not sources:
            raise DFIRCaseEvidenceError("derived evidence requires source evidence")
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


def admit_case_evidence(case: CaseRecord, item: ForensicEvidenceObject, normalized: NormalizedEvidence) -> CaseRecord:
    case.validate()
    item.validate()
    try:
        normalized.validate()
    except NormalizedEvidenceError as exc:
        raise DFIRCaseEvidenceError(f"normalized evidence rejected: {exc}") from exc
    if item.case_id != case.case_id or item.evidence_id != normalized.evidence_id:
        raise DFIRCaseEvidenceError("case/evidence linkage mismatch")
    if item.normalized_evidence_sha256 != normalized.identity_sha256 or item.content_sha256 != normalized.integrity.content_sha256:
        raise DFIRCaseEvidenceError("evidence hash mismatch")
    auth = case.authorization
    if normalized.task_ref_sha256 != auth.task_ref_sha256 or normalized.authorization_ref_sha256 != auth.authorization_ref_sha256:
        raise DFIRCaseEvidenceError("case authorization lineage mismatch")
    if normalized.asset_ref not in auth.approved_asset_refs or normalized.sensitivity not in auth.allowed_sensitivities:
        raise DFIRCaseEvidenceError("evidence is outside approved case scope")
    refs = case.evidence_ids if item.evidence_id in case.evidence_ids else (*case.evidence_ids, item.evidence_id)
    return CaseRecord(case.case_id, case.title_ref, case.created_at, auth, refs, case.status, case.authority).validate()


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

    def _identity(self) -> dict[str, object]:
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

    @classmethod
    def build(cls, *, event_index: int, case_id: str, evidence_id: str, event_type: str, occurred_at: str, actor_ref_sha256: str, evidence_fingerprint: str, previous_event_sha256: str | None, note_ref: str | None = None) -> "CustodyEvent":
        base = cls(event_index, case_id, evidence_id, event_type, _utc(occurred_at, "occurred_at"), actor_ref_sha256, evidence_fingerprint, previous_event_sha256, note_ref)
        return cls(**{**base.__dict__, "event_sha256": sha256_fingerprint(base._identity())}).validate()

    def validate(self) -> "CustodyEvent":
        if self.schema_version != DFIR_CUSTODY_SCHEMA or isinstance(self.event_index, bool) or not isinstance(self.event_index, int) or self.event_index < 1:
            raise DFIRCaseEvidenceError("custody event schema/index is invalid")
        if not _CASE_RE.fullmatch(str(self.case_id or "")) or not _EVIDENCE_RE.fullmatch(str(self.evidence_id or "")) or self.event_type not in _CUSTODY_TYPES:
            raise DFIRCaseEvidenceError("custody identity/type is invalid")
        object.__setattr__(self, "occurred_at", _utc(self.occurred_at, "occurred_at"))
        _sha(self.actor_ref_sha256, "actor_ref_sha256")
        _sha(self.evidence_fingerprint, "evidence_fingerprint")
        if self.previous_event_sha256 is not None:
            _sha(self.previous_event_sha256, "previous_event_sha256")
        if self.note_ref is not None:
            object.__setattr__(self, "note_ref", _compact(self.note_ref, "note_ref", 160))
        if self.event_sha256 != sha256_fingerprint(self._identity()):
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
        if self.schema_version != DFIR_CUSTODY_CHAIN_SCHEMA or not self.events or len(self.events) > MAX_CUSTODY_EVENTS:
            raise DFIRCaseEvidenceError("custody chain must be non-empty and bounded")
        first = self.events[0]
        previous: CustodyEvent | None = None
        for expected_index, event in enumerate(self.events, start=1):
            expected_hash = None if previous is None else previous.event_sha256
            if event.previous_event_sha256 != expected_hash:
                raise DFIRCaseEvidenceError("custody previous hash mismatch")
            event.validate()
            if event.event_index != expected_index or event.case_id != first.case_id or event.evidence_id != first.evidence_id:
                raise DFIRCaseEvidenceError("custody chain identity/index mismatch")
            if previous is not None and event.occurred_at < previous.occurred_at:
                raise DFIRCaseEvidenceError("custody time cannot move backwards")
            previous = event
        return self

    @property
    def fingerprint(self) -> str:
        self.validate()
        return sha256_fingerprint({"schema_version": self.schema_version, "events": [event.event_sha256 for event in self.events]})

    def canonical_json(self) -> str:
        self.validate()
        return canonical_json({"schema_version": self.schema_version, "events": [{**event._identity(), "event_sha256": event.event_sha256} for event in self.events]})
