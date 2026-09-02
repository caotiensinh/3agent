from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from .contracts import APPROVED_DATA_CLASSES, MonitoringContractError, sha256_fingerprint
from .forensic_evidence import CaseRecord, EvidenceObject, EvidenceReference, FORENSIC_EVIDENCE_TYPES
from .forensic_hypothesis import ForensicHypothesis, HYPOTHESIS_STATUSES

FORENSIC_REPORT_SCHEMA = "workspace-security-forensics/case-report-v1"
FORENSIC_REPORT_EVIDENCE_ENTRY_SCHEMA = "workspace-security-forensics/report-evidence-entry-v1"
FORENSIC_REPORT_HYPOTHESIS_SCHEMA = "workspace-security-forensics/report-hypothesis-summary-v1"

_REPORT_ID_RE = re.compile(r"^forensic-report:[0-9a-f]{24}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REASON_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
MAX_REPORT_EVIDENCE = 10_000
MAX_REPORT_HYPOTHESES = 1024
MAX_REPORT_LIMITATIONS = 128

_DATA_CLASS_RANK = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
    "secret": 4,
}


def _sha(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not _SHA256_RE.fullmatch(text):
        raise MonitoringContractError(f"{field_name} must be a SHA-256 fingerprint")
    return text


def _timestamp(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MonitoringContractError(f"{field_name} must include timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _reason_codes(values: Iterable[str]) -> tuple[str, ...]:
    rows = tuple(str(value or "").strip() for value in values)
    if len(rows) > MAX_REPORT_LIMITATIONS:
        raise MonitoringContractError("forensic report limitation bound exceeded")
    if len(rows) != len(set(rows)):
        raise MonitoringContractError("forensic report limitation codes must be unique")
    if any(not _REASON_RE.fullmatch(value) for value in rows):
        raise MonitoringContractError("forensic report limitation codes must be compact reason codes")
    return tuple(sorted(rows))


@dataclass(frozen=True, order=True)
class ForensicReportEvidenceEntry:
    evidence_id: str
    evidence_type: str
    content_sha256: str
    data_class: str
    provenance_fingerprint: str
    producer_id: str
    producer_version: str
    event_time_fingerprint: str | None
    derived: bool
    schema_version: str = FORENSIC_REPORT_EVIDENCE_ENTRY_SCHEMA

    @classmethod
    def from_evidence(cls, evidence: EvidenceObject) -> "ForensicReportEvidenceEntry":
        evidence.validate()
        return cls(
            evidence_id=evidence.evidence_id,
            evidence_type=evidence.evidence_type,
            content_sha256=evidence.content_sha256,
            data_class=evidence.data_class,
            provenance_fingerprint=evidence.provenance.fingerprint,
            producer_id=evidence.provenance.producer_id,
            producer_version=evidence.provenance.producer_version,
            event_time_fingerprint=None if evidence.event_time is None else evidence.event_time.fingerprint,
            derived=evidence.derived,
        ).validate()

    def validate(self) -> "ForensicReportEvidenceEntry":
        if not self.evidence_id.startswith("evidence:"):
            raise MonitoringContractError("forensic report evidence_id is invalid")
        if self.evidence_type not in FORENSIC_EVIDENCE_TYPES:
            raise MonitoringContractError("forensic report evidence_type is invalid")
        object.__setattr__(self, "content_sha256", _sha(self.content_sha256, "content_sha256"))
        object.__setattr__(self, "provenance_fingerprint", _sha(self.provenance_fingerprint, "provenance_fingerprint"))
        if self.event_time_fingerprint is not None:
            object.__setattr__(self, "event_time_fingerprint", _sha(self.event_time_fingerprint, "event_time_fingerprint"))
        if self.data_class not in APPROVED_DATA_CLASSES:
            raise MonitoringContractError("forensic report evidence data_class is invalid")
        if not self.producer_id or "://" in self.producer_id or "\\" in self.producer_id:
            raise MonitoringContractError("forensic report producer_id is invalid")
        if not self.producer_version or "://" in self.producer_version or "\\" in self.producer_version:
            raise MonitoringContractError("forensic report producer_version is invalid")
        if self.schema_version != FORENSIC_REPORT_EVIDENCE_ENTRY_SCHEMA:
            raise MonitoringContractError("unsupported forensic report evidence-entry schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "content_sha256": self.content_sha256,
            "data_class": self.data_class,
            "provenance_fingerprint": self.provenance_fingerprint,
            "producer_id": self.producer_id,
            "producer_version": self.producer_version,
            "event_time_fingerprint": self.event_time_fingerprint,
            "derived": self.derived,
        }


@dataclass(frozen=True, order=True)
class ForensicReportHypothesisSummary:
    hypothesis_id: str
    statement_sha256: str
    status: str
    supporting: tuple[EvidenceReference, ...]
    contradicting: tuple[EvidenceReference, ...]
    missing_evidence_codes: tuple[str, ...]
    human_confirmation_sha256: str | None
    schema_version: str = FORENSIC_REPORT_HYPOTHESIS_SCHEMA

    @classmethod
    def from_hypothesis(cls, hypothesis: ForensicHypothesis) -> "ForensicReportHypothesisSummary":
        hypothesis.validate()
        return cls(
            hypothesis_id=hypothesis.hypothesis_id,
            statement_sha256=hypothesis.statement_sha256,
            status=hypothesis.status,
            supporting=hypothesis.evidence.supporting,
            contradicting=hypothesis.evidence.contradicting,
            missing_evidence_codes=hypothesis.evidence.missing_evidence_codes,
            human_confirmation_sha256=(None if hypothesis.human_confirmation is None else hypothesis.human_confirmation.record_sha256),
        ).validate()

    def validate(self) -> "ForensicReportHypothesisSummary":
        if not self.hypothesis_id.startswith("hypothesis:"):
            raise MonitoringContractError("forensic report hypothesis_id is invalid")
        object.__setattr__(self, "statement_sha256", _sha(self.statement_sha256, "statement_sha256"))
        if self.status not in HYPOTHESIS_STATUSES:
            raise MonitoringContractError("forensic report hypothesis status is invalid")
        supporting = tuple(ref.validate() for ref in self.supporting)
        contradicting = tuple(ref.validate() for ref in self.contradicting)
        if any(ref.relation != "supports" for ref in supporting):
            raise MonitoringContractError("report supporting evidence relation is invalid")
        if any(ref.relation != "contradicts" for ref in contradicting):
            raise MonitoringContractError("report contradicting evidence relation is invalid")
        object.__setattr__(self, "supporting", tuple(sorted(supporting, key=lambda ref: ref.evidence_id)))
        object.__setattr__(self, "contradicting", tuple(sorted(contradicting, key=lambda ref: ref.evidence_id)))
        object.__setattr__(self, "missing_evidence_codes", _reason_codes(self.missing_evidence_codes))
        if self.human_confirmation_sha256 is not None:
            object.__setattr__(self, "human_confirmation_sha256", _sha(self.human_confirmation_sha256, "human_confirmation_sha256"))
        if self.schema_version != FORENSIC_REPORT_HYPOTHESIS_SCHEMA:
            raise MonitoringContractError("unsupported forensic report hypothesis schema")
        return self

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        self.validate()
        return tuple(sorted({ref.evidence_id for ref in (*self.supporting, *self.contradicting)}))

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "hypothesis_id": self.hypothesis_id,
            "statement_sha256": self.statement_sha256,
            "status": self.status,
            "supporting": [ref.public_dict() for ref in self.supporting],
            "contradicting": [ref.public_dict() for ref in self.contradicting],
            "missing_evidence_codes": list(self.missing_evidence_codes),
            "human_confirmation_sha256": self.human_confirmation_sha256,
        }


@dataclass(frozen=True)
class ForensicCaseReport:
    report_id: str
    case_id: str
    generated_at: str
    case_fingerprint: str
    authorization_fingerprint: str
    custody_head_sha256: str | None
    timeline_fingerprint: str | None
    data_class: str
    evidence_manifest: tuple[ForensicReportEvidenceEntry, ...]
    hypotheses: tuple[ForensicReportHypothesisSummary, ...]
    limitation_codes: tuple[str, ...]
    human_review_required: bool = True
    authority: str = "advisory"
    narrative_embedded: bool = False
    raw_payload_embedded: bool = False
    schema_version: str = FORENSIC_REPORT_SCHEMA

    def _identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "generated_at": self.generated_at,
            "case_fingerprint": self.case_fingerprint,
            "authorization_fingerprint": self.authorization_fingerprint,
            "custody_head_sha256": self.custody_head_sha256,
            "timeline_fingerprint": self.timeline_fingerprint,
            "data_class": self.data_class,
            "evidence_manifest": [item.public_dict() for item in self.evidence_manifest],
            "hypotheses": [item.public_dict() for item in self.hypotheses],
            "limitation_codes": list(self.limitation_codes),
            "human_review_required": self.human_review_required,
            "authority": self.authority,
            "narrative_embedded": self.narrative_embedded,
            "raw_payload_embedded": self.raw_payload_embedded,
        }

    def validate(self) -> "ForensicCaseReport":
        if not _REPORT_ID_RE.fullmatch(str(self.report_id or "")):
            raise MonitoringContractError("forensic report_id is invalid")
        if not self.case_id.startswith("case:"):
            raise MonitoringContractError("forensic report case_id is invalid")
        object.__setattr__(self, "generated_at", _timestamp(self.generated_at, "generated_at"))
        object.__setattr__(self, "case_fingerprint", _sha(self.case_fingerprint, "case_fingerprint"))
        object.__setattr__(self, "authorization_fingerprint", _sha(self.authorization_fingerprint, "authorization_fingerprint"))
        if self.custody_head_sha256 is not None:
            object.__setattr__(self, "custody_head_sha256", _sha(self.custody_head_sha256, "custody_head_sha256"))
        if self.timeline_fingerprint is not None:
            object.__setattr__(self, "timeline_fingerprint", _sha(self.timeline_fingerprint, "timeline_fingerprint"))
        if self.data_class not in APPROVED_DATA_CLASSES:
            raise MonitoringContractError("forensic report data_class is invalid")
        evidence = tuple(item.validate() for item in self.evidence_manifest)
        if not evidence or len(evidence) > MAX_REPORT_EVIDENCE:
            raise MonitoringContractError("forensic report requires bounded evidence manifest")
        if len({item.evidence_id for item in evidence}) != len(evidence):
            raise MonitoringContractError("forensic report evidence IDs must be unique")
        object.__setattr__(self, "evidence_manifest", tuple(sorted(evidence, key=lambda item: item.evidence_id)))
        hypotheses = tuple(item.validate() for item in self.hypotheses)
        if len(hypotheses) > MAX_REPORT_HYPOTHESES:
            raise MonitoringContractError("forensic report hypothesis bound exceeded")
        if len({item.hypothesis_id for item in hypotheses}) != len(hypotheses):
            raise MonitoringContractError("forensic report hypothesis IDs must be unique")
        object.__setattr__(self, "hypotheses", tuple(sorted(hypotheses, key=lambda item: item.hypothesis_id)))
        manifest_ids = {item.evidence_id for item in self.evidence_manifest}
        if any(not set(item.evidence_ids) <= manifest_ids for item in self.hypotheses):
            raise MonitoringContractError("forensic report hypothesis references evidence outside case manifest")
        object.__setattr__(self, "limitation_codes", _reason_codes(self.limitation_codes))
        if not self.human_review_required:
            raise MonitoringContractError("forensic case reports require human review")
        if self.authority != "advisory":
            raise MonitoringContractError("forensic case report must remain advisory")
        if self.narrative_embedded or self.raw_payload_embedded:
            raise MonitoringContractError("forensic core report must remain metadata-only")
        if self.schema_version != FORENSIC_REPORT_SCHEMA:
            raise MonitoringContractError("unsupported forensic report schema")
        expected_id = "forensic-report:" + sha256_fingerprint(self._identity_payload()).split(":", 1)[1][:24]
        if self.report_id != expected_id:
            raise MonitoringContractError("forensic report_id does not match report identity")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {"report_id": self.report_id, **self._identity_payload()}

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


def build_forensic_case_report(
    case: CaseRecord,
    evidence: Iterable[EvidenceObject],
    hypotheses: Iterable[ForensicHypothesis],
    *,
    generated_at: str,
    limitation_codes: Iterable[str] = (),
) -> ForensicCaseReport:
    if not isinstance(case, CaseRecord):
        raise MonitoringContractError("forensic report requires CaseRecord")
    case.validate()
    by_id: dict[str, EvidenceObject] = {}
    for raw in tuple(evidence):
        if not isinstance(raw, EvidenceObject):
            raise MonitoringContractError("forensic report evidence type is invalid")
        item = raw.validate()
        if item.evidence_id in by_id:
            raise MonitoringContractError("forensic report evidence IDs must be unique")
        by_id[item.evidence_id] = item
    case_refs = {ref.evidence_id: ref for ref in case.evidence_refs}
    if set(by_id) != set(case_refs):
        raise MonitoringContractError("forensic report evidence must exactly match case evidence refs")
    for evidence_id, item in by_id.items():
        if item.content_sha256 != case_refs[evidence_id].content_sha256:
            raise MonitoringContractError("forensic report case evidence content hash mismatch")
    if case.timeline_fingerprint is not None:
        timeline_matches = [item for item in by_id.values() if item.evidence_type == "timeline" and item.content_sha256 == case.timeline_fingerprint]
        if len(timeline_matches) != 1:
            raise MonitoringContractError("forensic report requires exactly one case-bound timeline evidence object")
    summaries = tuple(ForensicReportHypothesisSummary.from_hypothesis(item) for item in tuple(hypotheses))
    manifest_ids = set(by_id)
    if any(not set(summary.evidence_ids) <= manifest_ids for summary in summaries):
        raise MonitoringContractError("forensic hypothesis evidence is outside case scope")
    missing_codes = {code for summary in summaries for code in summary.missing_evidence_codes}
    combined_limitations = _reason_codes(set(tuple(limitation_codes)) | missing_codes)
    if not by_id:
        raise MonitoringContractError("forensic report requires case evidence")
    data_class = max((item.data_class for item in by_id.values()), key=lambda value: _DATA_CLASS_RANK[value])
    manifest = tuple(sorted((ForensicReportEvidenceEntry.from_evidence(item) for item in by_id.values()), key=lambda item: item.evidence_id))
    generated = _timestamp(generated_at, "generated_at")
    provisional = ForensicCaseReport(
        report_id="forensic-report:" + "0" * 24,
        case_id=case.case_id,
        generated_at=generated,
        case_fingerprint=case.fingerprint,
        authorization_fingerprint=case.authorization_fingerprint,
        custody_head_sha256=case.custody_head_sha256,
        timeline_fingerprint=case.timeline_fingerprint,
        data_class=data_class,
        evidence_manifest=manifest,
        hypotheses=summaries,
        limitation_codes=combined_limitations,
    )
    report_id = "forensic-report:" + sha256_fingerprint(provisional._identity_payload()).split(":", 1)[1][:24]
    return ForensicCaseReport(
        report_id=report_id,
        case_id=provisional.case_id,
        generated_at=provisional.generated_at,
        case_fingerprint=provisional.case_fingerprint,
        authorization_fingerprint=provisional.authorization_fingerprint,
        custody_head_sha256=provisional.custody_head_sha256,
        timeline_fingerprint=provisional.timeline_fingerprint,
        data_class=provisional.data_class,
        evidence_manifest=provisional.evidence_manifest,
        hypotheses=provisional.hypotheses,
        limitation_codes=provisional.limitation_codes,
    ).validate()
