from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint
from .forensic_evidence import EvidenceReference

FORENSIC_HYPOTHESIS_EVIDENCE_SCHEMA = "workspace-security-forensics/hypothesis-evidence-v1"
FORENSIC_HUMAN_CONFIRMATION_SCHEMA = "workspace-security-forensics/human-confirmation-v1"
FORENSIC_HYPOTHESIS_SCHEMA = "workspace-security-forensics/hypothesis-v1"

HYPOTHESIS_OPEN = "OPEN"
HYPOTHESIS_SUPPORTED = "SUPPORTED"
HYPOTHESIS_CONTRADICTED = "CONTRADICTED"
HYPOTHESIS_INCONCLUSIVE = "INCONCLUSIVE"
HYPOTHESIS_CONFIRMED_BY_HUMAN = "CONFIRMED_BY_HUMAN"
HYPOTHESIS_STATUSES = frozenset(
    {
        HYPOTHESIS_OPEN,
        HYPOTHESIS_SUPPORTED,
        HYPOTHESIS_CONTRADICTED,
        HYPOTHESIS_INCONCLUSIVE,
        HYPOTHESIS_CONFIRMED_BY_HUMAN,
    }
)

_HYPOTHESIS_ID_RE = re.compile(r"^hypothesis:[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,116}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HUMAN_REF_RE = re.compile(r"^human:sha256:[0-9a-f]{64}$")
_REASON_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
MAX_HYPOTHESIS_EVIDENCE_REFS = 512
MAX_HYPOTHESIS_MISSING_CODES = 64


def _sha(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not _SHA256_RE.fullmatch(text):
        raise MonitoringContractError(f"{field_name} must be a SHA-256 fingerprint")
    return text


def _hypothesis_id(value: str) -> str:
    text = str(value or "").strip()
    if not _HYPOTHESIS_ID_RE.fullmatch(text):
        raise MonitoringContractError("hypothesis_id must be a compact hypothesis: identifier")
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


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _reason_codes(values: Iterable[str]) -> tuple[str, ...]:
    rows = tuple(str(value or "").strip() for value in values)
    if len(rows) > MAX_HYPOTHESIS_MISSING_CODES:
        raise MonitoringContractError("missing_evidence_codes bound exceeded")
    if len(rows) != len(set(rows)):
        raise MonitoringContractError("missing_evidence_codes must be unique")
    if any(not _REASON_RE.fullmatch(value) for value in rows):
        raise MonitoringContractError("missing_evidence_codes must be compact reason codes")
    return tuple(sorted(rows))


@dataclass(frozen=True)
class HypothesisEvidenceSet:
    supporting: tuple[EvidenceReference, ...] = ()
    contradicting: tuple[EvidenceReference, ...] = ()
    missing_evidence_codes: tuple[str, ...] = ()
    schema_version: str = FORENSIC_HYPOTHESIS_EVIDENCE_SCHEMA

    def validate(self) -> "HypothesisEvidenceSet":
        supporting = tuple(ref.validate() for ref in self.supporting)
        contradicting = tuple(ref.validate() for ref in self.contradicting)
        if len(supporting) + len(contradicting) > MAX_HYPOTHESIS_EVIDENCE_REFS:
            raise MonitoringContractError("hypothesis evidence reference bound exceeded")
        if any(ref.relation != "supports" for ref in supporting):
            raise MonitoringContractError("supporting evidence refs must use supports relation")
        if any(ref.relation != "contradicts" for ref in contradicting):
            raise MonitoringContractError("contradicting evidence refs must use contradicts relation")
        supporting_ids = [ref.evidence_id for ref in supporting]
        contradicting_ids = [ref.evidence_id for ref in contradicting]
        if len(supporting_ids) != len(set(supporting_ids)):
            raise MonitoringContractError("supporting evidence IDs must be unique")
        if len(contradicting_ids) != len(set(contradicting_ids)):
            raise MonitoringContractError("contradicting evidence IDs must be unique")
        if set(supporting_ids) & set(contradicting_ids):
            raise MonitoringContractError("one evidence object cannot both support and contradict the same hypothesis")
        object.__setattr__(self, "supporting", tuple(sorted(supporting, key=lambda ref: ref.evidence_id)))
        object.__setattr__(self, "contradicting", tuple(sorted(contradicting, key=lambda ref: ref.evidence_id)))
        object.__setattr__(self, "missing_evidence_codes", _reason_codes(self.missing_evidence_codes))
        if self.schema_version != FORENSIC_HYPOTHESIS_EVIDENCE_SCHEMA:
            raise MonitoringContractError("unsupported hypothesis evidence schema")
        return self

    @property
    def deterministic_status(self) -> str:
        self.validate()
        if self.supporting and self.contradicting:
            return HYPOTHESIS_INCONCLUSIVE
        if self.supporting:
            return HYPOTHESIS_SUPPORTED
        if self.contradicting:
            return HYPOTHESIS_CONTRADICTED
        return HYPOTHESIS_OPEN

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "supporting": [ref.public_dict() for ref in self.supporting],
            "contradicting": [ref.public_dict() for ref in self.contradicting],
            "missing_evidence_codes": list(self.missing_evidence_codes),
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


@dataclass(frozen=True)
class HumanHypothesisConfirmation:
    hypothesis_id: str
    evidence_fingerprint: str
    human_ref: str
    confirmed_at: str
    note_sha256: str | None = None
    record_sha256: str = ""
    schema_version: str = FORENSIC_HUMAN_CONFIRMATION_SCHEMA

    def _identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "hypothesis_id": self.hypothesis_id,
            "evidence_fingerprint": self.evidence_fingerprint,
            "human_ref": self.human_ref,
            "confirmed_at": self.confirmed_at,
            "note_sha256": self.note_sha256,
        }

    def validate(self) -> "HumanHypothesisConfirmation":
        object.__setattr__(self, "hypothesis_id", _hypothesis_id(self.hypothesis_id))
        object.__setattr__(self, "evidence_fingerprint", _sha(self.evidence_fingerprint, "evidence_fingerprint"))
        human_ref = str(self.human_ref or "").strip()
        if not _HUMAN_REF_RE.fullmatch(human_ref):
            raise MonitoringContractError("human confirmation requires human:sha256 typed identity")
        object.__setattr__(self, "human_ref", human_ref)
        object.__setattr__(self, "confirmed_at", _timestamp(self.confirmed_at, "confirmed_at"))
        if self.note_sha256 is not None:
            object.__setattr__(self, "note_sha256", _sha(self.note_sha256, "note_sha256"))
        if self.schema_version != FORENSIC_HUMAN_CONFIRMATION_SCHEMA:
            raise MonitoringContractError("unsupported human confirmation schema")
        expected = sha256_fingerprint(self._identity_payload())
        if self.record_sha256 != expected:
            raise MonitoringContractError("human confirmation record_sha256 does not match content")
        return self

    @classmethod
    def build(
        cls,
        *,
        hypothesis_id: str,
        evidence_fingerprint: str,
        human_ref: str,
        confirmed_at: str,
        note_sha256: str | None = None,
    ) -> "HumanHypothesisConfirmation":
        base = cls(
            hypothesis_id=_hypothesis_id(hypothesis_id),
            evidence_fingerprint=_sha(evidence_fingerprint, "evidence_fingerprint"),
            human_ref=str(human_ref or "").strip(),
            confirmed_at=_timestamp(confirmed_at, "confirmed_at"),
            note_sha256=None if note_sha256 is None else _sha(note_sha256, "note_sha256"),
        )
        if not _HUMAN_REF_RE.fullmatch(base.human_ref):
            raise MonitoringContractError("human confirmation requires human:sha256 typed identity")
        return cls(**{**asdict(base), "record_sha256": sha256_fingerprint(base._identity_payload())}).validate()

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {**self._identity_payload(), "record_sha256": self.record_sha256}


@dataclass(frozen=True)
class ForensicHypothesis:
    hypothesis_id: str
    statement_sha256: str
    created_at: str
    updated_at: str
    evidence: HypothesisEvidenceSet
    status: str
    human_confirmation: HumanHypothesisConfirmation | None = None
    human_review_required: bool = True
    authority: str = "advisory"
    schema_version: str = FORENSIC_HYPOTHESIS_SCHEMA

    def validate(self) -> "ForensicHypothesis":
        object.__setattr__(self, "hypothesis_id", _hypothesis_id(self.hypothesis_id))
        object.__setattr__(self, "statement_sha256", _sha(self.statement_sha256, "statement_sha256"))
        created = _timestamp(self.created_at, "created_at")
        updated = _timestamp(self.updated_at, "updated_at")
        if _instant(updated) < _instant(created):
            raise MonitoringContractError("hypothesis updated_at cannot precede created_at")
        object.__setattr__(self, "created_at", created)
        object.__setattr__(self, "updated_at", updated)
        if not isinstance(self.evidence, HypothesisEvidenceSet):
            raise MonitoringContractError("hypothesis evidence type is invalid")
        self.evidence.validate()
        if self.status not in HYPOTHESIS_STATUSES:
            raise MonitoringContractError("unsupported hypothesis status")
        deterministic_status = self.evidence.deterministic_status
        if self.human_confirmation is None:
            if self.status != deterministic_status:
                raise MonitoringContractError("hypothesis status must be derived from evidence")
        else:
            if not isinstance(self.human_confirmation, HumanHypothesisConfirmation):
                raise MonitoringContractError("human confirmation type is invalid")
            confirmation = self.human_confirmation.validate()
            if deterministic_status != HYPOTHESIS_SUPPORTED:
                raise MonitoringContractError("human confirmation requires a deterministically supported hypothesis")
            if self.status != HYPOTHESIS_CONFIRMED_BY_HUMAN:
                raise MonitoringContractError("human confirmation requires CONFIRMED_BY_HUMAN status")
            if confirmation.hypothesis_id != self.hypothesis_id:
                raise MonitoringContractError("human confirmation hypothesis_id mismatch")
            if confirmation.evidence_fingerprint != self.evidence.fingerprint:
                raise MonitoringContractError("human confirmation evidence fingerprint mismatch")
            if _instant(confirmation.confirmed_at) < _instant(self.created_at):
                raise MonitoringContractError("human confirmation cannot precede hypothesis creation")
            if self.updated_at != confirmation.confirmed_at:
                raise MonitoringContractError("confirmed hypothesis updated_at must equal confirmation time")
        if not self.human_review_required:
            raise MonitoringContractError("forensic hypotheses require human review")
        if self.authority != "advisory":
            raise MonitoringContractError("forensic hypothesis authority must remain advisory")
        if self.schema_version != FORENSIC_HYPOTHESIS_SCHEMA:
            raise MonitoringContractError("unsupported forensic hypothesis schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "hypothesis_id": self.hypothesis_id,
            "statement_sha256": self.statement_sha256,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "evidence": self.evidence.public_dict(),
            "status": self.status,
            "human_confirmation": (
                None if self.human_confirmation is None else self.human_confirmation.public_dict()
            ),
            "human_review_required": self.human_review_required,
            "authority": self.authority,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


def evaluate_hypothesis(
    *,
    hypothesis_id: str,
    statement_sha256: str,
    created_at: str,
    updated_at: str,
    supporting: Iterable[EvidenceReference] = (),
    contradicting: Iterable[EvidenceReference] = (),
    missing_evidence_codes: Iterable[str] = (),
) -> ForensicHypothesis:
    evidence = HypothesisEvidenceSet(
        supporting=tuple(supporting),
        contradicting=tuple(contradicting),
        missing_evidence_codes=tuple(missing_evidence_codes),
    ).validate()
    return ForensicHypothesis(
        hypothesis_id=hypothesis_id,
        statement_sha256=statement_sha256,
        created_at=created_at,
        updated_at=updated_at,
        evidence=evidence,
        status=evidence.deterministic_status,
    ).validate()


def confirm_hypothesis(
    hypothesis: ForensicHypothesis,
    confirmation: HumanHypothesisConfirmation,
) -> ForensicHypothesis:
    if not isinstance(hypothesis, ForensicHypothesis):
        raise MonitoringContractError("confirmation requires ForensicHypothesis")
    hypothesis.validate()
    if hypothesis.status != HYPOTHESIS_SUPPORTED or hypothesis.human_confirmation is not None:
        raise MonitoringContractError("only an unconfirmed SUPPORTED hypothesis can be human-confirmed")
    confirmation.validate()
    return ForensicHypothesis(
        hypothesis_id=hypothesis.hypothesis_id,
        statement_sha256=hypothesis.statement_sha256,
        created_at=hypothesis.created_at,
        updated_at=confirmation.confirmed_at,
        evidence=hypothesis.evidence,
        status=HYPOTHESIS_CONFIRMED_BY_HUMAN,
        human_confirmation=confirmation,
    ).validate()
