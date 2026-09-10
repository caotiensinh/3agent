from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint

RCA_UNCERTAINTY_SCHEMA = "workspace-security-monitoring/rca-uncertainty-v1"
MAX_GAPS = 64
MAX_CONTRADICTIONS = 64
_EVIDENCE_ID_RE = re.compile(r"^evidence:[0-9a-f]{24}$")
_ASSESSMENT_ID_RE = re.compile(r"^rca-uncertainty:[0-9a-f]{24}$")


def _compact(value: str, field: str, max_len: int = 160) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or "://" in text:
        raise MonitoringContractError(f"{field} must be a bounded identifier")
    return text


@dataclass(frozen=True)
class RcaDataGap:
    evidence_class: str
    reason_code: str

    def validate(self) -> "RcaDataGap":
        object.__setattr__(self, "evidence_class", _compact(self.evidence_class, "evidence_class", 96))
        object.__setattr__(self, "reason_code", _compact(self.reason_code, "reason_code", 96))
        return self

    def public_dict(self) -> dict[str, str]:
        self.validate()
        return {
            "evidence_class": self.evidence_class,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True)
class RcaContradiction:
    supporting_evidence_id: str
    contradicting_evidence_id: str
    dimension: str

    def validate(self) -> "RcaContradiction":
        if not _EVIDENCE_ID_RE.fullmatch(str(self.supporting_evidence_id or "")):
            raise MonitoringContractError("supporting_evidence_id must be canonical evidence")
        if not _EVIDENCE_ID_RE.fullmatch(str(self.contradicting_evidence_id or "")):
            raise MonitoringContractError("contradicting_evidence_id must be canonical evidence")
        if self.supporting_evidence_id == self.contradicting_evidence_id:
            raise MonitoringContractError("contradiction requires two distinct evidence IDs")
        object.__setattr__(self, "dimension", _compact(self.dimension, "dimension", 96))
        return self

    def public_dict(self) -> dict[str, str]:
        self.validate()
        return {
            "supporting_evidence_id": self.supporting_evidence_id,
            "contradicting_evidence_id": self.contradicting_evidence_id,
            "dimension": self.dimension,
        }


def _derive_status(
    gaps: tuple[RcaDataGap, ...],
    contradictions: tuple[RcaContradiction, ...],
) -> str:
    if contradictions:
        return "contradicted"
    if gaps:
        return "data_gap"
    return "clear"


@dataclass(frozen=True)
class RcaUncertaintyAssessment:
    hypothesis_ref: str
    gaps: tuple[RcaDataGap, ...]
    contradictions: tuple[RcaContradiction, ...]
    status: str
    assessment_id: str
    authority: str = "advisory"
    schema_version: str = RCA_UNCERTAINTY_SCHEMA

    @classmethod
    def assess(
        cls,
        *,
        hypothesis_ref: str,
        gaps: Iterable[RcaDataGap] = (),
        contradictions: Iterable[RcaContradiction] = (),
    ) -> "RcaUncertaintyAssessment":
        hypothesis = _compact(hypothesis_ref, "hypothesis_ref")
        gap_rows = tuple(
            sorted(
                (row.validate() for row in gaps),
                key=lambda row: (row.evidence_class, row.reason_code),
            )
        )
        contradiction_rows = tuple(
            sorted(
                (row.validate() for row in contradictions),
                key=lambda row: (
                    row.dimension,
                    row.supporting_evidence_id,
                    row.contradicting_evidence_id,
                ),
            )
        )
        if len(gap_rows) > MAX_GAPS or len(contradiction_rows) > MAX_CONTRADICTIONS:
            raise MonitoringContractError("RCA uncertainty bound exceeded")
        if len(set(gap_rows)) != len(gap_rows) or len(set(contradiction_rows)) != len(contradiction_rows):
            raise MonitoringContractError("RCA uncertainty rows must be unique")
        status = _derive_status(gap_rows, contradiction_rows)
        provisional = cls(
            hypothesis_ref=hypothesis,
            gaps=gap_rows,
            contradictions=contradiction_rows,
            status=status,
            assessment_id="rca-uncertainty:" + "0" * 24,
        )
        assessment_id = "rca-uncertainty:" + sha256_fingerprint(
            provisional._identity_payload()
        ).split(":", 1)[1][:24]
        return cls(
            hypothesis_ref=hypothesis,
            gaps=gap_rows,
            contradictions=contradiction_rows,
            status=status,
            assessment_id=assessment_id,
        ).validate()

    def _identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "hypothesis_ref": self.hypothesis_ref,
            "gaps": [row.public_dict() for row in self.gaps],
            "contradictions": [row.public_dict() for row in self.contradictions],
            "status": self.status,
            "authority": self.authority,
        }

    def validate(self) -> "RcaUncertaintyAssessment":
        if self.schema_version != RCA_UNCERTAINTY_SCHEMA:
            raise MonitoringContractError("unsupported RCA uncertainty schema")
        if self.authority != "advisory":
            raise MonitoringContractError("RCA uncertainty assessment must remain advisory")
        object.__setattr__(self, "hypothesis_ref", _compact(self.hypothesis_ref, "hypothesis_ref"))
        gap_rows = tuple(
            sorted(
                (row.validate() for row in self.gaps),
                key=lambda row: (row.evidence_class, row.reason_code),
            )
        )
        contradiction_rows = tuple(
            sorted(
                (row.validate() for row in self.contradictions),
                key=lambda row: (
                    row.dimension,
                    row.supporting_evidence_id,
                    row.contradicting_evidence_id,
                ),
            )
        )
        if len(gap_rows) > MAX_GAPS or len(contradiction_rows) > MAX_CONTRADICTIONS:
            raise MonitoringContractError("RCA uncertainty bound exceeded")
        if len(set(gap_rows)) != len(gap_rows) or len(set(contradiction_rows)) != len(contradiction_rows):
            raise MonitoringContractError("RCA uncertainty rows must be unique")
        object.__setattr__(self, "gaps", gap_rows)
        object.__setattr__(self, "contradictions", contradiction_rows)

        expected_status = _derive_status(gap_rows, contradiction_rows)
        if self.status != expected_status:
            raise MonitoringContractError("RCA uncertainty status does not match evidence state")
        if not _ASSESSMENT_ID_RE.fullmatch(str(self.assessment_id or "")):
            raise MonitoringContractError("assessment_id is invalid")
        expected_id = "rca-uncertainty:" + sha256_fingerprint(self._identity_payload()).split(":", 1)[1][:24]
        if self.assessment_id != expected_id:
            raise MonitoringContractError("assessment_id does not match assessment content")
        return self

    @property
    def can_claim_confirmed_root_cause(self) -> bool:
        self.validate()
        return self.status == "clear"

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "assessment_id": self.assessment_id,
            **self._identity_payload(),
        }
