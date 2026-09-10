from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint

RCA_UNCERTAINTY_SCHEMA = "workspace-security-monitoring/rca-uncertainty-v1"
MAX_GAPS = 64
MAX_CONTRADICTIONS = 64
_EVIDENCE_ID_RE = re.compile(r"^evidence:[0-9a-f]{24}$")


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
    def assess(cls, *, hypothesis_ref: str, gaps: Iterable[RcaDataGap] = (),
               contradictions: Iterable[RcaContradiction] = ()) -> "RcaUncertaintyAssessment":
        hypothesis = _compact(hypothesis_ref, "hypothesis_ref")
        gap_rows = tuple(sorted((row.validate() for row in gaps), key=lambda row: (row.evidence_class, row.reason_code)))
        contradiction_rows = tuple(sorted((row.validate() for row in contradictions), key=lambda row: (row.dimension, row.supporting_evidence_id, row.contradicting_evidence_id)))
        if len(gap_rows) > MAX_GAPS or len(contradiction_rows) > MAX_CONTRADICTIONS:
            raise MonitoringContractError("RCA uncertainty bound exceeded")
        if len(set(gap_rows)) != len(gap_rows) or len(set(contradiction_rows)) != len(contradiction_rows):
            raise MonitoringContractError("RCA uncertainty rows must be unique")
        if contradiction_rows:
            status = "contradicted"
        elif gap_rows:
            status = "data_gap"
        else:
            status = "clear"
        identity = {
            "schema_version": RCA_UNCERTAINTY_SCHEMA,
            "hypothesis_ref": hypothesis,
            "gaps": [row.__dict__ for row in gap_rows],
            "contradictions": [row.__dict__ for row in contradiction_rows],
            "status": status,
            "authority": "advisory",
        }
        assessment_id = "rca-uncertainty:" + sha256_fingerprint(identity).split(":", 1)[1][:24]
        return cls(hypothesis, gap_rows, contradiction_rows, status, assessment_id)

    @property
    def can_claim_confirmed_root_cause(self) -> bool:
        return self.status == "clear"
