from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint

RCA_QUORUM_SCHEMA = "workspace-security-monitoring/rca-evidence-quorum-v1"
MAX_SIGNALS = 128
_EVIDENCE_ID_RE = re.compile(r"^evidence:[0-9a-f]{24}$")
_ALLOWED_STANCES = frozenset({"supports", "contradicts"})


def _compact(value: str, field: str, max_len: int = 96) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or any(ch.isspace() for ch in text) or "://" in text:
        raise MonitoringContractError(f"{field} must be a bounded compact identifier")
    return text


@dataclass(frozen=True)
class RcaEvidenceSignal:
    evidence_id: str
    evidence_class: str
    stance: str

    def validate(self) -> "RcaEvidenceSignal":
        if not _EVIDENCE_ID_RE.fullmatch(str(self.evidence_id or "")):
            raise MonitoringContractError("evidence_id must reference canonical evidence")
        object.__setattr__(self, "evidence_class", _compact(self.evidence_class, "evidence_class"))
        stance = str(self.stance or "").strip()
        if stance not in _ALLOWED_STANCES:
            raise MonitoringContractError("unsupported RCA evidence stance")
        object.__setattr__(self, "stance", stance)
        return self


@dataclass(frozen=True)
class RcaEvidenceQuorum:
    hypothesis_ref: str
    min_supporting_evidence: int
    min_distinct_classes: int
    signals: tuple[RcaEvidenceSignal, ...]
    status: str
    supporting_count: int
    contradicting_count: int
    distinct_supporting_classes: int
    quorum_id: str
    schema_version: str = RCA_QUORUM_SCHEMA

    @classmethod
    def evaluate(cls, *, hypothesis_ref: str, signals: Iterable[RcaEvidenceSignal],
                 min_supporting_evidence: int = 2, min_distinct_classes: int = 2) -> "RcaEvidenceQuorum":
        hypothesis = _compact(hypothesis_ref, "hypothesis_ref", 160)
        if isinstance(min_supporting_evidence, bool) or not 1 <= int(min_supporting_evidence) <= 32:
            raise MonitoringContractError("min_supporting_evidence is out of bounds")
        if isinstance(min_distinct_classes, bool) or not 1 <= int(min_distinct_classes) <= 16:
            raise MonitoringContractError("min_distinct_classes is out of bounds")
        rows = tuple(item.validate() for item in signals)
        if not rows or len(rows) > MAX_SIGNALS:
            raise MonitoringContractError("RCA evidence signal bound violated")
        ids = tuple(item.evidence_id for item in rows)
        if len(set(ids)) != len(ids):
            raise MonitoringContractError("RCA evidence IDs must be unique")
        support = tuple(item for item in rows if item.stance == "supports")
        contradict = tuple(item for item in rows if item.stance == "contradicts")
        classes = len({item.evidence_class for item in support})
        if contradict:
            status = "contradicted"
        elif len(support) >= int(min_supporting_evidence) and classes >= int(min_distinct_classes):
            status = "supported"
        else:
            status = "insufficient_evidence"
        identity = {
            "schema_version": RCA_QUORUM_SCHEMA,
            "hypothesis_ref": hypothesis,
            "min_supporting_evidence": int(min_supporting_evidence),
            "min_distinct_classes": int(min_distinct_classes),
            "signals": [item.__dict__ for item in sorted(rows, key=lambda item: item.evidence_id)],
            "status": status,
        }
        quorum_id = "rca-quorum:" + sha256_fingerprint(identity).split(":", 1)[1][:24]
        return cls(hypothesis, int(min_supporting_evidence), int(min_distinct_classes), rows,
                   status, len(support), len(contradict), classes, quorum_id)

    @property
    def confirmed(self) -> bool:
        return self.status == "supported"
