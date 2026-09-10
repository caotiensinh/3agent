from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint

RCA_QUORUM_SCHEMA = "workspace-security-monitoring/rca-evidence-quorum-v1"
MAX_SIGNALS = 128
_EVIDENCE_ID_RE = re.compile(r"^evidence:[0-9a-f]{24}$")
_QUORUM_ID_RE = re.compile(r"^rca-quorum:[0-9a-f]{24}$")
_ALLOWED_STANCES = frozenset({"supports", "contradicts"})


def _compact(value: str, field: str, max_len: int = 96) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or any(ch.isspace() for ch in text) or "://" in text:
        raise MonitoringContractError(f"{field} must be a bounded compact identifier")
    return text


def _threshold(value: int, field: str, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= upper:
        raise MonitoringContractError(f"{field} is out of bounds")
    return value


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

    def public_dict(self) -> dict[str, str]:
        self.validate()
        return {
            "evidence_id": self.evidence_id,
            "evidence_class": self.evidence_class,
            "stance": self.stance,
        }


def _derive(
    signals: tuple[RcaEvidenceSignal, ...],
    *,
    min_supporting_evidence: int,
    min_distinct_classes: int,
) -> tuple[str, int, int, int]:
    support = tuple(item for item in signals if item.stance == "supports")
    contradict = tuple(item for item in signals if item.stance == "contradicts")
    classes = len({item.evidence_class for item in support})
    if contradict:
        status = "contradicted"
    elif len(support) >= min_supporting_evidence and classes >= min_distinct_classes:
        status = "supported"
    else:
        status = "insufficient_evidence"
    return status, len(support), len(contradict), classes


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
    authority: str = "advisory"
    schema_version: str = RCA_QUORUM_SCHEMA

    @classmethod
    def evaluate(
        cls,
        *,
        hypothesis_ref: str,
        signals: Iterable[RcaEvidenceSignal],
        min_supporting_evidence: int = 2,
        min_distinct_classes: int = 2,
    ) -> "RcaEvidenceQuorum":
        hypothesis = _compact(hypothesis_ref, "hypothesis_ref", 160)
        min_support = _threshold(min_supporting_evidence, "min_supporting_evidence", 32)
        min_classes = _threshold(min_distinct_classes, "min_distinct_classes", 16)
        rows = tuple(sorted((item.validate() for item in signals), key=lambda item: item.evidence_id))
        if not rows or len(rows) > MAX_SIGNALS:
            raise MonitoringContractError("RCA evidence signal bound violated")
        ids = tuple(item.evidence_id for item in rows)
        if len(set(ids)) != len(ids):
            raise MonitoringContractError("RCA evidence IDs must be unique")
        status, supporting_count, contradicting_count, distinct_classes = _derive(
            rows,
            min_supporting_evidence=min_support,
            min_distinct_classes=min_classes,
        )
        provisional = cls(
            hypothesis_ref=hypothesis,
            min_supporting_evidence=min_support,
            min_distinct_classes=min_classes,
            signals=rows,
            status=status,
            supporting_count=supporting_count,
            contradicting_count=contradicting_count,
            distinct_supporting_classes=distinct_classes,
            quorum_id="rca-quorum:" + "0" * 24,
        )
        quorum_id = "rca-quorum:" + sha256_fingerprint(provisional._identity_payload()).split(":", 1)[1][:24]
        return cls(
            hypothesis_ref=hypothesis,
            min_supporting_evidence=min_support,
            min_distinct_classes=min_classes,
            signals=rows,
            status=status,
            supporting_count=supporting_count,
            contradicting_count=contradicting_count,
            distinct_supporting_classes=distinct_classes,
            quorum_id=quorum_id,
        ).validate()

    def _identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "hypothesis_ref": self.hypothesis_ref,
            "min_supporting_evidence": self.min_supporting_evidence,
            "min_distinct_classes": self.min_distinct_classes,
            "signals": [item.public_dict() for item in self.signals],
            "status": self.status,
            "supporting_count": self.supporting_count,
            "contradicting_count": self.contradicting_count,
            "distinct_supporting_classes": self.distinct_supporting_classes,
            "authority": self.authority,
        }

    def validate(self) -> "RcaEvidenceQuorum":
        if self.schema_version != RCA_QUORUM_SCHEMA:
            raise MonitoringContractError("unsupported RCA evidence quorum schema")
        if self.authority != "advisory":
            raise MonitoringContractError("RCA evidence quorum must remain advisory")
        object.__setattr__(self, "hypothesis_ref", _compact(self.hypothesis_ref, "hypothesis_ref", 160))
        min_support = _threshold(self.min_supporting_evidence, "min_supporting_evidence", 32)
        min_classes = _threshold(self.min_distinct_classes, "min_distinct_classes", 16)
        rows = tuple(sorted((item.validate() for item in self.signals), key=lambda item: item.evidence_id))
        if not rows or len(rows) > MAX_SIGNALS:
            raise MonitoringContractError("RCA evidence signal bound violated")
        ids = tuple(item.evidence_id for item in rows)
        if len(set(ids)) != len(ids):
            raise MonitoringContractError("RCA evidence IDs must be unique")
        object.__setattr__(self, "signals", rows)

        expected_status, support_count, contradict_count, distinct_classes = _derive(
            rows,
            min_supporting_evidence=min_support,
            min_distinct_classes=min_classes,
        )
        if self.status != expected_status:
            raise MonitoringContractError("RCA quorum status does not match evidence")
        if self.supporting_count != support_count:
            raise MonitoringContractError("supporting_count does not match evidence")
        if self.contradicting_count != contradict_count:
            raise MonitoringContractError("contradicting_count does not match evidence")
        if self.distinct_supporting_classes != distinct_classes:
            raise MonitoringContractError("distinct_supporting_classes does not match evidence")
        if not _QUORUM_ID_RE.fullmatch(str(self.quorum_id or "")):
            raise MonitoringContractError("quorum_id is invalid")
        expected_id = "rca-quorum:" + sha256_fingerprint(self._identity_payload()).split(":", 1)[1][:24]
        if self.quorum_id != expected_id:
            raise MonitoringContractError("quorum_id does not match quorum content")
        return self

    @property
    def confirmed(self) -> bool:
        self.validate()
        return self.status == "supported"

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {"quorum_id": self.quorum_id, **self._identity_payload()}
