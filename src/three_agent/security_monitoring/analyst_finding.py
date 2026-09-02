from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Iterable

from .contracts import SEVERITIES, canonical_json, sha256_fingerprint
from .evidence_lineage import EvidenceLineageReceipt
from .normalized_evidence import EvidenceObservationWindow

ANALYST_FINDING_SCHEMA = "workspace-security-analyst-finding/v1"
RISK_CLASSIFICATIONS = frozenset(
    {"informational", "operational", "availability", "security", "integrity", "confidentiality"}
)
DEFAULT_PROHIBITED_AUTOMATIC_ACTIONS = (
    "arbitrary_shell_execution",
    "autonomous_firewall_modification",
    "active_exploitation",
    "credential_harvesting",
    "unrestricted_scanning",
    "unrestricted_pcap_capture",
    "autonomous_remediation",
    "external_data_exfiltration",
)
MAX_FINDING_STATEMENTS = 24
MAX_FINDING_EVIDENCE_REFS = 128
MAX_AFFECTED_REFS = 64
MAX_STATEMENT_LENGTH = 512
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_ID_RE = re.compile(r"^evidence:[0-9a-f]{24}$")
_FINDING_ID_RE = re.compile(r"^finding:[0-9a-f]{24}$")
_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,255}$")


class AnalystFindingError(ValueError):
    """Analyst finding is ambiguous, unbounded, or lacks validated evidence lineage."""


def _sha(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not _SHA256_RE.fullmatch(text):
        raise AnalystFindingError(f"{field_name} must be SHA-256")
    return text


def _timestamp(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AnalystFindingError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise AnalystFindingError(f"{field_name} must include timezone")
    return text


def _statement(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not text or len(text) > MAX_STATEMENT_LENGTH:
        raise AnalystFindingError(f"{field_name} must be non-empty and bounded")
    if any(ord(ch) < 32 and ch not in "\t" for ch in text):
        raise AnalystFindingError(f"{field_name} contains control characters")
    if "\n" in text or "\r" in text:
        raise AnalystFindingError(f"{field_name} must be single-line")
    return text


def _statements(values: Iterable[str], field_name: str, *, required: bool = False) -> tuple[str, ...]:
    output = tuple(_statement(value, field_name) for value in values)
    if required and not output:
        raise AnalystFindingError(f"{field_name} is required")
    if len(output) > MAX_FINDING_STATEMENTS:
        raise AnalystFindingError(f"{field_name} count exceeds bound")
    if len(set(output)) != len(output):
        raise AnalystFindingError(f"{field_name} must be unique")
    return output


def _evidence_ids(values: Iterable[str], field_name: str, *, required: bool = False) -> tuple[str, ...]:
    output = tuple(str(value or "").strip() for value in values)
    if required and not output:
        raise AnalystFindingError(f"{field_name} is required")
    if len(output) > MAX_FINDING_EVIDENCE_REFS:
        raise AnalystFindingError(f"{field_name} count exceeds bound")
    if len(set(output)) != len(output):
        raise AnalystFindingError(f"{field_name} must be unique")
    if any(not _EVIDENCE_ID_RE.fullmatch(value) for value in output):
        raise AnalystFindingError(f"{field_name} contains invalid evidence ID")
    return output


def _compact_refs(values: Iterable[str]) -> tuple[str, ...]:
    output = tuple(str(value or "").strip() for value in values)
    if not output or len(output) > MAX_AFFECTED_REFS or len(set(output)) != len(output):
        raise AnalystFindingError("affected_refs must be non-empty, unique, and bounded")
    for value in output:
        if not _COMPACT_RE.fullmatch(value) or "://" in value or ".." in value.split("/"):
            raise AnalystFindingError("affected_refs contains invalid reference")
    return output


@dataclass(frozen=True)
class AnalystFinding:
    finding_id: str
    observed_facts: tuple[str, ...]
    derived_indicators: tuple[str, ...]
    hypotheses: tuple[str, ...]
    confidence: float
    supporting_evidence_ids: tuple[str, ...]
    conflicting_evidence_ids: tuple[str, ...]
    recommended_human_actions: tuple[str, ...]
    prohibited_automatic_actions: tuple[str, ...]
    affected_refs: tuple[str, ...]
    severity: str
    risk_classification: str
    created_at: str
    observation_window: EvidenceObservationWindow
    task_ref_sha256: str
    audit_record_sha256: str
    lineage_receipt: EvidenceLineageReceipt
    schema_version: str = ANALYST_FINDING_SCHEMA

    @classmethod
    def create(
        cls,
        *,
        observed_facts: Iterable[str],
        derived_indicators: Iterable[str] = (),
        hypotheses: Iterable[str] = (),
        confidence: float,
        supporting_evidence_ids: Iterable[str],
        conflicting_evidence_ids: Iterable[str] = (),
        recommended_human_actions: Iterable[str],
        affected_refs: Iterable[str],
        severity: str,
        risk_classification: str,
        created_at: str,
        observation_window: EvidenceObservationWindow,
        task_ref_sha256: str,
        audit_record_sha256: str,
        lineage_receipt: EvidenceLineageReceipt,
    ) -> "AnalystFinding":
        provisional = cls(
            finding_id="finding:" + "0" * 24,
            observed_facts=tuple(observed_facts),
            derived_indicators=tuple(derived_indicators),
            hypotheses=tuple(hypotheses),
            confidence=confidence,
            supporting_evidence_ids=tuple(supporting_evidence_ids),
            conflicting_evidence_ids=tuple(conflicting_evidence_ids),
            recommended_human_actions=tuple(recommended_human_actions),
            prohibited_automatic_actions=DEFAULT_PROHIBITED_AUTOMATIC_ACTIONS,
            affected_refs=tuple(affected_refs),
            severity=severity,
            risk_classification=risk_classification,
            created_at=created_at,
            observation_window=observation_window,
            task_ref_sha256=task_ref_sha256,
            audit_record_sha256=audit_record_sha256,
            lineage_receipt=lineage_receipt,
        )
        provisional._validate_fields(check_id=False)
        finding_id = "finding:" + provisional.identity_sha256.split(":", 1)[1][:24]
        return cls(**{**provisional.__dict__, "finding_id": finding_id}).validate()

    def _validate_fields(self, *, check_id: bool) -> "AnalystFinding":
        if self.schema_version != ANALYST_FINDING_SCHEMA:
            raise AnalystFindingError("unsupported analyst finding schema")
        facts = _statements(self.observed_facts, "observed_facts", required=True)
        indicators = _statements(self.derived_indicators, "derived_indicators")
        hypotheses = _statements(self.hypotheses, "hypotheses")
        if set(facts) & set(hypotheses):
            raise AnalystFindingError("hypothesis must not be represented as an observed fact")
        if set(indicators) & set(hypotheses):
            raise AnalystFindingError("hypothesis must remain separate from derived indicators")
        object.__setattr__(self, "observed_facts", facts)
        object.__setattr__(self, "derived_indicators", indicators)
        object.__setattr__(self, "hypotheses", hypotheses)
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)) or not 0.0 <= float(self.confidence) <= 1.0:
            raise AnalystFindingError("confidence must be within [0,1]")
        object.__setattr__(self, "confidence", float(self.confidence))
        supporting = _evidence_ids(self.supporting_evidence_ids, "supporting_evidence_ids", required=True)
        conflicting = _evidence_ids(self.conflicting_evidence_ids, "conflicting_evidence_ids")
        if set(supporting) & set(conflicting):
            raise AnalystFindingError("supporting and conflicting evidence must be disjoint")
        object.__setattr__(self, "supporting_evidence_ids", supporting)
        object.__setattr__(self, "conflicting_evidence_ids", conflicting)
        object.__setattr__(self, "recommended_human_actions", _statements(self.recommended_human_actions, "recommended_human_actions", required=True))
        prohibited = tuple(str(value or "").strip() for value in self.prohibited_automatic_actions)
        if prohibited != DEFAULT_PROHIBITED_AUTOMATIC_ACTIONS:
            raise AnalystFindingError("prohibited automatic action boundary cannot be weakened")
        object.__setattr__(self, "affected_refs", _compact_refs(self.affected_refs))
        if self.severity not in SEVERITIES:
            raise AnalystFindingError("unsupported finding severity")
        if self.risk_classification not in RISK_CLASSIFICATIONS:
            raise AnalystFindingError("unsupported risk classification")
        object.__setattr__(self, "created_at", _timestamp(self.created_at, "created_at"))
        self.observation_window.validate()
        created_dt = datetime.fromisoformat(self.created_at.replace("Z", "+00:00"))
        window_end = datetime.fromisoformat(self.observation_window.end_at.replace("Z", "+00:00"))
        if created_dt < window_end:
            raise AnalystFindingError("created_at cannot precede observation window end")
        object.__setattr__(self, "task_ref_sha256", _sha(self.task_ref_sha256, "task_ref_sha256"))
        object.__setattr__(self, "audit_record_sha256", _sha(self.audit_record_sha256, "audit_record_sha256"))
        self.lineage_receipt.validate()
        if self.task_ref_sha256 != self.lineage_receipt.task_ref_sha256:
            raise AnalystFindingError("finding task does not match evidence lineage task")
        lineage_ids = set(self.lineage_receipt.evidence_ids)
        if not set(supporting).issubset(lineage_ids):
            raise AnalystFindingError("supporting evidence is missing from validated lineage")
        if not set(conflicting).issubset(lineage_ids):
            raise AnalystFindingError("conflicting evidence is missing from validated lineage")
        if check_id:
            if not _FINDING_ID_RE.fullmatch(str(self.finding_id or "")):
                raise AnalystFindingError("finding_id is invalid")
            expected = "finding:" + self.identity_sha256.split(":", 1)[1][:24]
            if self.finding_id != expected:
                raise AnalystFindingError("finding_id does not match canonical finding identity")
        return self

    def validate(self) -> "AnalystFinding":
        return self._validate_fields(check_id=True)

    def identity_dict(self) -> dict[str, Any]:
        self._validate_fields(check_id=False)
        return {
            "schema_version": self.schema_version,
            "observed_facts": list(self.observed_facts),
            "derived_indicators": list(self.derived_indicators),
            "hypotheses": list(self.hypotheses),
            "confidence": self.confidence,
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "conflicting_evidence_ids": list(self.conflicting_evidence_ids),
            "recommended_human_actions": list(self.recommended_human_actions),
            "prohibited_automatic_actions": list(self.prohibited_automatic_actions),
            "affected_refs": list(self.affected_refs),
            "severity": self.severity,
            "risk_classification": self.risk_classification,
            "created_at": self.created_at,
            "observation_window": asdict(self.observation_window),
            "task_ref_sha256": self.task_ref_sha256,
            "audit_record_sha256": self.audit_record_sha256,
            "lineage_receipt": self.lineage_receipt.public_dict(),
        }

    @property
    def identity_sha256(self) -> str:
        return sha256_fingerprint(self.identity_dict())

    def public_dict(self) -> dict[str, Any]:
        self.validate()
        return {"finding_id": self.finding_id, **self.identity_dict()}

    def canonical_json(self) -> str:
        return canonical_json(self.public_dict())
