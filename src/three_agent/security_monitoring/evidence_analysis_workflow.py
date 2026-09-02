from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from .analyst_finding import AnalystFinding, RISK_CLASSIFICATIONS
from .contracts import SEVERITIES, sha256_fingerprint
from .evidence_analysis_audit import EvidenceAnalysisAuditJournal, EvidenceAnalysisAuditRecord
from .evidence_lineage import EvidenceLineageGate, EvidenceLineageReceipt
from .normalized_evidence import EvidenceObservationWindow, NormalizedEvidenceBatch
from .workflow_audit import SecurityWorkflowAuditError, SecurityWorkflowAuditJournal

HUMAN_ANALYST_RECOMMENDATION_SCHEMA = "workspace-security-human-analyst-recommendation/v1"
AUDITED_EVIDENCE_ANALYSIS_RESULT_SCHEMA = "workspace-security-audited-evidence-analysis-result/v1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_FINDING_ID_RE = re.compile(r"^finding:[0-9a-f]{24}$")


class AuditedEvidenceAnalysisError(ValueError):
    """Normalized evidence cannot safely advance through the audited analyst pipeline."""


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _batch_window(batch: NormalizedEvidenceBatch) -> EvidenceObservationWindow:
    batch.validate()
    starts = [_parse_time(row.observation_window.start_at) for row in batch.evidence]
    ends = [_parse_time(row.observation_window.end_at) for row in batch.evidence]
    return EvidenceObservationWindow(start_at=_format_time(min(starts)), end_at=_format_time(max(ends))).validate()


@dataclass(frozen=True)
class HumanAnalystRecommendation:
    finding_id: str
    finding_audit_record_sha256: str
    recommended_human_actions: tuple[str, ...]
    severity: str
    risk_classification: str
    affected_refs: tuple[str, ...]
    authority: str = "advisory"
    automatic_action_allowed: bool = False
    schema_version: str = HUMAN_ANALYST_RECOMMENDATION_SCHEMA

    @classmethod
    def from_finding(cls, finding: AnalystFinding, audit_record: EvidenceAnalysisAuditRecord) -> "HumanAnalystRecommendation":
        finding.validate()
        audit_record.validate()
        if audit_record.finding_sha256 != finding.identity_sha256:
            raise AuditedEvidenceAnalysisError("finding audit record does not match finding")
        return cls(finding_id=finding.finding_id, finding_audit_record_sha256=audit_record.record_sha256, recommended_human_actions=finding.recommended_human_actions, severity=finding.severity, risk_classification=finding.risk_classification, affected_refs=finding.affected_refs).validate()

    def validate(self) -> "HumanAnalystRecommendation":
        if self.schema_version != HUMAN_ANALYST_RECOMMENDATION_SCHEMA:
            raise AuditedEvidenceAnalysisError("unsupported human recommendation schema")
        if not _FINDING_ID_RE.fullmatch(str(self.finding_id or "")):
            raise AuditedEvidenceAnalysisError("human recommendation finding_id is invalid")
        if not _SHA256_RE.fullmatch(str(self.finding_audit_record_sha256 or "")):
            raise AuditedEvidenceAnalysisError("human recommendation audit reference is invalid")
        if not self.recommended_human_actions or len(self.recommended_human_actions) > 24:
            raise AuditedEvidenceAnalysisError("human recommendation requires bounded human actions")
        if len(set(self.recommended_human_actions)) != len(self.recommended_human_actions):
            raise AuditedEvidenceAnalysisError("human recommendation actions must be unique")
        if any(not str(value or "").strip() or len(str(value).strip()) > 512 for value in self.recommended_human_actions):
            raise AuditedEvidenceAnalysisError("human recommendation action is invalid")
        if self.severity not in SEVERITIES:
            raise AuditedEvidenceAnalysisError("human recommendation severity is invalid")
        if self.risk_classification not in RISK_CLASSIFICATIONS:
            raise AuditedEvidenceAnalysisError("human recommendation risk classification is invalid")
        if not self.affected_refs or len(self.affected_refs) > 64 or len(set(self.affected_refs)) != len(self.affected_refs):
            raise AuditedEvidenceAnalysisError("human recommendation affected refs are invalid")
        if not isinstance(self.automatic_action_allowed, bool):
            raise AuditedEvidenceAnalysisError("human recommendation automatic_action_allowed must be boolean")
        if self.authority != "advisory" or self.automatic_action_allowed:
            raise AuditedEvidenceAnalysisError("human recommendation cannot grant automatic action authority")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {"schema_version": self.schema_version, "finding_id": self.finding_id, "finding_audit_record_sha256": self.finding_audit_record_sha256, "recommended_human_actions": list(self.recommended_human_actions), "severity": self.severity, "risk_classification": self.risk_classification, "affected_refs": list(self.affected_refs), "authority": self.authority, "automatic_action_allowed": self.automatic_action_allowed}


@dataclass(frozen=True)
class AuditedEvidenceAnalysisResult:
    lineage_receipt: EvidenceLineageReceipt
    finding: AnalystFinding
    audit_record: EvidenceAnalysisAuditRecord
    recommendation: HumanAnalystRecommendation
    schema_version: str = AUDITED_EVIDENCE_ANALYSIS_RESULT_SCHEMA

    def validate(self) -> "AuditedEvidenceAnalysisResult":
        if self.schema_version != AUDITED_EVIDENCE_ANALYSIS_RESULT_SCHEMA:
            raise AuditedEvidenceAnalysisError("unsupported audited evidence analysis result schema")
        self.lineage_receipt.validate()
        self.finding.validate()
        self.audit_record.validate()
        self.recommendation.validate()
        if self.finding.lineage_receipt.public_dict() != self.lineage_receipt.public_dict():
            raise AuditedEvidenceAnalysisError("result finding lineage does not match gate receipt")
        if self.audit_record.finding_sha256 != self.finding.identity_sha256:
            raise AuditedEvidenceAnalysisError("result audit record does not match finding")
        if self.audit_record.task_ref_sha256 != self.lineage_receipt.task_ref_sha256:
            raise AuditedEvidenceAnalysisError("result audit task does not match validated lineage")
        if self.audit_record.workflow_audit_anchor_sha256 != self.finding.audit_record_sha256:
            raise AuditedEvidenceAnalysisError("result audit anchor does not match finding")
        if self.audit_record.evidence_batch_sha256 != self.lineage_receipt.evidence_batch_fingerprint:
            raise AuditedEvidenceAnalysisError("result audit batch does not match validated lineage")
        if self.audit_record.lineage_receipt_sha256 != sha256_fingerprint(self.lineage_receipt.public_dict()):
            raise AuditedEvidenceAnalysisError("result audit receipt hash does not match validated lineage")
        if self.recommendation.finding_audit_record_sha256 != self.audit_record.record_sha256:
            raise AuditedEvidenceAnalysisError("result recommendation is not linked to finding audit")
        if self.recommendation.finding_id != self.finding.finding_id:
            raise AuditedEvidenceAnalysisError("result recommendation finding_id does not match finding")
        if self.recommendation.recommended_human_actions != self.finding.recommended_human_actions:
            raise AuditedEvidenceAnalysisError("result recommendation actions do not match finding")
        if self.recommendation.severity != self.finding.severity:
            raise AuditedEvidenceAnalysisError("result recommendation severity does not match finding")
        if self.recommendation.risk_classification != self.finding.risk_classification:
            raise AuditedEvidenceAnalysisError("result recommendation risk does not match finding")
        if self.recommendation.affected_refs != self.finding.affected_refs:
            raise AuditedEvidenceAnalysisError("result recommendation affected refs do not match finding")
        return self


class AuditedEvidenceAnalysisWorkflow:
    """Read-only evidence -> lineage gate -> finding -> audit -> human recommendation.

    This coordinator has no execution/remediation API. The only outward action is a
    human-facing advisory recommendation derived from a validated AnalystFinding.
    """

    def __init__(self, *, lineage_gate: EvidenceLineageGate, workflow_audit_journal: SecurityWorkflowAuditJournal, finding_audit_journal: EvidenceAnalysisAuditJournal) -> None:
        if not isinstance(lineage_gate, EvidenceLineageGate):
            raise AuditedEvidenceAnalysisError("workflow requires EvidenceLineageGate")
        if not isinstance(workflow_audit_journal, SecurityWorkflowAuditJournal):
            raise AuditedEvidenceAnalysisError("workflow requires SecurityWorkflowAuditJournal")
        if not isinstance(finding_audit_journal, EvidenceAnalysisAuditJournal):
            raise AuditedEvidenceAnalysisError("workflow requires EvidenceAnalysisAuditJournal")
        self.lineage_gate = lineage_gate
        self.workflow_audit_journal = workflow_audit_journal
        self.finding_audit_journal = finding_audit_journal

    def _validated_workflow_anchor(self) -> str:
        try:
            verification = self.workflow_audit_journal.verify()
        except SecurityWorkflowAuditError as exc:
            raise AuditedEvidenceAnalysisError(f"existing workflow audit rejected: {exc}") from exc
        if verification.record_count < 1 or verification.last_record_sha256 is None:
            raise AuditedEvidenceAnalysisError("existing workflow audit must contain a validated record")
        if verification.last_record_sha256 != self.finding_audit_journal.anchor_record_sha256:
            raise AuditedEvidenceAnalysisError("finding audit anchor does not match current workflow audit")
        return verification.last_record_sha256

    def analyze(self, *, batch: NormalizedEvidenceBatch, observed_facts: Iterable[str], derived_indicators: Iterable[str] = (), hypotheses: Iterable[str] = (), confidence: float, supporting_evidence_ids: Iterable[str], conflicting_evidence_ids: Iterable[str] = (), recommended_human_actions: Iterable[str], affected_refs: Iterable[str], severity: str, risk_classification: str, created_at: str) -> AuditedEvidenceAnalysisResult:
        workflow_anchor = self._validated_workflow_anchor()
        lineage_receipt = self.lineage_gate.validate_batch(batch)
        finding = AnalystFinding.create(observed_facts=observed_facts, derived_indicators=derived_indicators, hypotheses=hypotheses, confidence=confidence, supporting_evidence_ids=supporting_evidence_ids, conflicting_evidence_ids=conflicting_evidence_ids, recommended_human_actions=recommended_human_actions, affected_refs=affected_refs, severity=severity, risk_classification=risk_classification, created_at=created_at, observation_window=_batch_window(batch), task_ref_sha256=lineage_receipt.task_ref_sha256, audit_record_sha256=workflow_anchor, lineage_receipt=lineage_receipt)
        audit_record = self.finding_audit_journal.append(finding=finding, batch=batch, lineage_receipt=lineage_receipt, occurred_at=created_at)
        recommendation = HumanAnalystRecommendation.from_finding(finding, audit_record)
        return AuditedEvidenceAnalysisResult(lineage_receipt=lineage_receipt, finding=finding, audit_record=audit_record, recommendation=recommendation).validate()
