import inspect
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from three_agent.security_monitoring.analyst_finding import AnalystFinding, AnalystFindingError
from three_agent.security_monitoring.evidence_analysis_audit import EvidenceAnalysisAuditError, EvidenceAnalysisAuditJournal
from three_agent.security_monitoring.evidence_analysis_workflow import AuditedEvidenceAnalysisError, AuditedEvidenceAnalysisWorkflow
from three_agent.security_monitoring.evidence_lineage import EvidenceLineageError, EvidenceLineageGate, EvidenceLineagePolicy, EvidenceLineageReceipt
from three_agent.security_monitoring.normalized_evidence import EvidenceIntegrity, EvidenceObservationWindow, EvidenceProvenance, EvidenceQuality, NormalizedEvidence, NormalizedEvidenceBatch
from three_agent.security_monitoring.workflow_audit import SecurityWorkflowAuditJournal

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
SHA_D = "sha256:" + "d" * 64
SHA_E = "sha256:" + "e" * 64
SHA_F = "sha256:" + "f" * 64
SHA_1 = "sha256:" + "1" * 64
SHA_2 = "sha256:" + "2" * 64


class EvidencePipelineAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name).resolve()
        self.workflow_audit = SecurityWorkflowAuditJournal(root / "workflow.jsonl")
        self.anchor = self.workflow_audit.append(event_type="SESSION_PREPARED", session_id="security-session:" + "a" * 24, request_sha256=SHA_A, plan_fingerprint=SHA_B, binding_fingerprint=SHA_C, workflow_fingerprint=SHA_D, reason_codes=("WORKFLOW_PREPARED_NO_AUTO_EXECUTE",), occurred_at="2026-09-02T10:00:00Z")
        self.finding_audit = EvidenceAnalysisAuditJournal(root / "findings.jsonl", anchor_record_sha256=self.anchor.record_sha256)
        self.policy = EvidenceLineagePolicy(task_ref_sha256=SHA_E, approved_authorization_refs=(SHA_F,), approved_asset_refs=("asset:edge-router-01",), allowed_sensitivities=("internal", "confidential"))
        self.service = AuditedEvidenceAnalysisWorkflow(lineage_gate=EvidenceLineageGate(self.policy), workflow_audit_journal=self.workflow_audit, finding_audit_journal=self.finding_audit)

    def tearDown(self):
        self.tempdir.cleanup()

    @staticmethod
    def evidence(*, raw_ref="evidence/log/event-001", sensitivity="confidential", task_ref=SHA_E, content=SHA_1, source=SHA_2):
        return NormalizedEvidence.create(evidence_type="log_event", source_type="approved_json_log", asset_ref="asset:edge-router-01", task_ref_sha256=task_ref, authorization_ref_sha256=SHA_F, collected_at="2026-09-02T10:00:10Z", observation_window=EvidenceObservationWindow("2026-09-02T10:00:01Z", "2026-09-02T10:00:09Z"), integrity=EvidenceIntegrity(content, source), sensitivity=sensitivity, quality=EvidenceQuality(0.9, 1.0, ("read_only",)), raw_ref=raw_ref, provenance=EvidenceProvenance("approved_log_parser", "v1", (source,)))

    def analyze(self, *, batch=None, created_at="2026-09-02T10:01:00Z"):
        batch = batch or NormalizedEvidenceBatch.from_evidence((self.evidence(),))
        return self.service.analyze(batch=batch, observed_facts=("Approved telemetry recorded repeated service failures.",), derived_indicators=("Failure ratio exceeded the reviewed baseline.",), hypotheses=("A dependency may be degraded.",), confidence=0.8, supporting_evidence_ids=(batch.evidence[0].evidence_id,), conflicting_evidence_ids=(), recommended_human_actions=("Review approved service telemetry and maintenance state.",), affected_refs=("asset:edge-router-01", "service:network"), severity="medium", risk_classification="availability", created_at=created_at)

    def test_forged_lineage_receipt_rejects_non_boolean_automatic_action_flag(self):
        receipt = EvidenceLineageReceipt(task_ref_sha256=SHA_E, policy_fingerprint=SHA_A, evidence_batch_fingerprint=SHA_B, evidence_ids=("evidence:" + "1" * 24,), evidence_count=1, automatic_action_allowed=0)
        with self.assertRaisesRegex(EvidenceLineageError, "must be boolean"):
            receipt.validate()

    def test_forged_lineage_receipt_rejects_invalid_evidence_identifier(self):
        receipt = EvidenceLineageReceipt(task_ref_sha256=SHA_E, policy_fingerprint=SHA_A, evidence_batch_fingerprint=SHA_B, evidence_ids=("evidence:../../raw-payload",), evidence_count=1)
        with self.assertRaisesRegex(EvidenceLineageError, "invalid evidence ID"):
            receipt.validate()

    def test_forged_lineage_receipt_rejects_boolean_or_oversized_count(self):
        with self.assertRaisesRegex(EvidenceLineageError, "must be an integer"):
            EvidenceLineageReceipt(task_ref_sha256=SHA_E, policy_fingerprint=SHA_A, evidence_batch_fingerprint=SHA_B, evidence_ids=("evidence:" + "1" * 24,), evidence_count=True).validate()
        ids = tuple(f"evidence:{index:024x}" for index in range(257))
        with self.assertRaisesRegex(EvidenceLineageError, "bound exceeded"):
            EvidenceLineageReceipt(task_ref_sha256=SHA_E, policy_fingerprint=SHA_A, evidence_batch_fingerprint=SHA_B, evidence_ids=ids, evidence_count=len(ids)).validate()

    def test_excessive_finding_evidence_references_fail_closed(self):
        ids = tuple(f"evidence:{index:024x}" for index in range(1, 130))
        receipt = EvidenceLineageReceipt(task_ref_sha256=SHA_E, policy_fingerprint=SHA_A, evidence_batch_fingerprint=SHA_B, evidence_ids=ids, evidence_count=len(ids)).validate()
        with self.assertRaisesRegex(AnalystFindingError, "count exceeds bound"):
            AnalystFinding.create(observed_facts=("A bounded fact.",), hypotheses=("A bounded hypothesis.",), confidence=0.5, supporting_evidence_ids=ids, recommended_human_actions=("Review evidence.",), affected_refs=("asset:edge-router-01",), severity="low", risk_classification="operational", created_at="2026-09-02T10:01:00Z", observation_window=EvidenceObservationWindow("2026-09-02T10:00:00Z", "2026-09-02T10:00:59Z"), task_ref_sha256=SHA_E, audit_record_sha256=SHA_C, lineage_receipt=receipt)

    def test_policy_denied_sensitivity_cannot_bypass_integrated_gate(self):
        batch = NormalizedEvidenceBatch.from_evidence((self.evidence(sensitivity="secret"),))
        with self.assertRaisesRegex(EvidenceLineageError, "SENSITIVITY_DENIED"):
            self.analyze(batch=batch)
        self.assertFalse(self.finding_audit.path.exists())

    def test_tampered_normalized_evidence_id_cannot_enter_integrated_pipeline(self):
        row = self.evidence()
        forged = replace(row, evidence_id="evidence:" + "0" * 24)
        batch = NormalizedEvidenceBatch((forged,))
        with self.assertRaisesRegex(EvidenceLineageError, "normalized evidence rejected"):
            self.analyze(batch=batch)
        self.assertFalse(self.finding_audit.path.exists())

    def test_identical_finding_replay_is_denied_by_append_only_audit(self):
        self.analyze()
        with self.assertRaisesRegex(EvidenceAnalysisAuditError, "duplicate finding audit replay denied"):
            self.analyze()
        self.assertEqual(self.finding_audit.verify().record_count, 1)

    def test_finding_audit_timestamp_cannot_predate_finding(self):
        batch = NormalizedEvidenceBatch.from_evidence((self.evidence(),))
        result = self.analyze(batch=batch)
        second_journal = EvidenceAnalysisAuditJournal(Path(self.tempdir.name).resolve() / "second-findings.jsonl", anchor_record_sha256=self.anchor.record_sha256)
        with self.assertRaisesRegex(EvidenceAnalysisAuditError, "cannot precede finding created_at"):
            second_journal.append(finding=result.finding, batch=batch, lineage_receipt=result.lineage_receipt, occurred_at="2026-09-02T10:00:30Z")

    def test_non_regular_finding_audit_target_is_rejected(self):
        directory = Path(self.tempdir.name).resolve() / "audit-directory"
        directory.mkdir()
        journal = EvidenceAnalysisAuditJournal(directory, anchor_record_sha256=self.anchor.record_sha256)
        with self.assertRaises((EvidenceAnalysisAuditError, OSError)):
            journal.records()

    def test_reordered_finding_audit_records_break_hash_chain(self):
        first = self.analyze()
        second_batch = NormalizedEvidenceBatch.from_evidence((self.evidence(raw_ref="evidence/log/event-002", content=SHA_2, source=SHA_1),))
        second = self.analyze(batch=second_batch, created_at="2026-09-02T10:02:00Z")
        self.assertNotEqual(first.audit_record.record_sha256, second.audit_record.record_sha256)
        lines = self.finding_audit.path.read_text(encoding="utf-8").splitlines()
        self.finding_audit.path.write_text(lines[1] + "\n" + lines[0] + "\n", encoding="utf-8")
        with self.assertRaisesRegex(EvidenceAnalysisAuditError, "record_index|hash chain"):
            self.finding_audit.verify()

    def test_forged_recommendation_identity_is_rejected(self):
        result = self.analyze()
        forged = replace(result.recommendation, finding_id="finding:" + "x" * 24)
        with self.assertRaisesRegex(AuditedEvidenceAnalysisError, "finding_id is invalid"):
            forged.validate()

    def test_result_rejects_recommendation_content_not_derived_from_finding(self):
        result = self.analyze()
        forged_recommendation = replace(result.recommendation, recommended_human_actions=("Take a different human action.",)).validate()
        forged_result = replace(result, recommendation=forged_recommendation)
        with self.assertRaisesRegex(AuditedEvidenceAnalysisError, "actions do not match finding"):
            forged_result.validate()

    def test_result_rejects_automatic_action_escalation(self):
        result = self.analyze()
        forged_recommendation = replace(result.recommendation, automatic_action_allowed=True)
        with self.assertRaisesRegex(AuditedEvidenceAnalysisError, "automatic action authority"):
            forged_recommendation.validate()
        forged_audit = replace(result.audit_record, automatic_action_allowed=0)
        with self.assertRaisesRegex(EvidenceAnalysisAuditError, "must be boolean"):
            forged_audit.validate()

    def test_integrated_workflow_does_not_accept_external_receipt_or_remediation_parameters(self):
        parameters = inspect.signature(self.service.analyze).parameters
        for forbidden in ("lineage_receipt", "execute", "remediate", "firewall_rule", "shell_command", "capture_command"):
            self.assertNotIn(forbidden, parameters)
        self.assertFalse(hasattr(self.service, "execute"))
        self.assertFalse(hasattr(self.service, "remediate"))


if __name__ == "__main__":
    unittest.main()
