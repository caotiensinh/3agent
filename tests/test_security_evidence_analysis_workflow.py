import json
import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.evidence_analysis_audit import EvidenceAnalysisAuditError, EvidenceAnalysisAuditJournal
from three_agent.security_monitoring.evidence_analysis_workflow import AuditedEvidenceAnalysisError, AuditedEvidenceAnalysisWorkflow
from three_agent.security_monitoring.evidence_lineage import EvidenceLineageError, EvidenceLineageGate, EvidenceLineagePolicy
from three_agent.security_monitoring.normalized_evidence import (
    EvidenceIntegrity,
    EvidenceObservationWindow,
    EvidenceProvenance,
    EvidenceQuality,
    NormalizedEvidence,
    NormalizedEvidenceBatch,
)
from three_agent.security_monitoring.workflow_audit import SecurityWorkflowAuditJournal

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
SHA_D = "sha256:" + "d" * 64
SHA_E = "sha256:" + "e" * 64
SHA_F = "sha256:" + "f" * 64
SHA_1 = "sha256:" + "1" * 64
SHA_2 = "sha256:" + "2" * 64


class AuditedEvidenceAnalysisWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name).resolve()
        self.workflow_audit = SecurityWorkflowAuditJournal(root / "workflow-audit.jsonl")
        self.anchor = self.workflow_audit.append(
            event_type="SESSION_PREPARED",
            session_id="security-session:" + "1" * 24,
            request_sha256=SHA_A,
            plan_fingerprint=SHA_B,
            binding_fingerprint=SHA_C,
            workflow_fingerprint=SHA_D,
            reason_codes=("WORKFLOW_PREPARED_NO_AUTO_EXECUTE",),
            occurred_at="2026-09-02T09:00:00Z",
        )
        self.finding_audit = EvidenceAnalysisAuditJournal(
            root / "finding-audit.jsonl",
            anchor_record_sha256=self.anchor.record_sha256,
        )
        self.policy = EvidenceLineagePolicy(
            task_ref_sha256=SHA_E,
            approved_authorization_refs=(SHA_F,),
            approved_asset_refs=("asset:edge-router-01",),
            allowed_sensitivities=("internal", "confidential", "restricted"),
        )
        self.service = AuditedEvidenceAnalysisWorkflow(
            lineage_gate=EvidenceLineageGate(self.policy),
            workflow_audit_journal=self.workflow_audit,
            finding_audit_journal=self.finding_audit,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    @staticmethod
    def _evidence(*, raw_ref="evidence/dns/event-001", content_hash=SHA_1, source_hash=SHA_2, task_ref=SHA_E):
        return NormalizedEvidence.create(
            evidence_type="dns_event",
            source_type="zeek_json",
            asset_ref="asset:edge-router-01",
            task_ref_sha256=task_ref,
            authorization_ref_sha256=SHA_F,
            collected_at="2026-09-02T09:00:10Z",
            observation_window=EvidenceObservationWindow("2026-09-02T09:00:01Z", "2026-09-02T09:00:09Z"),
            integrity=EvidenceIntegrity(content_hash, source_hash),
            sensitivity="confidential",
            quality=EvidenceQuality(0.92, 1.0, ("read_only",)),
            raw_ref=raw_ref,
            provenance=EvidenceProvenance("zeek_dns_parser", "v1", (source_hash,)),
        )

    def _analyze(self, batch=None, **overrides):
        batch = batch or NormalizedEvidenceBatch.from_evidence((self._evidence(),))
        values = {
            "batch": batch,
            "observed_facts": ("Repeated DNS SERVFAIL responses were observed.",),
            "derived_indicators": ("Resolver failure ratio exceeded the reviewed baseline.",),
            "hypotheses": ("An upstream DNS dependency may be degraded.",),
            "confidence": 0.82,
            "supporting_evidence_ids": (batch.evidence[0].evidence_id,),
            "conflicting_evidence_ids": (),
            "recommended_human_actions": ("Review approved upstream DNS telemetry.",),
            "affected_refs": ("asset:edge-router-01", "service:dns"),
            "severity": "medium",
            "risk_classification": "availability",
            "created_at": "2026-09-02T09:01:00Z",
        }
        values.update(overrides)
        return self.service.analyze(**values)

    def test_valid_pipeline_links_existing_audit_to_finding_audit_and_human_recommendation(self):
        result = self._analyze()
        self.assertEqual(result.finding.audit_record_sha256, self.anchor.record_sha256)
        self.assertEqual(result.audit_record.previous_record_sha256, self.anchor.record_sha256)
        self.assertEqual(result.audit_record.finding_sha256, result.finding.identity_sha256)
        self.assertEqual(result.recommendation.finding_audit_record_sha256, result.audit_record.record_sha256)
        self.assertEqual(result.recommendation.recommended_human_actions, result.finding.recommended_human_actions)
        self.assertEqual(result.recommendation.authority, "advisory")
        self.assertFalse(result.recommendation.automatic_action_allowed)
        verification = self.finding_audit.verify()
        self.assertEqual(verification.record_count, 1)
        self.assertEqual(verification.anchor_record_sha256, self.anchor.record_sha256)

    def test_observation_window_is_derived_from_normalized_evidence_batch(self):
        first = self._evidence(raw_ref="evidence/dns/event-001")
        second = NormalizedEvidence.create(
            evidence_type="network_flow",
            source_type="flow_json",
            asset_ref="asset:edge-router-01",
            task_ref_sha256=SHA_E,
            authorization_ref_sha256=SHA_F,
            collected_at="2026-09-02T09:00:20Z",
            observation_window=EvidenceObservationWindow("2026-09-02T08:59:58Z", "2026-09-02T09:00:19Z"),
            integrity=EvidenceIntegrity(SHA_2, SHA_1),
            sensitivity="confidential",
            quality=EvidenceQuality(0.88, 1.0, ("read_only",)),
            raw_ref="evidence/flow/event-002",
            provenance=EvidenceProvenance("flow_parser", "v1", (SHA_1,)),
        )
        batch = NormalizedEvidenceBatch.from_evidence((first, second))
        result = self._analyze(batch=batch)
        self.assertEqual(result.finding.observation_window.start_at, "2026-09-02T08:59:58Z")
        self.assertEqual(result.finding.observation_window.end_at, "2026-09-02T09:00:19Z")

    def test_invalid_existing_workflow_audit_fails_closed_before_analysis(self):
        path = self.workflow_audit.path
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace(self.anchor.record_sha256, SHA_1), encoding="utf-8")
        with self.assertRaisesRegex(AuditedEvidenceAnalysisError, "existing workflow audit rejected"):
            self._analyze()
        self.assertFalse(self.finding_audit.path.exists())

    def test_workflow_audit_anchor_change_fails_closed(self):
        self.workflow_audit.append(
            event_type="SESSION_PREPARED",
            session_id="security-session:" + "2" * 24,
            request_sha256=SHA_A,
            plan_fingerprint=SHA_B,
            binding_fingerprint=SHA_C,
            workflow_fingerprint=SHA_D,
            reason_codes=("WORKFLOW_PREPARED_NO_AUTO_EXECUTE",),
            occurred_at="2026-09-02T09:00:30Z",
        )
        with self.assertRaisesRegex(AuditedEvidenceAnalysisError, "anchor does not match"):
            self._analyze()

    def test_lineage_task_mismatch_fails_before_finding_audit(self):
        batch = NormalizedEvidenceBatch.from_evidence((self._evidence(task_ref=SHA_A),))
        with self.assertRaisesRegex(EvidenceLineageError, "TASK_MISMATCH"):
            self._analyze(batch=batch)
        self.assertFalse(self.finding_audit.path.exists())

    def test_finding_audit_chain_is_anchored_and_contiguous_for_multiple_findings(self):
        first = self._analyze()
        second_batch = NormalizedEvidenceBatch.from_evidence(
            (self._evidence(raw_ref="evidence/dns/event-002", content_hash=SHA_2, source_hash=SHA_1),)
        )
        second = self._analyze(batch=second_batch)
        self.assertEqual(second.audit_record.record_index, 2)
        self.assertEqual(second.audit_record.previous_record_sha256, first.audit_record.record_sha256)
        verification = self.finding_audit.verify()
        self.assertEqual(verification.record_count, 2)
        self.assertEqual(verification.last_record_sha256, second.audit_record.record_sha256)

    def test_tampered_finding_audit_record_fails_closed(self):
        self._analyze()
        text = self.finding_audit.path.read_text(encoding="utf-8")
        payload = json.loads(text)
        payload["automatic_action_allowed"] = True
        self.finding_audit.path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(EvidenceAnalysisAuditError, "automatic action authority"):
            self.finding_audit.verify()

    def test_human_recommendation_exposes_no_remediation_api_or_raw_evidence_reference(self):
        result = self._analyze()
        recommendation = result.recommendation
        for name in ("execute", "apply", "remediate", "run_shell", "modify_firewall"):
            self.assertFalse(hasattr(recommendation, name))
        rendered = json.dumps(recommendation.public_dict(), sort_keys=True)
        self.assertNotIn("raw_ref", rendered)
        self.assertNotIn("source_record", rendered)
        self.assertNotIn("packet", rendered)

    def test_finding_audit_symlink_is_denied_when_supported(self):
        target = Path(self.tempdir.name).resolve() / "target.jsonl"
        target.write_text("", encoding="utf-8")
        link = Path(self.tempdir.name).resolve() / "symlink-audit.jsonl"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unavailable")
        journal = EvidenceAnalysisAuditJournal(link, anchor_record_sha256=self.anchor.record_sha256)
        with self.assertRaisesRegex(EvidenceAnalysisAuditError, "symlink denied"):
            journal.records()


if __name__ == "__main__":
    unittest.main()
