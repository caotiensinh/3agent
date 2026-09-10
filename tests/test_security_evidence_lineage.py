import unittest
from dataclasses import replace

from three_agent.security_monitoring.evidence_lineage import (
    EvidenceLineageError,
    EvidenceLineageGate,
    EvidenceLineagePolicy,
)
from three_agent.security_monitoring.normalized_evidence import (
    EvidenceIntegrity,
    EvidenceObservationWindow,
    EvidenceProvenance,
    EvidenceQuality,
    NormalizedEvidence,
    NormalizedEvidenceBatch,
)

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
SHA_D = "sha256:" + "d" * 64
SHA_E = "sha256:" + "e" * 64


class EvidenceLineageGateTests(unittest.TestCase):
    @staticmethod
    def _evidence(**overrides):
        values = {
            "evidence_type": "dns_event",
            "source_type": "zeek_json",
            "asset_ref": "asset:edge-router-01",
            "task_ref_sha256": SHA_A,
            "authorization_ref_sha256": SHA_B,
            "collected_at": "2026-09-02T09:00:10+00:00",
            "observation_window": EvidenceObservationWindow(
                "2026-09-02T09:00:00+00:00",
                "2026-09-02T09:00:09+00:00",
            ),
            "integrity": EvidenceIntegrity(SHA_C, SHA_D),
            "sensitivity": "confidential",
            "quality": EvidenceQuality(0.9, 1.0, ("read_only",)),
            "raw_ref": "evidence/dns/event-001",
            "provenance": EvidenceProvenance("zeek_dns_parser", "v1", (SHA_D, SHA_E)),
        }
        values.update(overrides)
        return NormalizedEvidence.create(**values)

    @staticmethod
    def _policy(**overrides):
        values = {
            "task_ref_sha256": SHA_A,
            "approved_authorization_refs": (SHA_B,),
            "approved_asset_refs": ("asset:edge-router-01",),
            "allowed_sensitivities": ("internal", "confidential", "restricted"),
        }
        values.update(overrides)
        return EvidenceLineagePolicy(**values)

    def test_valid_batch_produces_advisory_receipt(self):
        batch = NormalizedEvidenceBatch.from_evidence((self._evidence(),))
        receipt = EvidenceLineageGate(self._policy()).validate_batch(batch)
        self.assertEqual(receipt.status, "validated")
        self.assertEqual(receipt.reason_code, "EVIDENCE_LINEAGE_VALIDATED")
        self.assertEqual(receipt.authority, "advisory")
        self.assertFalse(receipt.automatic_action_allowed)
        self.assertEqual(receipt.evidence_count, 1)
        self.assertRegex(receipt.policy_fingerprint, r"^sha256:[0-9a-f]{64}$")

    def test_task_mismatch_fails_closed(self):
        row = self._evidence(task_ref_sha256=SHA_E)
        batch = NormalizedEvidenceBatch.from_evidence((row,))
        with self.assertRaisesRegex(EvidenceLineageError, "TASK_MISMATCH"):
            EvidenceLineageGate(self._policy()).validate_batch(batch)

    def test_authorization_mismatch_fails_closed(self):
        row = self._evidence(authorization_ref_sha256=SHA_E)
        batch = NormalizedEvidenceBatch.from_evidence((row,))
        with self.assertRaisesRegex(EvidenceLineageError, "AUTHORIZATION_MISMATCH"):
            EvidenceLineageGate(self._policy()).validate_batch(batch)

    def test_unknown_asset_fails_closed(self):
        row = self._evidence(asset_ref="asset:unknown")
        batch = NormalizedEvidenceBatch.from_evidence((row,))
        with self.assertRaisesRegex(EvidenceLineageError, "ASSET_NOT_APPROVED"):
            EvidenceLineageGate(self._policy()).validate_batch(batch)

    def test_source_integrity_hash_must_be_in_provenance(self):
        row = self._evidence(
            provenance=EvidenceProvenance("zeek_dns_parser", "v1", (SHA_E,))
        )
        batch = NormalizedEvidenceBatch.from_evidence((row,))
        with self.assertRaisesRegex(EvidenceLineageError, "SOURCE_HASH_NOT_IN_PROVENANCE"):
            EvidenceLineageGate(self._policy()).validate_batch(batch)

    def test_sensitivity_policy_is_fail_closed(self):
        row = self._evidence(sensitivity="secret")
        batch = NormalizedEvidenceBatch.from_evidence((row,))
        with self.assertRaisesRegex(EvidenceLineageError, "SENSITIVITY_DENIED"):
            EvidenceLineageGate(self._policy()).validate_batch(batch)

    def test_policy_rejects_empty_authorization_or_asset_scope(self):
        with self.assertRaisesRegex(EvidenceLineageError, "authorization references"):
            self._policy(approved_authorization_refs=()).validate()
        with self.assertRaisesRegex(EvidenceLineageError, "asset references"):
            self._policy(approved_asset_refs=()).validate()

    def test_policy_rejects_duplicate_scope_entries(self):
        with self.assertRaisesRegex(EvidenceLineageError, "authorization references"):
            self._policy(approved_authorization_refs=(SHA_B, SHA_B)).validate()
        with self.assertRaisesRegex(EvidenceLineageError, "asset references"):
            self._policy(
                approved_asset_refs=("asset:edge-router-01", "asset:edge-router-01")
            ).validate()

    def test_batch_bound_is_enforced_by_gate_policy(self):
        first = self._evidence()
        second = self._evidence(raw_ref="evidence/dns/event-002", integrity=EvidenceIntegrity(SHA_E, SHA_D))
        batch = NormalizedEvidenceBatch.from_evidence((first, second))
        with self.assertRaisesRegex(EvidenceLineageError, "BATCH_BOUND_EXCEEDED"):
            EvidenceLineageGate(self._policy(max_evidence=1)).validate_batch(batch)

    def test_domain_hash_collision_is_rejected(self):
        row = self._evidence(integrity=EvidenceIntegrity(SHA_A, SHA_D))
        batch = NormalizedEvidenceBatch.from_evidence((row,))
        with self.assertRaisesRegex(EvidenceLineageError, "DOMAIN_HASH_COLLISION"):
            EvidenceLineageGate(self._policy()).validate_batch(batch)

    def test_tampered_normalized_evidence_is_rejected_before_lineage(self):
        row = self._evidence()
        tampered = replace(row, evidence_id="evidence:" + "0" * 24)
        batch = NormalizedEvidenceBatch((tampered,))
        with self.assertRaisesRegex(EvidenceLineageError, "normalized evidence rejected"):
            EvidenceLineageGate(self._policy()).validate_batch(batch)


if __name__ == "__main__":
    unittest.main()
