import json
import unittest
from dataclasses import replace

from three_agent.security_monitoring.normalized_evidence import (
    MAX_METADATA_ITEMS,
    EvidenceIntegrity,
    EvidenceMetadataItem,
    EvidenceObservationWindow,
    EvidenceProvenance,
    EvidenceQuality,
    NormalizedEvidence,
    NormalizedEvidenceBatch,
    NormalizedEvidenceError,
)


SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
SHA_D = "sha256:" + "d" * 64


class NormalizedEvidenceTests(unittest.TestCase):
    @staticmethod
    def _evidence(**overrides):
        values = {
            "evidence_type": "pcap_summary",
            "source_type": "classic_pcap",
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
            "quality": EvidenceQuality(0.95, 1.0, ("bounded", "read_only")),
            "raw_ref": "evidence/pcap/capture-001",
            "provenance": EvidenceProvenance(
                "bounded_pcap_reader",
                "pcap-v0.7.1",
                (SHA_C, SHA_D),
            ),
            "metadata": (
                EvidenceMetadataItem("packet_count_ref", "metric:packet-count:42"),
            ),
        }
        values.update(overrides)
        return NormalizedEvidence.create(**values)

    def test_valid_normalized_evidence_is_deterministic_and_contains_no_raw_payload(self):
        first = self._evidence()
        second = self._evidence()
        self.assertEqual(first.evidence_id, second.evidence_id)
        self.assertEqual(first.identity_sha256, second.identity_sha256)
        self.assertEqual(first.canonical_json(), second.canonical_json())
        payload = json.loads(first.canonical_json())
        self.assertEqual(payload["schema_version"], "workspace-security-normalized-evidence/v1")
        self.assertEqual(payload["evidence_type"], "pcap_summary")
        self.assertRegex(payload["evidence_id"], r"^evidence:[0-9a-f]{24}$")
        self.assertNotIn("raw_payload", payload)
        self.assertNotIn("packet_payload", payload)

    def test_supported_source_families_can_use_common_envelope(self):
        for evidence_type in (
            "snmp_observation",
            "log_event",
            "pcap_summary",
            "dns_event",
            "network_flow",
            "authentication_event",
            "process_event",
            "correlation_result",
        ):
            with self.subTest(evidence_type=evidence_type):
                row = self._evidence(evidence_type=evidence_type)
                self.assertEqual(row.evidence_type, evidence_type)

    def test_missing_task_authorization_fails_closed(self):
        with self.assertRaisesRegex(NormalizedEvidenceError, "task_ref_sha256"):
            self._evidence(task_ref_sha256="")
        with self.assertRaisesRegex(NormalizedEvidenceError, "authorization_ref_sha256"):
            self._evidence(authorization_ref_sha256="")

    def test_missing_provenance_fails_closed(self):
        with self.assertRaisesRegex(NormalizedEvidenceError, "provenance lineage is required"):
            self._evidence(
                provenance=EvidenceProvenance("bounded_pcap_reader", "pcap-v0.7.1", ())
            )

    def test_invalid_hash_reference_fails_closed(self):
        with self.assertRaisesRegex(NormalizedEvidenceError, "content_sha256"):
            self._evidence(integrity=EvidenceIntegrity("sha256:not-a-hash", SHA_D))

    def test_oversized_metadata_fails_closed(self):
        metadata = tuple(
            EvidenceMetadataItem(f"key_{index}", f"ref:value:{index}")
            for index in range(MAX_METADATA_ITEMS + 1)
        )
        with self.assertRaisesRegex(NormalizedEvidenceError, "too many metadata"):
            self._evidence(metadata=metadata)

    def test_metadata_rejects_urls_and_path_traversal(self):
        with self.assertRaisesRegex(NormalizedEvidenceError, "URL or path traversal"):
            self._evidence(metadata=(EvidenceMetadataItem("source", "https://example.com/raw"),))
        with self.assertRaisesRegex(NormalizedEvidenceError, "URL or path traversal"):
            self._evidence(raw_ref="evidence/../secret.log")

    def test_invalid_observation_lineage_fails_closed(self):
        with self.assertRaisesRegex(NormalizedEvidenceError, "end precedes start"):
            self._evidence(
                observation_window=EvidenceObservationWindow(
                    "2026-09-02T09:00:09+00:00",
                    "2026-09-02T09:00:00+00:00",
                )
            )
        with self.assertRaisesRegex(NormalizedEvidenceError, "collected_at cannot precede"):
            self._evidence(collected_at="2026-09-02T08:59:59+00:00")

    def test_sensitivity_classification_is_restricted_to_approved_classes(self):
        with self.assertRaisesRegex(NormalizedEvidenceError, "sensitivity"):
            self._evidence(sensitivity="unclassified-external")

    def test_duplicate_identical_evidence_is_deduplicated_deterministically(self):
        row = self._evidence()
        batch = NormalizedEvidenceBatch.from_evidence((row, row, self._evidence()))
        self.assertEqual(len(batch.evidence), 1)
        self.assertRegex(batch.fingerprint, r"^sha256:[0-9a-f]{64}$")

    def test_tampered_evidence_id_fails_closed(self):
        row = self._evidence()
        tampered = replace(row, evidence_id="evidence:" + "f" * 24)
        with self.assertRaisesRegex(NormalizedEvidenceError, "evidence_id does not match"):
            tampered.validate()

    def test_duplicate_metadata_keys_fail_closed(self):
        with self.assertRaisesRegex(NormalizedEvidenceError, "metadata keys must be unique"):
            self._evidence(
                metadata=(
                    EvidenceMetadataItem("metric", "ref:value:1"),
                    EvidenceMetadataItem("metric", "ref:value:2"),
                )
            )

    def test_quality_and_provenance_bounds_are_fail_closed(self):
        with self.assertRaisesRegex(NormalizedEvidenceError, "quality.confidence"):
            self._evidence(quality=EvidenceQuality(1.01, 1.0))
        with self.assertRaisesRegex(NormalizedEvidenceError, "lineage references must be unique"):
            self._evidence(
                provenance=EvidenceProvenance(
                    "bounded_pcap_reader",
                    "pcap-v0.7.1",
                    (SHA_C, SHA_C),
                )
            )


if __name__ == "__main__":
    unittest.main()
