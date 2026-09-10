import json
import unittest
from dataclasses import replace

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.device_config_history import (
    DeviceConfigSectionDigest,
    DeviceConfigSnapshot,
)
from three_agent.security_monitoring.device_config_normalization import (
    normalize_device_config_snapshot,
)
from three_agent.security_monitoring.normalized_evidence import (
    NormalizedEvidenceError,
    SUPPORTED_EVIDENCE_TYPES,
)

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
SHA_D = "sha256:" + "d" * 64
SHA_E = "sha256:" + "e" * 64


class DeviceConfigNormalizationTests(unittest.TestCase):
    @staticmethod
    def _snapshot():
        return DeviceConfigSnapshot.build(
            asset_id="edge-router-01",
            captured_at="2026-09-10T03:10:00+00:00",
            source_type="reviewed_device_export",
            producer="device_config_import",
            task_ref_sha256=SHA_D,
            authorization_ref_sha256=SHA_E,
            source_record_sha256=SHA_A,
            sections=(
                DeviceConfigSectionDigest("interfaces", SHA_B, 12),
                DeviceConfigSectionDigest("routes", SHA_C, 8),
            ),
        )

    def test_configuration_snapshot_is_canonical_supported_evidence(self):
        self.assertIn("configuration_snapshot", SUPPORTED_EVIDENCE_TYPES)
        snapshot = self._snapshot()
        row = normalize_device_config_snapshot(
            snapshot,
            sensitivity="confidential",
            confidence=0.95,
            completeness=0.80,
        )
        self.assertEqual(row.evidence_type, "configuration_snapshot")
        self.assertEqual(row.asset_ref, "asset:edge-router-01")
        self.assertEqual(row.task_ref_sha256, SHA_D)
        self.assertEqual(row.authorization_ref_sha256, SHA_E)
        self.assertEqual(row.integrity.content_sha256, snapshot.section_set_sha256)
        self.assertEqual(row.integrity.source_record_sha256, SHA_A)
        self.assertEqual(row.raw_ref, snapshot.snapshot_id)
        self.assertEqual(row.quality.confidence, 0.95)
        self.assertEqual(row.quality.completeness, 0.80)
        self.assertEqual(row.quality.flags, ("metadata_only", "read_only"))

    def test_normalization_is_deterministic_and_contains_no_raw_configuration(self):
        snapshot = self._snapshot()
        first = normalize_device_config_snapshot(
            snapshot,
            sensitivity="confidential",
            confidence=0.90,
            completeness=0.75,
        )
        second = normalize_device_config_snapshot(
            snapshot,
            sensitivity="confidential",
            confidence=0.90,
            completeness=0.75,
        )
        self.assertEqual(first.evidence_id, second.evidence_id)
        payload = json.loads(first.canonical_json())
        self.assertEqual(payload["metadata"][-1], {"key": "raw_config_retained", "value_ref": "policy:false"})
        serialized = first.canonical_json()
        self.assertNotIn("configuration_text", serialized)
        self.assertNotIn("credential", serialized)
        self.assertNotIn("password", serialized)
        self.assertNotIn("secret", serialized)

    def test_quality_is_explicit_and_fail_closed(self):
        snapshot = self._snapshot()
        with self.assertRaisesRegex(NormalizedEvidenceError, "quality.confidence"):
            normalize_device_config_snapshot(
                snapshot,
                sensitivity="confidential",
                confidence=1.01,
                completeness=0.75,
            )
        with self.assertRaisesRegex(NormalizedEvidenceError, "quality.completeness"):
            normalize_device_config_snapshot(
                snapshot,
                sensitivity="confidential",
                confidence=0.90,
                completeness=-0.01,
            )

    def test_tampered_snapshot_is_rejected_before_normalization(self):
        snapshot = self._snapshot()
        tampered = replace(snapshot, raw_config_retained=True)
        with self.assertRaisesRegex(MonitoringContractError, "raw device configuration retention"):
            normalize_device_config_snapshot(
                tampered,
                sensitivity="confidential",
                confidence=0.90,
                completeness=0.75,
            )


if __name__ == "__main__":
    unittest.main()
