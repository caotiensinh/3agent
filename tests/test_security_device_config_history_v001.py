import json
import unittest
from dataclasses import replace

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.device_config_history import (
    DeviceConfigDiff,
    DeviceConfigHistory,
    DeviceConfigSectionDigest,
    DeviceConfigSnapshot,
)


SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
SHA_D = "sha256:" + "d" * 64
SHA_E = "sha256:" + "e" * 64
SHA_F = "sha256:" + "f" * 64


class DeviceConfigHistoryTests(unittest.TestCase):
    @staticmethod
    def _snapshot(
        *,
        captured_at="2026-09-10T01:00:00+00:00",
        asset_id="edge-router-01",
        sections=None,
        source_record_sha256=SHA_A,
        task_ref_sha256=SHA_E,
        authorization_ref_sha256=SHA_F,
    ):
        return DeviceConfigSnapshot.build(
            asset_id=asset_id,
            captured_at=captured_at,
            source_type="reviewed_device_export",
            producer="device_config_import",
            task_ref_sha256=task_ref_sha256,
            authorization_ref_sha256=authorization_ref_sha256,
            source_record_sha256=source_record_sha256,
            sections=sections
            or (
                DeviceConfigSectionDigest("interfaces", SHA_B, 12),
                DeviceConfigSectionDigest("routes", SHA_C, 8),
                DeviceConfigSectionDigest("vlans", SHA_D, 4),
            ),
        )

    def test_snapshot_is_order_independent_and_metadata_only(self):
        sections = (
            DeviceConfigSectionDigest("vlans", SHA_D, 4),
            DeviceConfigSectionDigest("interfaces", SHA_B, 12),
            DeviceConfigSectionDigest("routes", SHA_C, 8),
        )
        first = self._snapshot(sections=sections)
        second = self._snapshot(sections=tuple(reversed(sections)))
        self.assertEqual(first.snapshot_id, second.snapshot_id)
        self.assertEqual(first.identity_sha256, second.identity_sha256)
        snapshot_payload = first.public_dict()
        self.assertFalse(snapshot_payload["raw_config_retained"])
        self.assertNotIn("raw_config", snapshot_payload)
        self.assertNotIn("raw_payload", snapshot_payload)
        self.assertNotIn("configuration_text", snapshot_payload)
        self.assertNotIn("credential_ref", snapshot_payload)
        self.assertEqual(first.authority, "evidence_only")

    def test_snapshot_binds_task_authorization_and_source_integrity(self):
        snapshot = self._snapshot()
        self.assertEqual(snapshot.task_ref_sha256, SHA_E)
        self.assertEqual(snapshot.authorization_ref_sha256, SHA_F)
        self.assertEqual(snapshot.source_record_sha256, SHA_A)
        with self.assertRaisesRegex(MonitoringContractError, "task_ref_sha256"):
            self._snapshot(task_ref_sha256="")
        with self.assertRaisesRegex(MonitoringContractError, "authorization_ref_sha256"):
            self._snapshot(authorization_ref_sha256="")

    def test_snapshot_rejects_duplicate_sections_and_raw_retention(self):
        with self.assertRaisesRegex(MonitoringContractError, "section names must be unique"):
            self._snapshot(
                sections=(
                    DeviceConfigSectionDigest("routes", SHA_B, 1),
                    DeviceConfigSectionDigest("routes", SHA_C, 1),
                )
            )
        snapshot = self._snapshot()
        with self.assertRaisesRegex(MonitoringContractError, "raw device configuration retention"):
            replace(snapshot, raw_config_retained=True).validate()

    def test_diff_is_deterministic_and_classifies_drift(self):
        base = self._snapshot()
        target = self._snapshot(
            captured_at="2026-09-10T01:05:00+00:00",
            source_record_sha256=SHA_E,
            sections=(
                DeviceConfigSectionDigest("interfaces", SHA_B, 12),
                DeviceConfigSectionDigest("routes", SHA_E, 9),
                DeviceConfigSectionDigest("acl", SHA_F, 5),
            ),
        )
        diff = DeviceConfigDiff.between(base, target)
        self.assertTrue(diff.drift_detected)
        self.assertEqual(diff.added_sections, ("acl",))
        self.assertEqual(diff.removed_sections, ("vlans",))
        self.assertEqual(diff.changed_sections, ("routes",))
        self.assertEqual(diff.unchanged_sections, ("interfaces",))
        self.assertEqual(diff.diff_id, DeviceConfigDiff.between(base, target).diff_id)

    def test_diff_rejects_cross_asset_and_reverse_time(self):
        base = self._snapshot()
        other = self._snapshot(
            asset_id="edge-router-02",
            captured_at="2026-09-10T01:05:00+00:00",
        )
        with self.assertRaisesRegex(MonitoringContractError, "same asset"):
            DeviceConfigDiff.between(base, other)
        older = self._snapshot(captured_at="2026-09-10T00:59:00+00:00")
        with self.assertRaisesRegex(MonitoringContractError, "cannot precede"):
            DeviceConfigDiff.between(base, older)

    def test_history_is_chronological_bounded_and_deduplicated(self):
        first = self._snapshot(captured_at="2026-09-10T01:00:00+00:00")
        second = self._snapshot(
            captured_at="2026-09-10T01:05:00+00:00",
            source_record_sha256=SHA_E,
            sections=(
                DeviceConfigSectionDigest("interfaces", SHA_B, 12),
                DeviceConfigSectionDigest("routes", SHA_E, 9),
                DeviceConfigSectionDigest("vlans", SHA_D, 4),
            ),
        )
        history = DeviceConfigHistory.build((second, first, first))
        self.assertEqual(
            tuple(row.snapshot_id for row in history.snapshots),
            (first.snapshot_id, second.snapshot_id),
        )
        self.assertEqual(len(history.diffs), 1)
        self.assertTrue(history.diffs[0].drift_detected)
        self.assertRegex(history.fingerprint, r"^sha256:[0-9a-f]{64}$")
        history_payload = history.public_dict()
        self.assertFalse(history_payload["raw_config_retained"])
        for snapshot_payload in history_payload["snapshots"]:
            self.assertFalse(snapshot_payload["raw_config_retained"])
            self.assertNotIn("raw_config", snapshot_payload)
            self.assertNotIn("raw_payload", snapshot_payload)
            self.assertNotIn("configuration_text", snapshot_payload)
            self.assertNotIn("credential_ref", snapshot_payload)

    def test_history_rejects_multiple_assets(self):
        with self.assertRaisesRegex(MonitoringContractError, "one asset"):
            DeviceConfigHistory.build(
                (
                    self._snapshot(asset_id="edge-router-01"),
                    self._snapshot(asset_id="edge-router-02"),
                )
            )

    def test_tampered_snapshot_and_diff_ids_fail_closed(self):
        snapshot = self._snapshot()
        with self.assertRaisesRegex(MonitoringContractError, "snapshot_id does not match"):
            replace(snapshot, snapshot_id="config-snapshot:" + "f" * 24).validate()

        target = self._snapshot(
            captured_at="2026-09-10T01:05:00+00:00",
            source_record_sha256=SHA_E,
        )
        diff = DeviceConfigDiff.between(snapshot, target)
        with self.assertRaisesRegex(MonitoringContractError, "diff_id does not match"):
            replace(diff, diff_id="config-diff:" + "f" * 24).validate()

    def test_invalid_section_hash_and_item_bound_fail_closed(self):
        with self.assertRaisesRegex(MonitoringContractError, "content_sha256"):
            DeviceConfigSectionDigest("routes", "sha256:not-valid", 1).validate()
        with self.assertRaisesRegex(MonitoringContractError, "item_count"):
            DeviceConfigSectionDigest("routes", SHA_B, -1).validate()


if __name__ == "__main__":
    unittest.main()
