import unittest
from dataclasses import replace

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.endpoint_state_snapshot import EndpointStateComponent, EndpointStateSnapshot

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
SHA_D = "sha256:" + "d" * 64


class EndpointStateSnapshotTests(unittest.TestCase):
    def _snapshot(self):
        return EndpointStateSnapshot.build(
            asset_id="asset:edge-host-01",
            captured_at="2026-09-10T03:00:00+00:00",
            producer="reviewed-endpoint-import",
            task_ref_sha256=SHA_A,
            authorization_ref_sha256=SHA_B,
            source_record_sha256=SHA_C,
            components=(
                EndpointStateComponent("services", SHA_C, 12),
                EndpointStateComponent("packages", SHA_D, 240),
            ),
        )

    def test_snapshot_is_deterministic_and_metadata_only(self):
        first = self._snapshot()
        second = EndpointStateSnapshot.build(
            asset_id=first.asset_id, captured_at=first.captured_at, producer=first.producer,
            task_ref_sha256=first.task_ref_sha256,
            authorization_ref_sha256=first.authorization_ref_sha256,
            source_record_sha256=first.source_record_sha256,
            components=tuple(reversed(first.components)),
        )
        self.assertEqual(first.snapshot_id, second.snapshot_id)
        payload = first.identity_dict()
        self.assertFalse(payload["remote_execution_performed"])
        self.assertFalse(payload["raw_output_retained"])
        self.assertNotIn("command", payload)
        self.assertNotIn("credential", payload)

    def test_duplicate_components_fail_closed(self):
        with self.assertRaisesRegex(MonitoringContractError, "unique"):
            EndpointStateSnapshot.build(
                asset_id="asset:x", captured_at="2026-09-10T03:00:00+00:00", producer="import",
                task_ref_sha256=SHA_A, authorization_ref_sha256=SHA_B, source_record_sha256=SHA_C,
                components=(EndpointStateComponent("services", SHA_C, 1), EndpointStateComponent("services", SHA_D, 2)),
            )

    def test_execution_and_tampered_id_fail_closed(self):
        snapshot = self._snapshot()
        with self.assertRaisesRegex(MonitoringContractError, "broaden"):
            replace(snapshot, remote_execution_performed=True).validate()
        with self.assertRaisesRegex(MonitoringContractError, "canonical identity"):
            replace(snapshot, snapshot_id="endpoint-state:" + "f" * 24).validate()

    def test_unknown_component_and_bounds_fail_closed(self):
        with self.assertRaisesRegex(MonitoringContractError, "unsupported"):
            EndpointStateComponent("raw_shell", SHA_A, 1).validate()
        with self.assertRaisesRegex(MonitoringContractError, "out of bounds"):
            EndpointStateComponent("services", SHA_A, -1).validate()


if __name__ == "__main__":
    unittest.main()
