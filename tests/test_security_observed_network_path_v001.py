import unittest
from dataclasses import replace

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.observed_network_path import ObservedNetworkPath, ObservedPathHop

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
SHA_D = "sha256:" + "d" * 64


class ObservedNetworkPathTests(unittest.TestCase):
    def _path(self):
        return ObservedNetworkPath.build(
            asset_id="asset:camera-gateway-01",
            destination_ref="asset:core-router-01",
            captured_at="2026-09-10T03:00:00+00:00",
            producer="reviewed-route-import",
            task_ref_sha256=SHA_A,
            authorization_ref_sha256=SHA_B,
            source_record_sha256=SHA_C,
            hops=(ObservedPathHop(1, SHA_C, 1.2), ObservedPathHop(2, SHA_D, 2.8)),
        )

    def test_deterministic_metadata_only_path(self):
        first = self._path()
        second = self._path()
        self.assertEqual(first.observation_id, second.observation_id)
        self.assertEqual(first.identity_sha256, second.identity_sha256)
        payload = first.identity_dict()
        self.assertEqual(payload["authority"], "evidence_only")
        self.assertFalse(payload["acquisition_performed"])
        self.assertFalse(payload["raw_output_retained"])
        self.assertNotIn("command", payload)
        self.assertNotIn("credential", payload)

    def test_non_contiguous_hops_fail_closed(self):
        with self.assertRaisesRegex(MonitoringContractError, "contiguous"):
            ObservedNetworkPath.build(
                asset_id="asset:a", destination_ref="asset:b",
                captured_at="2026-09-10T03:00:00+00:00", producer="import",
                task_ref_sha256=SHA_A, authorization_ref_sha256=SHA_B,
                source_record_sha256=SHA_C,
                hops=(ObservedPathHop(1, SHA_C), ObservedPathHop(3, SHA_D)),
            )

    def test_tampered_id_and_authority_fail_closed(self):
        path = self._path()
        with self.assertRaisesRegex(MonitoringContractError, "canonical identity"):
            replace(path, observation_id="observed-path:" + "f" * 24).validate()
        with self.assertRaisesRegex(MonitoringContractError, "broaden"):
            replace(path, acquisition_performed=True).validate()

    def test_hash_and_latency_bounds_fail_closed(self):
        with self.assertRaisesRegex(MonitoringContractError, "responder_sha256"):
            ObservedPathHop(1, "bad", 1.0).validate()
        with self.assertRaisesRegex(MonitoringContractError, "out of bounds"):
            ObservedPathHop(1, SHA_A, 999999.0).validate()


if __name__ == "__main__":
    unittest.main()
