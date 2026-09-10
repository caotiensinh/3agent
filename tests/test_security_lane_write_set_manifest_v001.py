import unittest

from three_agent.security_monitoring.lane_write_set_manifest import (
    LaneWriteSet,
    LaneWriteSetError,
    ParallelLaneManifest,
)


class ParallelLaneManifestTests(unittest.TestCase):
    @staticmethod
    def _lanes():
        names = (
            ("L01", "feat/security-device-config-history-20260910", "device_config_history.py"),
            ("L02", "feat/security-observed-network-path-20260910", "observed_network_path.py"),
            ("L03", "feat/security-endpoint-state-snapshot-20260910", "endpoint_state_snapshot.py"),
            ("L04", "feat/security-rca-evidence-quorum-20260910", "rca_evidence_quorum.py"),
            ("L05", "feat/security-rca-uncertainty-20260910", "rca_uncertainty.py"),
            ("L06", "test/security-connectivity-rca-corpus-20260910", "connectivity_rca_cases.py"),
            ("L07", "feat/security-evidence-resource-budget-20260910", "evidence_resource_budget.py"),
            ("L08", "feat/security-evidence-privacy-receipt-20260910", "evidence_privacy_receipt.py"),
            ("L09", "chore/security-lane-write-set-manifest-20260910", "lane_write_set_manifest.py"),
            ("L10", "feat/security-release-transport-readiness-20260910", "release_transport_readiness.py"),
        )
        return tuple(
            LaneWriteSet(
                lane_id=lane_id,
                branch=branch,
                weight_percent=10,
                owned_paths=(f"src/three_agent/security_monitoring/{module}",),
                verifier=f"tests/test_{module.removesuffix('.py')}_v001.py",
            )
            for lane_id, branch, module in names
        )

    def test_exact_ten_lanes_total_one_hundred_percent(self):
        manifest = ParallelLaneManifest.build(self._lanes())
        self.assertEqual(len(manifest.lanes), 10)
        self.assertEqual(sum(row.weight_percent for row in manifest.lanes), 100)
        self.assertEqual(
            manifest.owner_of("src/three_agent/security_monitoring/observed_network_path.py"),
            "L02",
        )

    def test_duplicate_write_path_fails_closed(self):
        rows = list(self._lanes())
        rows[-1] = LaneWriteSet(
            lane_id="L10",
            branch="feat/security-release-transport-readiness-20260910",
            weight_percent=10,
            owned_paths=rows[0].owned_paths,
            verifier="tests/test_release_transport_readiness_v001.py",
        )
        with self.assertRaisesRegex(LaneWriteSetError, "write-set collision"):
            ParallelLaneManifest.build(rows)

    def test_wrong_lane_weight_fails_closed(self):
        rows = list(self._lanes())
        rows[4] = LaneWriteSet(
            lane_id="L05",
            branch="feat/security-rca-uncertainty-20260910",
            weight_percent=20,
            owned_paths=rows[4].owned_paths,
            verifier=rows[4].verifier,
        )
        with self.assertRaisesRegex(LaneWriteSetError, "exactly 10 percent"):
            ParallelLaneManifest.build(rows)

    def test_traversal_and_directory_ownership_are_rejected(self):
        with self.assertRaisesRegex(LaneWriteSetError, "repository-relative"):
            LaneWriteSet("L01", "branch", 10, ("../secret",), "test").validate()
        with self.assertRaisesRegex(LaneWriteSetError, "files, not directories"):
            LaneWriteSet("L01", "branch", 10, ("src/foo/",), "test").validate()


if __name__ == "__main__":
    unittest.main()
