import unittest
from dataclasses import replace

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
        rows = []
        for lane_id, branch, module in names:
            verifier = f"tests/test_security_{module.removesuffix('.py')}_v001.py"
            source = f"src/three_agent/security_monitoring/{module}"
            rows.append(
                LaneWriteSet(
                    lane_id=lane_id,
                    branch=branch,
                    weight_percent=10,
                    owned_paths=(source, verifier),
                    verifier=verifier,
                )
            )
        return tuple(rows)

    def test_exact_ten_lanes_total_one_hundred_percent(self):
        manifest = ParallelLaneManifest.build(self._lanes())
        self.assertEqual(tuple(row.lane_id for row in manifest.lanes), tuple(f"L{i:02d}" for i in range(1, 11)))
        self.assertEqual(sum(row.weight_percent for row in manifest.lanes), 100)
        self.assertEqual(
            manifest.owner_of("src/three_agent/security_monitoring/observed_network_path.py"),
            "L02",
        )
        self.assertEqual(
            manifest.owner_of("tests/test_security_observed_network_path_v001.py"),
            "L02",
        )

    def test_duplicate_write_path_fails_closed(self):
        rows = list(self._lanes())
        rows[-1] = replace(
            rows[-1],
            owned_paths=(rows[0].owned_paths[0], rows[-1].verifier),
        )
        with self.assertRaisesRegex(LaneWriteSetError, "write-set collision"):
            ParallelLaneManifest.build(rows)

    def test_wrong_lane_weight_type_or_value_fails_closed(self):
        rows = list(self._lanes())
        with self.assertRaisesRegex(LaneWriteSetError, "exactly 10 percent"):
            replace(rows[4], weight_percent=20).validate()
        with self.assertRaisesRegex(LaneWriteSetError, "exactly 10 percent"):
            replace(rows[4], weight_percent=10.0).validate()  # type: ignore[arg-type]

    def test_noncanonical_path_cannot_evade_collision(self):
        lane = self._lanes()[0]
        with self.assertRaisesRegex(LaneWriteSetError, "canonical"):
            replace(
                lane,
                owned_paths=("src/three_agent/security_monitoring/./device_config_history.py", lane.verifier),
            ).validate()
        with self.assertRaisesRegex(LaneWriteSetError, "canonical"):
            replace(
                lane,
                owned_paths=("src/three_agent//security_monitoring/device_config_history.py", lane.verifier),
            ).validate()

    def test_verifier_must_be_owned_by_lane(self):
        lane = self._lanes()[0]
        with self.assertRaisesRegex(LaneWriteSetError, "verifier"):
            replace(lane, owned_paths=(lane.owned_paths[0],)).validate()

    def test_duplicate_branch_after_normalization_fails_closed(self):
        rows = list(self._lanes())
        rows[-1] = replace(rows[-1], branch=f" {rows[0].branch} ")
        with self.assertRaisesRegex(LaneWriteSetError, "duplicate lane branch"):
            ParallelLaneManifest.build(rows)

    def test_lane_ids_must_be_exactly_l01_through_l10(self):
        rows = list(self._lanes())
        rows[-1] = replace(rows[-1], lane_id="L11")
        with self.assertRaisesRegex(LaneWriteSetError, "L01 through L10"):
            ParallelLaneManifest.build(rows)

    def test_traversal_git_and_directory_ownership_are_rejected(self):
        lane = self._lanes()[0]
        with self.assertRaisesRegex(LaneWriteSetError, "repository-relative"):
            replace(lane, owned_paths=("../secret", lane.verifier)).validate()
        with self.assertRaisesRegex(LaneWriteSetError, "files, not directories"):
            replace(lane, owned_paths=("src/foo/", lane.verifier)).validate()
        with self.assertRaisesRegex(LaneWriteSetError, "git"):
            replace(lane, owned_paths=(".git/config", lane.verifier)).validate()


if __name__ == "__main__":
    unittest.main()
