import unittest
from dataclasses import replace

from three_agent.security_monitoring.lane_write_set_manifest import (
    CURRENT_PARALLEL_LANE_MANIFEST,
    LaneWriteSet,
    LaneWriteSetError,
    ParallelLaneManifest,
)


class ParallelLaneManifestTests(unittest.TestCase):
    @staticmethod
    def _lanes():
        return CURRENT_PARALLEL_LANE_MANIFEST.lanes

    def test_current_manifest_matches_real_parallel_write_sets(self):
        manifest = CURRENT_PARALLEL_LANE_MANIFEST.validate()
        self.assertEqual(tuple(row.lane_id for row in manifest.lanes), tuple(f"L{i:02d}" for i in range(1, 11)))
        self.assertEqual(sum(row.weight_percent for row in manifest.lanes), 100)
        all_paths = [path for lane in manifest.lanes for path in lane.owned_paths]
        self.assertEqual(len(all_paths), 24)
        self.assertEqual(len(set(all_paths)), 24)
        self.assertEqual(
            manifest.owner_of(".github/workflows/security-normalized-evidence-cross-platform.yml"),
            "L01",
        )
        self.assertEqual(
            manifest.owner_of("src/three_agent/security_monitoring/observed_network_path.py"),
            "L02",
        )
        self.assertEqual(
            manifest.owner_of("tests/test_security_lane_write_set_manifest_v001.py"),
            "L09",
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
        owned_without_verifier = tuple(path for path in lane.owned_paths if path != lane.verifier)
        with self.assertRaisesRegex(LaneWriteSetError, "repository-relative"):
            replace(lane, owned_paths=("../secret", lane.verifier)).validate()
        with self.assertRaisesRegex(LaneWriteSetError, "files, not directories"):
            replace(lane, owned_paths=("src/foo/", lane.verifier)).validate()
        with self.assertRaisesRegex(LaneWriteSetError, "git"):
            replace(lane, owned_paths=(".git/config", lane.verifier)).validate()
        self.assertGreater(len(owned_without_verifier), 0)


if __name__ == "__main__":
    unittest.main()
