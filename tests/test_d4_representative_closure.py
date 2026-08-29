import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "evaluation" / "d4_representative_closure_20260830.json"


class D4RepresentativeClosureTests(unittest.TestCase):
    def test_receipt_is_integrity_bound_and_d9_remains_blocked(self):
        payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
        self.assertEqual(
            payload["schema_version"],
            "workspace-d4-representative-closure/v1",
        )
        claimed = payload.pop("closure_sha256")
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(
            claimed,
            "sha256:" + hashlib.sha256(canonical).hexdigest(),
        )

        observation = payload["observation"]
        self.assertEqual(observation["decision"], "INSUFFICIENT_REPRESENTATIVE_DATA")
        self.assertEqual(observation["allowed_action"], "collect_more_metadata")
        self.assertEqual(observation["eligible_events"], 0)
        self.assertEqual(observation["telemetry_discovery"], "not-found")
        self.assertFalse(observation["production_serving_change_authorized"])
        self.assertFalse(observation["backend_cache_hit_claimed"])
        self.assertFalse(observation["raw_telemetry_uploaded"])

        decisions = payload["decisions"]
        self.assertEqual(decisions["d9_serving_cache_benchmark"], "NOT_ELIGIBLE")
        self.assertEqual(decisions["production_serving_change"], "NOT_AUTHORIZED")
        self.assertEqual(decisions["next_action"], "COLLECT_REAL_WORKLOAD_METADATA")
        self.assertEqual(decisions["synthetic_workload_substitution"], "FORBIDDEN")

        self.assertTrue(payload["privacy"])
        self.assertTrue(all(value is False for value in payload["privacy"].values()))


if __name__ == "__main__":
    unittest.main()
