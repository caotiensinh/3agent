import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "evaluation" / "representative_hardware_closure_20260830.json"


class RepresentativeHardwareClosureTests(unittest.TestCase):
    def test_receipt_is_integrity_bound_metadata_only_no_go(self):
        payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
        self.assertEqual(
            payload["schema_version"],
            "workspace-representative-hardware-closure/v1",
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

        self.assertTrue(payload["benchmark"]["verification_passed"])
        self.assertEqual(
            payload["benchmark"]["promotion_eligible"],
            {
                "ranked-48k": False,
                "ranked-40k": False,
                "ranked-32k": False,
            },
        )
        self.assertEqual(payload["decisions"]["context_budget_promotion"], "NO_GO")
        self.assertEqual(
            payload["decisions"]["d5_05_progressive_expansion"],
            "KEEP_DISABLED",
        )

        observation = payload["d7_06_observation"]
        self.assertTrue(observation["observation_complete"])
        self.assertTrue(observation["structured_output_concurrency_passed"])
        self.assertEqual(observation["structured_output_attempted"], 8)
        self.assertEqual(observation["structured_output_succeeded"], 8)
        self.assertTrue(observation["execution_budget_concurrency_passed"])
        self.assertTrue(observation["reuse_opportunity_trust_isolation_passed"])
        self.assertFalse(observation["backend_cache_isolation_measured"])
        self.assertFalse(observation["backend_cache_hit_measured"])
        self.assertFalse(observation["resource_benefit_measured"])
        self.assertFalse(observation["gpu_active_time_measured"])
        self.assertFalse(observation["evaluator_attested"])
        self.assertFalse(observation["promotion_evidence_emitted"])
        self.assertEqual(
            payload["decisions"]["d7_06_promotion_evidence"],
            "NOT_ADMISSIBLE",
        )

        self.assertTrue(payload["privacy"])
        self.assertTrue(all(value is False for value in payload["privacy"].values()))
        raw = json.dumps(payload, ensure_ascii=False).casefold()
        for forbidden in (
            "raw_prompt\": true",
            "raw_model_output\": true",
            "raw_evidence\": true",
            "credentials_recorded\": true",
        ):
            self.assertNotIn(forbidden, raw)


if __name__ == "__main__":
    unittest.main()
