from __future__ import annotations

import json
import unittest
from pathlib import Path

from three_agent.network_eval_harness import (
    CorpusManifest,
    NetworkHarnessError,
    build_specialist_input,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "evaluation" / "network_specialist_fixture_manifest_v1.json"


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class NetworkEvalHarnessTests(unittest.TestCase):
    def test_fixture_manifest_loads_and_fingerprints(self):
        manifest = CorpusManifest.from_dict(load_fixture())
        self.assertEqual(len(manifest.cases), 4)
        self.assertTrue(manifest.fingerprint().startswith("sha256:"))

    def test_specialist_visible_case_excludes_case_class_and_hidden_truth(self):
        manifest = CorpusManifest.from_dict(load_fixture())
        visible = manifest.visible_case("fixture-intrusion-positive-001")
        self.assertNotIn("case_class", visible)
        self.assertNotIn("hidden_ground_truth_ref", visible)
        self.assertNotIn("dataset_status", visible)
        self.assertEqual(visible["specialist_target"], "intrusion-trace-hunting")

    def test_scorer_contract_contains_hidden_labels_separately(self):
        manifest = CorpusManifest.from_dict(load_fixture())
        scorer = manifest.scorer_case("fixture-intrusion-positive-001")
        self.assertEqual(scorer["case_class"], "positive")
        self.assertTrue(scorer["hidden_ground_truth_ref"].startswith("hidden-truth/"))
        self.assertNotIn("visible_evidence_refs", scorer)

    def test_specialist_input_rejects_ground_truth_fields_inside_evidence(self):
        manifest = CorpusManifest.from_dict(load_fixture())
        case = manifest.cases[0]
        evidence = {
            "e-auth-001": {
                "observation": "remote authentication observed",
                "expected_attack_path": "hidden answer",
            },
            "e-flow-001": {"observation": "network flow observed"},
        }
        with self.assertRaises(NetworkHarnessError):
            build_specialist_input(case, evidence)

    def test_specialist_input_rejects_out_of_case_evidence(self):
        manifest = CorpusManifest.from_dict(load_fixture())
        case = manifest.cases[0]
        evidence = {
            "e-auth-001": {"observation": "remote authentication observed"},
            "e-flow-001": {"observation": "network flow observed"},
            "e-secret-extra": {"observation": "must never be supplied"},
        }
        with self.assertRaises(NetworkHarnessError):
            build_specialist_input(case, evidence)

    def test_research_only_dataset_cannot_enter_promotion_evaluation_manifest(self):
        payload = load_fixture()
        payload["cases"][0]["dataset_status"] = "research_only"
        with self.assertRaises(NetworkHarnessError):
            CorpusManifest.from_dict(payload)

    def test_hidden_truth_ref_cannot_overlap_visible_evidence(self):
        payload = load_fixture()
        payload["cases"][0]["hidden_ground_truth_ref"] = "e-auth-001"
        with self.assertRaises(NetworkHarnessError):
            CorpusManifest.from_dict(payload)

    def test_duplicate_case_ids_are_rejected(self):
        payload = load_fixture()
        payload["cases"][1]["case_id"] = payload["cases"][0]["case_id"]
        with self.assertRaises(NetworkHarnessError):
            CorpusManifest.from_dict(payload)

    def test_holdout_requires_at_least_twenty_five_percent_non_positive_cases(self):
        payload = load_fixture()
        payload["purpose"] = "holdout"
        for case in payload["cases"]:
            case["case_class"] = "positive"
        with self.assertRaises(NetworkHarnessError):
            CorpusManifest.from_dict(payload)

    def test_valid_specialist_input_contains_only_visible_evidence(self):
        manifest = CorpusManifest.from_dict(load_fixture())
        case = manifest.cases[0]
        evidence = {
            "e-auth-001": {"observation": "remote authentication observed"},
            "e-flow-001": {"observation": "network flow observed"},
        }
        visible = build_specialist_input(case, evidence)
        self.assertEqual(
            [item["evidence_id"] for item in visible["evidence"]],
            ["e-auth-001", "e-flow-001"],
        )
        self.assertNotIn("case_class", visible)
        self.assertNotIn("hidden_ground_truth_ref", visible)


if __name__ == "__main__":
    unittest.main()
