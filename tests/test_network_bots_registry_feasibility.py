from __future__ import annotations

import json
import unittest
from pathlib import Path

from three_agent.network_bots_feasibility import (
    BLOCKED_DEPENDENCY_COST,
    evaluate_bots_v2_feasibility,
    official_bots_v2_profile,
)

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "config/network-datasets.registry.json"
EXPECTED_SPEC = "docs/WORKSPACE_NETWORK_V3_02D_BOTS_V2_FEASIBILITY_SPEC_V1.md"
EXPECTED_EVALUATOR_VERSION = "bots-v2-feasibility/0.1"


def _bots_record() -> dict:
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    matches = [
        item for item in registry["datasets"] if item.get("id") == "splunk-bots-v2"
    ]
    if len(matches) != 1:
        raise AssertionError("registry must contain exactly one splunk-bots-v2 record")
    return matches[0]


class BOTSRegistryFeasibilityTests(unittest.TestCase):
    def test_license_eligibility_is_separate_from_runtime_feasibility(self):
        record = _bots_record()
        feasibility = record["runtime_feasibility"]

        self.assertEqual(record["status"], "enterprise_approved")
        self.assertIs(record["license"]["commercial_use"], True)
        self.assertEqual(feasibility["verdict"], BLOCKED_DEPENDENCY_COST)
        self.assertIs(feasibility["direct_adapter_authorized"], False)
        self.assertIs(
            feasibility["future_derived_export_requires_separate_review"], True
        )

    def test_registry_verdict_is_bound_to_reviewed_spec_and_evaluator(self):
        feasibility = _bots_record()["runtime_feasibility"]
        self.assertEqual(feasibility["spec"], EXPECTED_SPEC)
        self.assertEqual(
            feasibility["evaluator_version"], EXPECTED_EVALUATOR_VERSION
        )

    def test_attack_only_registry_evidence_matches_deterministic_evaluator(self):
        feasibility = _bots_record()["runtime_feasibility"]
        profile = official_bots_v2_profile("attack-only")
        receipt = evaluate_bots_v2_feasibility(profile)

        self.assertEqual(receipt.verdict, BLOCKED_DEPENDENCY_COST)
        self.assertEqual(
            feasibility["attack_only_profile_fingerprint"], profile.fingerprint
        )
        self.assertEqual(
            feasibility["attack_only_receipt_fingerprint"],
            receipt.receipt_fingerprint,
        )
        self.assertEqual(
            feasibility["blocker_codes"], list(receipt.blocker_codes)
        )

    def test_full_registry_evidence_matches_deterministic_evaluator(self):
        feasibility = _bots_record()["runtime_feasibility"]
        profile = official_bots_v2_profile("full")
        receipt = evaluate_bots_v2_feasibility(profile)

        self.assertEqual(receipt.verdict, BLOCKED_DEPENDENCY_COST)
        self.assertEqual(feasibility["full_profile_fingerprint"], profile.fingerprint)
        self.assertEqual(
            feasibility["full_receipt_fingerprint"], receipt.receipt_fingerprint
        )
        self.assertEqual(
            feasibility["blocker_codes"], list(receipt.blocker_codes)
        )

    def test_registry_does_not_claim_direct_bots_parser_support(self):
        record = _bots_record()
        feasibility = record["runtime_feasibility"]
        notes = str(record.get("notes", "")).casefold()

        self.assertFalse(feasibility["direct_adapter_authorized"])
        self.assertIn("not authorized for direct workspace parsing", notes)
        self.assertIn("separate", notes)
        self.assertIn("review", notes)


if __name__ == "__main__":
    unittest.main()
