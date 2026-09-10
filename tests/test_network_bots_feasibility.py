from __future__ import annotations

import ast
import inspect
import unittest

import three_agent.network_bots_feasibility as bots_module
from three_agent.network_bots_feasibility import (
    BLOCKED_DEPENDENCY_COST,
    BOTSFeasibilityError,
    BOTSFeasibilityProfile,
    PROFILE_SCHEMA,
    SUPPORTED_LIGHTWEIGHT,
    VERDICTS,
    evaluate_bots_v2_feasibility,
    official_bots_v2_profile,
    synthetic_lightweight_profile,
)

REQUIRED_OFFICIAL_BLOCKERS = {
    "PREINDEXED_VENDOR_FORMAT",
    "VENDOR_RUNTIME_REQUIRED",
    "SEPARATELY_LICENSED_ADDONS_REQUIRED",
    "NO_DOCUMENTED_VENDOR_FREE_EVENT_SCHEMA",
}


def _lightweight_dict() -> dict[str, object]:
    return synthetic_lightweight_profile().as_dict()


class BOTSFeasibilityVerdictTests(unittest.TestCase):
    def test_exact_two_verdicts(self):
        self.assertEqual(
            VERDICTS,
            frozenset({SUPPORTED_LIGHTWEIGHT, BLOCKED_DEPENDENCY_COST}),
        )

    def test_official_attack_only_fails_closed(self):
        profile = official_bots_v2_profile("attack-only")
        receipt = evaluate_bots_v2_feasibility(profile)
        self.assertEqual(receipt.verdict, BLOCKED_DEPENDENCY_COST)
        self.assertTrue(REQUIRED_OFFICIAL_BLOCKERS.issubset(receipt.blocker_codes))
        self.assertEqual(profile.reviewed_size, "3.2GB")

    def test_official_full_fails_closed(self):
        profile = official_bots_v2_profile("full")
        receipt = evaluate_bots_v2_feasibility(profile)
        self.assertEqual(receipt.verdict, BLOCKED_DEPENDENCY_COST)
        self.assertTrue(REQUIRED_OFFICIAL_BLOCKERS.issubset(receipt.blocker_codes))
        self.assertEqual(profile.reviewed_size, "16.4GB")

    def test_synthetic_documented_export_is_supported(self):
        receipt = evaluate_bots_v2_feasibility(synthetic_lightweight_profile())
        self.assertEqual(receipt.verdict, SUPPORTED_LIGHTWEIGHT)
        self.assertEqual(receipt.blocker_codes, ())

    def test_vendor_runtime_is_zero_tolerance_blocker(self):
        value = _lightweight_dict()
        value["vendor_runtime_required"] = True
        receipt = evaluate_bots_v2_feasibility(BOTSFeasibilityProfile.from_dict(value))
        self.assertIn("VENDOR_RUNTIME_REQUIRED", receipt.blocker_codes)

    def test_separate_addons_are_zero_tolerance_blocker(self):
        value = _lightweight_dict()
        value["separately_licensed_addons_required"] = True
        receipt = evaluate_bots_v2_feasibility(BOTSFeasibilityProfile.from_dict(value))
        self.assertIn("SEPARATELY_LICENSED_ADDONS_REQUIRED", receipt.blocker_codes)

    def test_undocumented_decoder_is_zero_tolerance_blocker(self):
        value = _lightweight_dict()
        value["undocumented_index_decoding_required"] = True
        receipt = evaluate_bots_v2_feasibility(BOTSFeasibilityProfile.from_dict(value))
        self.assertIn("UNDOCUMENTED_INDEX_DECODING_REQUIRED", receipt.blocker_codes)

    def test_missing_schema_is_zero_tolerance_blocker(self):
        value = _lightweight_dict()
        value["documented_vendor_free_event_schema"] = False
        receipt = evaluate_bots_v2_feasibility(BOTSFeasibilityProfile.from_dict(value))
        self.assertIn("NO_DOCUMENTED_VENDOR_FREE_EVENT_SCHEMA", receipt.blocker_codes)

    def test_network_service_is_zero_tolerance_blocker(self):
        value = _lightweight_dict()
        value["network_service_required"] = True
        receipt = evaluate_bots_v2_feasibility(BOTSFeasibilityProfile.from_dict(value))
        self.assertIn("NETWORK_SERVICE_REQUIRED_FOR_PARSE", receipt.blocker_codes)

    def test_unbounded_conversion_is_zero_tolerance_blocker(self):
        value = _lightweight_dict()
        value["bounded_conversion_possible"] = False
        receipt = evaluate_bots_v2_feasibility(BOTSFeasibilityProfile.from_dict(value))
        self.assertIn("UNBOUNDED_CONVERSION", receipt.blocker_codes)

    def test_missing_provenance_is_zero_tolerance_blocker(self):
        value = _lightweight_dict()
        value["source_to_derived_provenance_possible"] = False
        receipt = evaluate_bots_v2_feasibility(BOTSFeasibilityProfile.from_dict(value))
        self.assertIn("PROVENANCE_NOT_PRESERVABLE", receipt.blocker_codes)


class BOTSFeasibilityProfileTests(unittest.TestCase):
    def test_missing_material_field_fails_closed(self):
        value = _lightweight_dict()
        del value["documented_vendor_free_event_schema"]
        with self.assertRaises(BOTSFeasibilityError):
            BOTSFeasibilityProfile.from_dict(value)

    def test_unknown_field_fails_closed(self):
        value = _lightweight_dict()
        value["secret_override"] = True
        with self.assertRaises(BOTSFeasibilityError):
            BOTSFeasibilityProfile.from_dict(value)

    def test_model_inferred_source_fact_basis_is_rejected(self):
        value = _lightweight_dict()
        value["source_fact_basis"] = "model_inferred"
        with self.assertRaises(BOTSFeasibilityError):
            BOTSFeasibilityProfile.from_dict(value)

    def test_non_boolean_gate_value_is_rejected(self):
        value = _lightweight_dict()
        value["vendor_runtime_required"] = "false"
        with self.assertRaises(BOTSFeasibilityError):
            BOTSFeasibilityProfile.from_dict(value)

    def test_schema_version_is_exact(self):
        value = _lightweight_dict()
        value["schema_version"] = PROFILE_SCHEMA + "-future"
        with self.assertRaises(BOTSFeasibilityError):
            BOTSFeasibilityProfile.from_dict(value)

    def test_deterministic_profile_and_receipt_fingerprints(self):
        left = _lightweight_dict()
        right = dict(reversed(list(left.items())))
        p1 = BOTSFeasibilityProfile.from_dict(left)
        p2 = BOTSFeasibilityProfile.from_dict(right)
        r1 = evaluate_bots_v2_feasibility(p1)
        r2 = evaluate_bots_v2_feasibility(p2)
        self.assertEqual(p1.fingerprint, p2.fingerprint)
        self.assertEqual(r1.as_dict(), r2.as_dict())


class BOTSFeasibilityAuthorityTests(unittest.TestCase):
    def test_evaluator_has_no_network_model_subprocess_or_vendor_sdk_authority(self):
        tree = ast.parse(inspect.getsource(bots_module))
        forbidden_roots = {
            "requests",
            "urllib",
            "socket",
            "subprocess",
            "openai",
            "ollama",
            "splunklib",
            "splunk",
            "pip",
        }
        imported_roots: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])
        self.assertTrue(imported_roots.isdisjoint(forbidden_roots))

    def test_evaluator_does_not_open_or_download_corpus(self):
        tree = ast.parse(inspect.getsource(bots_module))
        forbidden_calls = {"open", "urlopen", "get", "post", "run", "Popen"}
        called: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name):
                called.add(func.id)
            elif isinstance(func, ast.Attribute):
                called.add(func.attr)
        self.assertTrue(called.isdisjoint(forbidden_calls))


if __name__ == "__main__":
    unittest.main()
