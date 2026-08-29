import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from three_agent.evaluation_profiles import (
    EvaluationProfile,
    EvaluationProfileError,
    EvaluationProfileResult,
    PROFILE_RESULT_SCHEMA,
    build_profile_promotion_evidence,
)
from three_agent.metric_registry import DEFAULT_METRIC_REGISTRY, METRIC_REGISTRY_ID
from three_agent.promotion_gate import PromotionPolicy


ROOT = Path(__file__).resolve().parents[1]
EDGE = ROOT / "evaluation" / "edge_large_context_profile_v1.json"
EFFICIENCY = ROOT / "evaluation" / "efficiency_cache_concurrency_profile_v1.json"
POLICY = ROOT / "evaluation" / "promotion_policy_v1.json"
BASELINE = "a" * 40
CANDIDATE = "b" * 40


def _sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def result_payload(profile: EvaluationProfile, *, label_commitment=None) -> dict:
    return {
        "schema_version": PROFILE_RESULT_SCHEMA,
        "profile_id": profile.profile_id,
        "profile_sha256": profile.sha256,
        "corpus_class": profile.corpus_class,
        "metric_registry_id": METRIC_REGISTRY_ID,
        "metric_registry_sha256": DEFAULT_METRIC_REGISTRY.sha256,
        "baseline_ref": BASELINE,
        "candidate_ref": CANDIDATE,
        "security_passed": True,
        "evaluator_attested": True,
        "evaluator_ref": f"evaluator:{profile.corpus_class}:v1",
        "label_commitment_sha256": label_commitment,
        "cases": [
            {
                "case_id": case.case_id,
                "checks": {check: True for check in case.required_checks},
                "evidence_refs": [f"artifact:{case.case_id}:v1"],
            }
            for case in profile.cases
        ],
    }


def load_result(payload: dict) -> EvaluationProfileResult:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "result.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return EvaluationProfileResult.load(path)


class EvaluationProfileTests(unittest.TestCase):
    def test_repository_profiles_are_versioned_metadata_only_optimizer_views(self):
        edge = EvaluationProfile.load(EDGE)
        efficiency = EvaluationProfile.load(EFFICIENCY)
        self.assertEqual(edge.corpus_class, "edge_large_context")
        self.assertEqual(efficiency.corpus_class, "efficiency_cache_concurrency")
        self.assertTrue(edge.holdout_labels_external)
        self.assertFalse(efficiency.holdout_labels_external)
        for profile in (edge, efficiency):
            view = profile.optimizer_view()
            raw = json.dumps(view, ensure_ascii=False)
            self.assertTrue(view["profile_sha256"].startswith("sha256:"))
            self.assertFalse(view["holdout_labels_embedded"])
            self.assertFalse(view["holdout_label_commitment_embedded"])
            self.assertNotIn("label_commitment_sha256", raw)
            self.assertNotIn("expected_answer", raw)

    def test_profile_hash_is_stable_and_changes_when_case_contract_changes(self):
        first = EvaluationProfile.load(EDGE)
        second = EvaluationProfile.load(EDGE)
        self.assertEqual(first.sha256, second.sha256)
        payload = json.loads(EDGE.read_text(encoding="utf-8"))
        payload["cases"][0]["dimensions"].append("changed-contract")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "changed.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            changed = EvaluationProfile.load(path)
        self.assertNotEqual(first.sha256, changed.sha256)

    def test_edge_result_requires_external_label_commitment(self):
        profile = EvaluationProfile.load(EDGE)
        result = load_result(result_payload(profile, label_commitment=None))
        with self.assertRaisesRegex(EvaluationProfileError, "label commitment"):
            build_profile_promotion_evidence(profile, result, evidence_id="edge-evidence")

    def test_efficiency_result_rejects_holdout_label_commitment(self):
        profile = EvaluationProfile.load(EFFICIENCY)
        result = load_result(result_payload(profile, label_commitment=_sha("labels")))
        with self.assertRaisesRegex(EvaluationProfileError, "must not attach"):
            build_profile_promotion_evidence(
                profile, result, evidence_id="efficiency-evidence"
            )

    def test_exact_case_set_and_required_checks_fail_closed(self):
        profile = EvaluationProfile.load(EDGE)
        payload = result_payload(profile, label_commitment=_sha("edge-labels"))
        payload["cases"].pop()
        result = load_result(payload)
        with self.assertRaisesRegex(EvaluationProfileError, "case set"):
            build_profile_promotion_evidence(profile, result, evidence_id="edge-evidence")

        payload = result_payload(profile, label_commitment=_sha("edge-labels"))
        first_check = next(iter(payload["cases"][0]["checks"]))
        payload["cases"][0]["checks"][first_check] = False
        result = load_result(payload)
        with self.assertRaisesRegex(EvaluationProfileError, "required profile check failed"):
            build_profile_promotion_evidence(profile, result, evidence_id="edge-evidence")

    def test_profile_lineage_and_metric_registry_are_hard_bound(self):
        profile = EvaluationProfile.load(EDGE)
        payload = result_payload(profile, label_commitment=_sha("edge-labels"))
        payload["profile_sha256"] = "sha256:" + "0" * 64
        result = load_result(payload)
        with self.assertRaisesRegex(EvaluationProfileError, "profile lineage"):
            build_profile_promotion_evidence(profile, result, evidence_id="edge-evidence")

        payload = result_payload(profile, label_commitment=_sha("edge-labels"))
        payload["metric_registry_sha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(EvaluationProfileError, "fingerprint mismatch"):
            load_result(payload)

    def test_unknown_result_fields_cannot_smuggle_raw_content(self):
        profile = EvaluationProfile.load(EDGE)
        payload = result_payload(profile, label_commitment=_sha("edge-labels"))
        payload["raw_prompt"] = "CONFIDENTIAL BUSINESS TEXT"
        with self.assertRaisesRegex(EvaluationProfileError, "unsupported fields"):
            load_result(payload)

    def test_valid_profile_results_emit_promotion_evidence_for_current_policy(self):
        policy = PromotionPolicy.load(POLICY)
        specs = policy.by_id()
        for path, commitment in (
            (EDGE, _sha("edge-labels")),
            (EFFICIENCY, None),
        ):
            profile = EvaluationProfile.load(path)
            result = load_result(result_payload(profile, label_commitment=commitment))
            evidence = build_profile_promotion_evidence(
                profile,
                result,
                evidence_id=f"{profile.corpus_class}-evidence",
            )
            self.assertEqual(evidence.corpus_id, profile.profile_id)
            self.assertEqual(evidence.corpus_sha256, profile.sha256)
            self.assertEqual(evidence.metric_registry_sha256, DEFAULT_METRIC_REGISTRY.sha256)
            self.assertTrue(evidence.evaluator_attested)
            self.assertTrue(evidence.security_passed)
            self.assertTrue(
                set(specs[profile.corpus_class].required_checks).issubset(evidence.checks)
            )
            raw = json.dumps(evidence.to_payload(), ensure_ascii=False)
            self.assertNotIn("dimensions", raw)
            self.assertNotIn("raw_prompt", raw)
            self.assertNotIn("expected_answer", raw)


if __name__ == "__main__":
    unittest.main()
