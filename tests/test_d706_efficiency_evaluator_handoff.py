import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from three_agent.efficiency_evaluator_handoff import (
    SCHEMA,
    EfficiencyEvaluatorHandoffError,
    build_handoff,
    canonical_hash,
    validate_external_result,
    validate_handoff,
)
from three_agent.evaluation_profiles import (
    EvaluationProfile,
    EvaluationProfileError,
    EvaluationProfileResult,
    PROFILE_RESULT_SCHEMA,
    build_profile_promotion_evidence,
)
from three_agent.metric_registry import DEFAULT_METRIC_REGISTRY, METRIC_REGISTRY_ID

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "evaluation" / "efficiency_cache_concurrency_profile_v1.json"
BASELINE = "a" * 40
CANDIDATE = "b" * 40


def metrics(*, verified_rate=1.0, first_pass=1.0, verified_tasks=4, evidence=1.0):
    return {
        "verified_work": {
            "verified_task_success_rate": verified_rate,
            "first_pass_verified_success_rate": first_pass,
            "verified_tasks": verified_tasks,
        },
        "evidence_coverage": {"evidence_coverage": evidence},
    }


def benchmark_tuple(ref, *, quality=None):
    quality = quality or metrics()
    lineage = {
        "source_ref": ref,
        "task_scope_sha256": "sha256:" + "1" * 64,
        "configuration_sha256": "sha256:" + ("2" if ref == BASELINE else "3") * 64,
        "metrics_sha256": "sha256:" + ("4" if ref == BASELINE else "5") * 64,
        "metric_registry_sha256": DEFAULT_METRIC_REGISTRY.sha256,
    }
    binding = {
        "manifest_sha256": "sha256:" + ("6" if ref == BASELINE else "7") * 64,
        "metrics_sha256": lineage["metrics_sha256"],
        "task_scope_sha256": lineage["task_scope_sha256"],
        "configuration_sha256": lineage["configuration_sha256"],
    }
    return quality, lineage, binding


def observation(ref):
    return {
        "environment": {"model": "qwen3:30b"},
        "structured_output_concurrency": {"attempted": 8, "concurrency_requested": 4},
        "observation_sha256": "sha256:" + ("8" if ref == BASELINE else "9") * 64,
    }


def observation_prechecks():
    return {
        "structured_output_non_regression_observed": True,
        "execution_budget_concurrency_observed": True,
        "workspace_reuse_opportunity_isolation_observed": True,
        "backend_cache_isolation_measured": False,
        "backend_cache_hit_claimed": False,
    }


def resource(ref):
    base = ref == BASELINE
    return {
        "environment": {"model": "qwen3:30b"},
        "experiment": {
            "warmup_requests": 1,
            "samples_per_mode": 8,
            "serial_concurrency": 1,
            "candidate_concurrency": 4,
            "same_model": True,
            "same_prompt_template": True,
            "same_output_schema": True,
        },
        "comparison": {
            "serial_wall_duration_ms": 1000.0,
            "concurrent_wall_duration_ms": 500.0 if base else 450.0,
            "throughput_speedup": 2.0 if base else 2.222,
            "serial_total_tokens": 1000,
            "concurrent_total_tokens": 1000,
            "total_token_delta_pct": 0.0,
            "serial_utilization_weighted_gpu_seconds": 3.0,
            "concurrent_utilization_weighted_gpu_seconds": 2.0 if base else 1.8,
            "utilization_weighted_gpu_seconds_delta_pct": -33.3 if base else -40.0,
            "serial_estimated_energy_j": 1000.0,
            "concurrent_estimated_energy_j": 800.0 if base else 700.0,
            "estimated_energy_delta_pct": -20.0 if base else -30.0,
        },
        "claims": {
            "resource_benefit_measured": True,
            "gpu_utilization_weighted_time_measured": True,
            "gpu_active_time_measured": False,
            "backend_cache_isolation_measured": False,
            "backend_cache_hit_claimed": False,
            "evaluator_attested": False,
            "promotion_evidence_emitted": False,
        },
        "observation_sha256": "sha256:" + ("a" if base else "b") * 64,
    }


def build_fixture(profile, *, candidate_quality=None, candidate_resource=None):
    baseline_tuple = benchmark_tuple(BASELINE)
    candidate_tuple = benchmark_tuple(CANDIDATE, quality=candidate_quality)
    candidate_resource = candidate_resource or resource(CANDIDATE)
    with (
        patch("three_agent.efficiency_evaluator_handoff._benchmark", side_effect=[baseline_tuple, candidate_tuple]),
        patch(
            "three_agent.efficiency_evaluator_handoff._observation",
            side_effect=[
                (observation(BASELINE), observation_prechecks()),
                (observation(CANDIDATE), observation_prechecks()),
            ],
        ),
        patch(
            "three_agent.efficiency_evaluator_handoff._resource",
            side_effect=[resource(BASELINE), candidate_resource],
        ),
    ):
        return build_handoff(
            profile,
            baseline_ref=BASELINE,
            candidate_ref=CANDIDATE,
            baseline_benchmark=Path("baseline-benchmark.json"),
            candidate_benchmark=Path("candidate-benchmark.json"),
            baseline_observation=Path("baseline-observation.json"),
            candidate_observation=Path("candidate-observation.json"),
            baseline_resource=Path("baseline-resource.json"),
            candidate_resource=Path("candidate-resource.json"),
        )


def result_payload(profile, handoff):
    bindings = handoff["evidence_bindings"]
    cases = []
    for spec in profile.cases:
        contract = next(item for item in handoff["cases"] if item["case_id"] == spec.case_id)
        refs = {handoff["handoff_sha256"]}
        refs.update(bindings[key] for key in contract["required_local_bindings"])
        if spec.case_id == "cache-trust-domain-isolation":
            refs.add("external-cache-artifact:v1")
        cases.append({
            "case_id": spec.case_id,
            "checks": {check: True for check in spec.required_checks},
            "evidence_refs": sorted(refs),
        })
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
        "evaluator_ref": "external-evaluator:d706-v1",
        "label_commitment_sha256": None,
        "cases": cases,
    }


def load_result(payload):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "result.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return EvaluationProfileResult.load(path)


class D706EfficiencyEvaluatorHandoffTests(unittest.TestCase):
    def setUp(self):
        self.profile = EvaluationProfile.load(PROFILE_PATH)
        self.handoff = build_fixture(self.profile)

    def test_handoff_is_metadata_only_and_cache_honest(self):
        raw = json.dumps(self.handoff, ensure_ascii=False).lower()
        self.assertEqual(self.handoff["schema_version"], SCHEMA)
        self.assertEqual(self.handoff["baseline_ref"], BASELINE)
        self.assertEqual(self.handoff["candidate_ref"], CANDIDATE)
        self.assertTrue(self.handoff["deterministic_prechecks"]["resource_measurements_complete"])
        self.assertFalse(self.handoff["deterministic_prechecks"]["backend_cache_isolation_measured"])
        self.assertEqual(self.handoff["experiment"]["model"], "qwen3:30b")
        for forbidden in (
            "raw_prompt", "raw_response", "business_data", "hostname", "username",
            "ip_address", "gpu_uuid", "credentials", "holdout_labels",
        ):
            self.assertNotIn(forbidden, raw)

    def test_fixed_task_quality_regression_blocks_handoff(self):
        with self.assertRaisesRegex(EfficiencyEvaluatorHandoffError, "quality regression"):
            build_fixture(
                self.profile,
                candidate_quality=metrics(verified_rate=0.75, verified_tasks=3),
            )

    def test_resource_experiment_mismatch_blocks_handoff(self):
        changed = resource(CANDIDATE)
        changed["experiment"] = dict(changed["experiment"])
        changed["experiment"]["candidate_concurrency"] = 2
        with self.assertRaisesRegex(EfficiencyEvaluatorHandoffError, "experiments must be identical"):
            build_fixture(self.profile, candidate_resource=changed)

    def test_rehashed_local_cache_overclaim_still_fails(self):
        tampered = json.loads(json.dumps(self.handoff))
        tampered["deterministic_prechecks"]["backend_cache_isolation_measured"] = True
        unsigned = dict(tampered)
        unsigned.pop("handoff_sha256")
        tampered["handoff_sha256"] = canonical_hash(unsigned)
        with self.assertRaisesRegex(EfficiencyEvaluatorHandoffError, "cannot claim backend cache isolation"):
            validate_handoff(tampered, profile=self.profile)

    def test_unknown_raw_field_fails_closed(self):
        tampered = json.loads(json.dumps(self.handoff))
        tampered["raw_prompt"] = "CONFIDENTIAL"
        with self.assertRaisesRegex(EfficiencyEvaluatorHandoffError, "unsupported or missing"):
            validate_handoff(tampered, profile=self.profile)

    def test_external_result_must_reference_bound_evidence(self):
        payload = result_payload(self.profile, self.handoff)
        payload["cases"][0]["evidence_refs"] = [self.handoff["handoff_sha256"]]
        with self.assertRaisesRegex(EvaluationProfileError, "missing bound evidence"):
            validate_external_result(self.profile, self.handoff, load_result(payload))

    def test_local_reuse_receipt_cannot_prove_backend_cache_isolation(self):
        payload = result_payload(self.profile, self.handoff)
        cache = next(row for row in payload["cases"] if row["case_id"] == "cache-trust-domain-isolation")
        cache["evidence_refs"] = [self.handoff["handoff_sha256"]]
        with self.assertRaisesRegex(EvaluationProfileError, "independent external evidence"):
            validate_external_result(self.profile, self.handoff, load_result(payload))

    def test_efficiency_result_must_not_attach_holdout_commitment(self):
        payload = result_payload(self.profile, self.handoff)
        payload["label_commitment_sha256"] = "sha256:" + "c" * 64
        with self.assertRaisesRegex(EvaluationProfileError, "must not attach holdout"):
            validate_external_result(self.profile, self.handoff, load_result(payload))

    def test_wrong_git_lineage_is_rejected(self):
        payload = result_payload(self.profile, self.handoff)
        payload["candidate_ref"] = "c" * 40
        with self.assertRaisesRegex(EvaluationProfileError, "candidate_ref"):
            validate_external_result(self.profile, self.handoff, load_result(payload))

    def test_exact_required_check_set_is_enforced(self):
        payload = result_payload(self.profile, self.handoff)
        payload["cases"][0]["checks"]["EXTRA_UNBOUND_CHECK"] = True
        with self.assertRaisesRegex(EvaluationProfileError, "required checks invalid"):
            validate_external_result(self.profile, self.handoff, load_result(payload))

    def test_valid_external_result_enters_existing_promotion_adapter(self):
        admitted = validate_external_result(
            self.profile, self.handoff, load_result(result_payload(self.profile, self.handoff))
        )
        evidence = build_profile_promotion_evidence(
            self.profile, admitted, evidence_id="d706-external-evaluation"
        ).to_payload()
        self.assertEqual(evidence["corpus_class"], "efficiency_cache_concurrency")
        self.assertEqual(evidence["baseline_ref"], BASELINE)
        self.assertEqual(evidence["candidate_ref"], CANDIDATE)
        self.assertTrue(evidence["evaluator_attested"])
        self.assertIsNone(evidence["label_commitment_sha256"])
        self.assertIn(self.handoff["handoff_sha256"], evidence["evidence_refs"])


if __name__ == "__main__":
    unittest.main()
