import inspect
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import three_agent.security_monitoring.advanced_benchmark as advanced_benchmark
from three_agent.security_monitoring.advanced_benchmark import (
    BenchmarkAdmissionPolicy,
    DetectorMetrics,
    benchmark_fingerprint,
    evaluate_candidate,
    load_fixed_benchmark,
    result_to_json,
    run_advanced_benchmark,
)
from three_agent.security_monitoring.contracts import MonitoringContractError


FIXTURE = Path(__file__).parent / "fixtures" / "security_monitoring" / "anomaly_benchmark.json"


def metrics(
    detector_id: str,
    *,
    detection: float,
    false_positive: float,
    dependencies: int = 0,
    complexity: int = 2,
    security: int = 0,
    llm_calls: int = 0,
) -> DetectorMetrics:
    return DetectorMetrics(
        detector_id=detector_id,
        case_count=20,
        true_positives=9,
        false_positives=1,
        true_negatives=9,
        false_negatives=1,
        detection_rate=detection,
        false_positive_rate=false_positive,
        wall_ms=10.0,
        cpu_ms=8.0,
        peak_allocated_bytes=128 * 1024,
        state_bytes=32 * 1024,
        external_dependencies=dependencies,
        complexity_points=complexity,
        security_risk_points=security,
        llm_calls=llm_calls,
    )


class FixedAdvancedBenchmarkTests(unittest.TestCase):
    def test_fixed_fixture_is_strict_stable_and_contains_both_classes(self):
        cases = load_fixed_benchmark(FIXTURE)
        self.assertEqual(len(cases), 10)
        self.assertEqual(len({case.case_id for case in cases}), 10)
        self.assertTrue(any(case.expected_anomaly for case in cases))
        self.assertTrue(any(not case.expected_anomaly for case in cases))
        first = benchmark_fingerprint(cases)
        second = benchmark_fingerprint(load_fixed_benchmark(FIXTURE))
        self.assertEqual(first, second)
        self.assertRegex(first, r"^sha256:[0-9a-f]{64}$")

    def test_fixed_baseline_vs_knn_records_quality_and_resource_cost_then_rejects_no_gain(self):
        result = run_advanced_benchmark(load_fixed_benchmark(FIXTURE))
        self.assertEqual(result.baseline.detector_id, "median-mad-v1")
        self.assertEqual(result.candidate.detector_id, "knn-distance-v1")
        self.assertIsNotNone(result.detection_gain)
        self.assertIsNotNone(result.false_positive_delta)
        self.assertGreaterEqual(result.baseline.wall_ms, 0.0)
        self.assertGreaterEqual(result.candidate.wall_ms, 0.0)
        self.assertGreaterEqual(result.baseline.cpu_ms, 0.0)
        self.assertGreaterEqual(result.candidate.cpu_ms, 0.0)
        self.assertGreater(result.baseline.peak_allocated_bytes, 0)
        self.assertGreater(result.candidate.peak_allocated_bytes, 0)
        self.assertGreater(result.baseline.state_bytes, 0)
        self.assertGreater(result.candidate.state_bytes, 0)
        self.assertEqual(result.baseline.llm_calls, 0)
        self.assertEqual(result.candidate.llm_calls, 0)
        self.assertEqual(result.candidate.external_dependencies, 0)
        self.assertFalse(result.production_promotion_authorized)
        self.assertEqual(result.decision, "REJECT_ML_PATH")
        self.assertFalse(result.benchmark_gate_passed)
        self.assertIn("NET_BENEFIT_NOT_PROVEN", result.reason_codes)
        self.assertIn("USEFUL_DETECTION_GAIN_NOT_PROVEN", result.reason_codes)
        rendered = result_to_json(result)
        self.assertNotIn("192.168.", rendered)
        self.assertNotIn("raw_log", rendered)

    def test_fixture_rejects_unknown_fields_duplicate_ids_and_nonfinite_numbers(self):
        original = json.loads(FIXTURE.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            unknown = json.loads(json.dumps(original))
            unknown["cases"][0]["extra"] = "not-allowed"
            path.write_text(json.dumps(unknown), encoding="utf-8")
            with self.assertRaises(MonitoringContractError):
                load_fixed_benchmark(path)

            duplicate = json.loads(json.dumps(original))
            duplicate["cases"][1]["case_id"] = duplicate["cases"][0]["case_id"]
            path.write_text(json.dumps(duplicate), encoding="utf-8")
            with self.assertRaises(MonitoringContractError):
                load_fixed_benchmark(path)

            nonfinite = json.loads(json.dumps(original))
            nonfinite["cases"][0]["current_value"] = float("inf")
            path.write_text(json.dumps(nonfinite, allow_nan=True), encoding="utf-8")
            with self.assertRaises(MonitoringContractError):
                load_fixed_benchmark(path)


class AdvancedAdmissionGateTests(unittest.TestCase):
    def test_clear_quality_gain_can_only_become_eligible_for_review_not_self_promoted(self):
        baseline = metrics("baseline", detection=0.70, false_positive=0.10, complexity=1)
        candidate = metrics("candidate", detection=0.90, false_positive=0.10)
        result = evaluate_candidate(
            dataset_fingerprint="sha256:" + "a" * 64,
            baseline=baseline,
            candidate=candidate,
        )
        self.assertTrue(result.benchmark_gate_passed)
        self.assertEqual(result.decision, "ELIGIBLE_FOR_REVIEW")
        self.assertEqual(result.reason_codes, ())
        self.assertGreater(result.benefit_score, result.cost_score)
        self.assertFalse(result.production_promotion_authorized)

    def test_false_positive_dependency_security_or_llm_cost_blocks_candidate(self):
        baseline = metrics("baseline", detection=0.60, false_positive=0.05, complexity=1)
        candidate = metrics(
            "candidate",
            detection=0.90,
            false_positive=0.10,
            dependencies=1,
            security=1,
            llm_calls=1,
        )
        result = evaluate_candidate(
            dataset_fingerprint="sha256:" + "b" * 64,
            baseline=baseline,
            candidate=candidate,
        )
        self.assertFalse(result.benchmark_gate_passed)
        self.assertIn("FALSE_POSITIVE_REGRESSION", result.reason_codes)
        self.assertIn("DEPENDENCY_BUDGET_EXCEEDED", result.reason_codes)
        self.assertIn("SECURITY_COST_EXCEEDED", result.reason_codes)
        self.assertIn("LLM_CALLS_NOT_ALLOWED_IN_ANOMALY_DETECTOR", result.reason_codes)
        self.assertFalse(result.production_promotion_authorized)

    def test_resource_or_complexity_over_budget_blocks_even_with_detection_gain(self):
        baseline = metrics("baseline", detection=0.60, false_positive=0.05, complexity=1)
        candidate = replace(
            metrics("candidate", detection=0.90, false_positive=0.05),
            wall_ms=2000.0,
            cpu_ms=2000.0,
            peak_allocated_bytes=16 * 1024 * 1024,
            state_bytes=4 * 1024 * 1024,
            complexity_points=4,
        )
        result = evaluate_candidate(
            dataset_fingerprint="sha256:" + "c" * 64,
            baseline=baseline,
            candidate=candidate,
            policy=BenchmarkAdmissionPolicy(),
        )
        self.assertFalse(result.benchmark_gate_passed)
        self.assertIn("WALL_LATENCY_BUDGET_EXCEEDED", result.reason_codes)
        self.assertIn("CPU_BUDGET_EXCEEDED", result.reason_codes)
        self.assertIn("RAM_BUDGET_EXCEEDED", result.reason_codes)
        self.assertIn("STORAGE_BUDGET_EXCEEDED", result.reason_codes)
        self.assertIn("COMPLEXITY_BUDGET_EXCEEDED", result.reason_codes)

    def test_benchmark_lane_has_no_runtime_ml_network_or_model_dependency(self):
        source = inspect.getsource(advanced_benchmark)
        forbidden = (
            "sklearn",
            "torch",
            "tensorflow",
            "import socket",
            "subprocess",
            "urlopen",
            "OllamaClient",
            "generate_json",
        )
        for marker in forbidden:
            self.assertNotIn(marker, source)


if __name__ == "__main__":
    unittest.main()
