from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

SPEC = importlib.util.spec_from_file_location(
    "run_runtime_p0_benchmark",
    SCRIPTS / "run_runtime_p0_benchmark.py",
)
assert SPEC and SPEC.loader
benchmark = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = benchmark
SPEC.loader.exec_module(benchmark)


class RuntimeP0BenchmarkTests(unittest.TestCase):
    def test_runtime_p0_benchmark_reports_all_architecture_dimensions(self) -> None:
        receipt = benchmark.run_benchmark(iterations=2)
        self.assertTrue(receipt["accepted"])
        self.assertEqual(tuple(receipt["metrics"]), benchmark.ARCHITECTURE_DIMENSIONS)
        self.assertEqual(receipt["metrics"]["task_completion_rate"]["value"], 1.0)
        self.assertEqual(
            receipt["metrics"]["parallel_execution_efficiency"]["value"], 1.0
        )
        self.assertEqual(receipt["metrics"]["failure_recovery_rate"]["value"], 1.0)
        self.assertEqual(receipt["metrics"]["evidence_completeness"]["value"], 1.0)
        self.assertEqual(
            receipt["metrics"]["policy_enforcement_correctness"]["value"], 1.0
        )
        self.assertEqual(receipt["metrics"]["approval_correctness"]["value"], 1.0)
        self.assertEqual(
            receipt["metrics"]["hallucinated_action_mismatch_rate"]["value"], 0.0
        )
        self.assertEqual(
            receipt["metrics"]["deterministic_replay_reconstruction_coverage"]["value"],
            1.0,
        )
        self.assertGreater(
            receipt["metrics"]["wall_clock_time_to_result_ms"]["value"]["p50"],
            0.0,
        )

    def test_benchmark_is_provider_free_and_does_not_fake_non_applicable_metrics(self) -> None:
        receipt = benchmark.run_benchmark(iterations=1)
        self.assertFalse(receipt["scope"]["provider_execution"])
        self.assertFalse(receipt["scope"]["network_execution"])
        self.assertEqual(
            receipt["metrics"]["inference_turns_per_completed_task"]["applicability"],
            "not_applicable",
        )
        self.assertIsNone(receipt["metrics"]["tool_calls_per_inference_turn"]["value"])
        self.assertEqual(
            receipt["metrics"]["partial_result_quality"]["applicability"],
            "not_applicable",
        )
        self.assertEqual(receipt["metrics"]["model_provider_cost_usd"]["value"], 0.0)
        self.assertEqual(receipt["metrics"]["model_token_consumption"]["value"], 0)

    def test_benchmark_receipt_identity_is_stable_across_wall_clock_measurement(self) -> None:
        first = benchmark.run_benchmark(iterations=1)
        second = benchmark.run_benchmark(iterations=1)
        self.assertEqual(first["receipt_fingerprint"], second["receipt_fingerprint"])
        self.assertEqual(
            first["task_context_fingerprint"], second["task_context_fingerprint"]
        )
        self.assertEqual(first["plan_fingerprint"], second["plan_fingerprint"])
        self.assertEqual(first["functional_acceptance"], second["functional_acceptance"])

    def test_benchmark_keeps_p1_p2_followups_explicit_instead_of_claiming_them(self) -> None:
        receipt = benchmark.run_benchmark(iterations=1)
        self.assertEqual(
            receipt["scope"]["out_of_scope_followups"],
            [
                "provider/resource-lock adapters",
                "provider timeout/safe-retry adapters",
                "runtime-wide subagent delegation contract",
            ],
        )

    def test_benchmark_has_no_direct_process_or_network_execution_primitives(self) -> None:
        source = (SCRIPTS / "run_runtime_p0_benchmark.py").read_text(encoding="utf-8")
        forbidden = (
            "import subprocess",
            "from subprocess",
            "os.system(",
            "os.popen(",
            "import socket",
            "from socket",
            "import requests",
            "from requests",
            "import httpx",
            "from httpx",
            "urllib.request",
        )
        for token in forbidden:
            self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()
