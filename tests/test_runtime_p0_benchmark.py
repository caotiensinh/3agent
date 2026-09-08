from __future__ import annotations

import importlib.util
import sys
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


def test_runtime_p0_benchmark_reports_all_architecture_dimensions() -> None:
    receipt = benchmark.run_benchmark(iterations=2)
    assert receipt["accepted"] is True
    assert tuple(receipt["metrics"]) == benchmark.ARCHITECTURE_DIMENSIONS
    assert receipt["metrics"]["task_completion_rate"]["value"] == 1.0
    assert receipt["metrics"]["parallel_execution_efficiency"]["value"] == 1.0
    assert receipt["metrics"]["failure_recovery_rate"]["value"] == 1.0
    assert receipt["metrics"]["evidence_completeness"]["value"] == 1.0
    assert receipt["metrics"]["policy_enforcement_correctness"]["value"] == 1.0
    assert receipt["metrics"]["approval_correctness"]["value"] == 1.0
    assert receipt["metrics"]["hallucinated_action_mismatch_rate"]["value"] == 0.0
    assert (
        receipt["metrics"]["deterministic_replay_reconstruction_coverage"]["value"]
        == 1.0
    )
    assert receipt["metrics"]["wall_clock_time_to_result_ms"]["value"]["p50"] > 0.0


def test_benchmark_is_provider_free_and_does_not_fake_non_applicable_metrics() -> None:
    receipt = benchmark.run_benchmark(iterations=1)
    assert receipt["scope"]["provider_execution"] is False
    assert receipt["scope"]["network_execution"] is False
    assert (
        receipt["metrics"]["inference_turns_per_completed_task"]["applicability"]
        == "not_applicable"
    )
    assert receipt["metrics"]["tool_calls_per_inference_turn"]["value"] is None
    assert (
        receipt["metrics"]["partial_result_quality"]["applicability"]
        == "not_applicable"
    )
    assert receipt["metrics"]["model_provider_cost_usd"]["value"] == 0.0
    assert receipt["metrics"]["model_token_consumption"]["value"] == 0


def test_benchmark_receipt_identity_is_stable_across_wall_clock_measurement() -> None:
    first = benchmark.run_benchmark(iterations=1)
    second = benchmark.run_benchmark(iterations=1)
    assert first["receipt_fingerprint"] == second["receipt_fingerprint"]
    assert first["task_context_fingerprint"] == second["task_context_fingerprint"]
    assert first["plan_fingerprint"] == second["plan_fingerprint"]
    assert first["functional_acceptance"] == second["functional_acceptance"]


def test_benchmark_keeps_p1_p2_followups_explicit_instead_of_claiming_them() -> None:
    receipt = benchmark.run_benchmark(iterations=1)
    assert receipt["scope"]["out_of_scope_followups"] == [
        "provider/resource-lock adapters",
        "provider timeout/safe-retry adapters",
        "runtime-wide subagent delegation contract",
    ]


def test_benchmark_has_no_direct_process_or_network_execution_primitives() -> None:
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
        assert token not in source
