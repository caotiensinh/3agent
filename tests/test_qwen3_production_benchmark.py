from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "run_qwen3_production_benchmark",
    SCRIPTS / "run_qwen3_production_benchmark.py",
)
assert SPEC and SPEC.loader
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


def test_metrics_reward_relevant_documents() -> None:
    queries = [
        {"id": "q1", "relevant": ["a"]},
        {"id": "q2", "relevant": ["b", "c"]},
    ]
    rankings = {
        "q1": ["a", "b", "c"],
        "q2": ["b", "x", "c"],
    }
    metrics = benchmark.aggregate_metrics(rankings, queries)
    assert metrics["recall_at_1"] == 0.75
    assert metrics["recall_at_3"] == 1.0
    assert metrics["recall_at_5"] == 1.0
    assert metrics["mrr_at_10"] == 1.0
    assert 0.9 < metrics["ndcg_at_10"] <= 1.0


def test_lexical_rank_is_deterministic_on_ties() -> None:
    docs = [
        {"id": "b", "text": "camera poe"},
        {"id": "a", "text": "camera poe"},
    ]
    assert benchmark.lexical_rank("camera poe", docs) == ["a", "b"]


def test_fixture_is_valid_and_non_authoritative() -> None:
    fixture_path = ROOT / "config" / "benchmarks" / "qwen3-embedding-retrieval-v1.json"
    raw = json.loads(fixture_path.read_text(encoding="utf-8"))
    benchmark.validate_fixture(raw)
    assert raw["schema"] == "workspace.embedding-retrieval-benchmark/v1"
    assert len(raw["documents"]) >= 10
    assert len(raw["queries"]) >= 10
    assert set(raw["domains"]) == {
        "cybersecurity",
        "network",
        "monitoring",
        "camera-diagnostics",
    }


def test_percentile_interpolates_without_external_dependencies() -> None:
    assert benchmark.percentile([10.0, 20.0, 30.0], 0.5) == 20.0
    assert benchmark.percentile([10.0, 20.0], 0.5) == 15.0


def test_dual_gpu_workflow_delegates_fail_closed_isolation_probe() -> None:
    workflow = (
        ROOT / ".github" / "workflows" / "qwen3-embedding-production-benchmark-rtx5090.yml"
    ).read_text(encoding="utf-8")
    assert "run_qwen3_production_benchmark.sh --probe-isolation" in workflow
    assert "seccomp-no-network" in workflow
    assert "runtime_authority') is False" in workflow
    assert "production_approval') is False" in workflow
    assert "scripts/run_with_network_seccomp.py" in workflow


def test_runner_script_docker_fallback_is_narrow_and_offline() -> None:
    script = (SCRIPTS / "run_qwen3_production_benchmark.sh").read_text(encoding="utf-8")
    assert "docker-none" in script
    assert "--network none" in script
    assert "--gpus all" in script
    assert "HF_HUB_OFFLINE=1" in script
    assert "TRANSFORMERS_OFFLINE=1" in script
    assert "--read-only" in script
    assert "--cap-drop ALL" in script
    assert "--security-opt no-new-privileges" in script
    assert "/var/run/docker.sock" not in script
    assert "sg docker -c" in script
    assert "docker_access_mode" in script
    assert "rootless_docker_host" in script


def test_seccomp_executor_is_kernel_enforced_and_exec_inherited() -> None:
    wrapper = (SCRIPTS / "run_with_network_seccomp.py").read_text(encoding="utf-8")
    assert "PR_SET_NO_NEW_PRIVS" in wrapper
    assert "seccomp_load" in wrapper
    assert '"socket"' in wrapper
    assert '"connect"' in wrapper
    assert '"sendto"' in wrapper
    assert '"sendmsg"' in wrapper
    assert '"io_uring_setup"' in wrapper
    assert "os.execvpe" in wrapper
    assert "close_inherited_fds" in wrapper


def test_python_receipt_requires_verified_isolation_mode() -> None:
    assert "seccomp-no-network" in benchmark.ALLOWED_ISOLATION_MODES
    assert "docker-none" in benchmark.ALLOWED_ISOLATION_MODES
    script = (SCRIPTS / "run_qwen3_production_benchmark.py").read_text(encoding="utf-8")
    assert '"network_isolation_mode": isolation_mode' in script
