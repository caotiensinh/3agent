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
