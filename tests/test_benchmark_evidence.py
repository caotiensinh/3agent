import copy
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from three_agent.benchmark_artifact_canonicalize import (
    BenchmarkArtifactCanonicalizationError,
    canonicalize_suite_manifest_paths,
)
from three_agent.benchmark_evidence import (
    BenchmarkEvidenceError,
    BenchmarkEvidenceVerifier,
    validate_verification_receipt,
)
from three_agent.benchmark_readiness import BenchmarkReadinessProbe
from three_agent.benchmark_suite import FixedTaskBenchmarkSuite, VariantExecution
from three_agent.config import AppConfig, GatewayConfig, LLMConfig, ModelPolicyConfig
from three_agent.metric_registry import DEFAULT_METRIC_REGISTRY


SOURCE = "a" * 40
MODEL = "qwen3:30b"


def _canonical_sha(payload) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _config(root: Path) -> AppConfig:
    llm = LLMConfig(
        provider="ollama",
        base_url="http://127.0.0.1:11434",
        model="qwen-test",
        timeout_seconds=120,
        keep_alive="2m",
    )
    policy = ModelPolicyConfig(
        enabled=True,
        fast_model="qwen-test",
        research_model="qwen-test",
        presentation_model="qwen-test",
        report_model="qwen-test",
        deep_model="qwen-test",
        deep_escalation=False,
        deep_prompt_chars=14000,
        resource_control_enabled=False,
    )
    return AppConfig(
        environment="benchmark-evidence-test",
        test_mode_full_access=False,
        database_path=root / "production" / "tasks.db",
        artifact_root=root / "production" / "data",
        profile_root=root / "profiles",
        llm=llm,
        internet_gateway=GatewayConfig(
            enabled=True,
            allow_all=False,
            audit_log=root / "production" / "internet.jsonl",
            mode="strict",
            public_search_enabled=False,
            direct_egress=False,
        ),
        execution_gateway=GatewayConfig(
            enabled=False,
            allow_all=False,
            audit_log=root / "production" / "execution.jsonl",
            mode="strict",
            direct_egress=False,
        ),
        raw={},
        model_policy=policy,
        confidentiality_mode="confidential",
    )


def _write_taskset(repo_root: Path) -> Path:
    (repo_root / "docs").mkdir(parents=True, exist_ok=True)
    (repo_root / "benchmarks").mkdir(parents=True, exist_ok=True)
    (repo_root / "docs" / "a.md").write_text("fixture a", encoding="utf-8")
    (repo_root / "docs" / "b.md").write_text("fixture b", encoding="utf-8")
    path = repo_root / "benchmarks" / "fixed.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "workspace-benchmark-taskset/v1",
                "task_set_id": "fixed-evidence-v1",
                "tasks": [
                    {
                        "case_id": "case-a",
                        "title": "Case A",
                        "request": "Use only fixture A.",
                        "fixtures": ["docs/a.md"],
                        "language": "en",
                        "slide_count": 6,
                    },
                    {
                        "case_id": "case-b",
                        "title": "Case B",
                        "request": "Use only fixture B.",
                        "fixtures": ["docs/b.md"],
                        "language": "en",
                        "slide_count": 6,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _fixture_corpus(fixed, repo_root: Path) -> str:
    rows = []
    ordered = list(dict.fromkeys(path for case in fixed.cases for path in case.fixtures))
    for relative in ordered:
        data = (repo_root / relative).read_bytes()
        seed = (
            fixed.task_set_id.encode()
            + b"\0"
            + relative.encode()
            + b"\0"
            + hashlib.sha256(data).digest()
        )
        rows.append(
            {
                "path": relative,
                "content_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                "upload_id": hashlib.sha256(seed).hexdigest()[:16],
            }
        )
    return _canonical_sha(rows)


def _metrics(task_ids, *, tokens: float) -> dict:
    return {
        "schema_version": "workspace-unified-metrics/v1",
        "metric_registry": DEFAULT_METRIC_REGISTRY.to_dict(),
        "scope": {
            "date": None,
            "selected_task_count": len(task_ids),
            "task_ids": list(task_ids),
        },
        "verified_work": {
            "verified_task_success_rate": 1.0,
            "first_pass_verified_success_rate": 1.0,
            "verified_tasks": len(task_ids),
        },
        "token_efficiency": {"total_tokens_per_verified_task": tokens},
        "resource_efficiency": {
            "tool_calls_per_verified_task": 2.0,
            "model_retries_per_verified_task": 0.0,
            "model_escalations_per_verified_task": 0.0,
        },
        "evidence_coverage": {"evidence_coverage": 1.0},
        "context_precision_proxy": {"context_precision_proxy": 0.8},
        "context_recall_proxy": {"context_recall_proxy": 1.0},
    }


def _case_rows(task_ids) -> tuple[dict, ...]:
    rows = []
    for case_id, task_id in zip(("case-a", "case-b"), task_ids):
        rows.append(
            {
                "case_id": case_id,
                "task_id": task_id,
                "workflow_status": "completed",
                "task_status": "done",
                "elapsed_ms": 100,
                "contract_bound": True,
                "required_validators": ["policy", "evidence", "schema"],
                "passed_validators": ["policy", "evidence", "schema"],
                "failed_validators": [],
                "missing_validators": [],
                "verified": True,
                "first_pass_verified": True,
            }
        )
    return tuple(rows)


class _ReadinessRunner:
    def __call__(self, argv, cwd):
        del cwd
        commands = {
            ("git", "rev-parse", "HEAD"): SOURCE + "\n",
            ("git", "status", "--porcelain", "--untracked-files=no"): "",
            (
                "nvidia-smi",
                "--query-gpu=name,driver_version,memory.total",
                "--format=csv,noheader,nounits",
            ): (
                "NVIDIA GeForce RTX 5090, 590.44, 32607\n"
                "NVIDIA GeForce RTX 5090, 590.44, 32607\n"
            ),
            ("ollama", "--version"): "ollama version is 0.11.4\n",
            ("ollama", "show", MODEL): "PRIVATE MODEL DETAILS\n",
        }
        key = tuple(argv)
        if key not in commands:
            raise AssertionError(f"unexpected command: {key}")
        return commands[key]


def _build_artifacts(root: Path):
    repo_root = root / "repo"
    bench_root = root / "artifact"
    task_set_path = _write_taskset(repo_root)
    task_ids = ("TASK-20260829-0001", "TASK-20260829-0002")
    tokens = {
        "baseline-legacy-48k": 100.0,
        "ranked-48k": 95.0,
        "ranked-40k": 80.0,
        "ranked-32k": 70.0,
    }

    def executor(prepared, fixed, source_root):
        return VariantExecution(
            metrics=_metrics(task_ids, tokens=tokens[prepared.spec.label]),
            cases=_case_rows(task_ids),
            elapsed_ms={
                "baseline-legacy-48k": 200,
                "ranked-48k": 190,
                "ranked-40k": 170,
                "ranked-32k": 160,
            }[prepared.spec.label],
            corpus_sha256=_fixture_corpus(fixed, source_root),
        )

    FixedTaskBenchmarkSuite(
        _config(root),
        bench_root,
        repo_root,
        variant_executor=executor,
        verify_source_checkout=False,
    ).run(task_set_path, source_ref=SOURCE)

    readiness = BenchmarkReadinessProbe(
        repo_root,
        runner=_ReadinessRunner(),
        clock=lambda: datetime(2026, 8, 29, 16, 0, tzinfo=timezone.utc),
    ).collect(source_ref=SOURCE, model=MODEL)
    (bench_root / "environment.json").write_text(
        json.dumps(readiness, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return repo_root, bench_root, task_set_path


class BenchmarkArtifactCanonicalizationTests(unittest.TestCase):
    def test_only_manifest_paths_are_rewritten_and_absolute_root_disappears(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, bench_root, _ = _build_artifacts(root)
            before = json.loads((bench_root / "suite.json").read_text(encoding="utf-8"))
            expected = copy.deepcopy(before)
            for label, row in expected["variants"].items():
                row["manifest_path"] = f"{label}/benchmark.json"
            result = canonicalize_suite_manifest_paths(bench_root)
            after_text = (bench_root / "suite.json").read_text(encoding="utf-8")
            after = json.loads(after_text)
        self.assertTrue(result["completed"])
        self.assertEqual(result["manifest_paths_rewritten"], 4)
        self.assertEqual(after, expected)
        self.assertNotIn(str(bench_root), after_text)

    def test_outside_manifest_path_fails_without_rewriting_suite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, bench_root, _ = _build_artifacts(root)
            path = bench_root / "suite.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["variants"]["baseline-legacy-48k"]["manifest_path"] = "/tmp/evil.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            before = path.read_text(encoding="utf-8")
            with self.assertRaisesRegex(
                BenchmarkArtifactCanonicalizationError,
                "MANIFEST_PATH_OUTSIDE_EXPECTED_FILE",
            ):
                canonicalize_suite_manifest_paths(bench_root)
            self.assertEqual(path.read_text(encoding="utf-8"), before)


class BenchmarkEvidenceVerifierTests(unittest.TestCase):
    def test_complete_artifact_set_recomputes_and_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo_root, bench_root, task_set = _build_artifacts(root)
            canonicalize_suite_manifest_paths(bench_root)
            report = BenchmarkEvidenceVerifier(bench_root, repo_root).verify(
                source_ref=SOURCE,
                task_set_path=task_set,
            )
        self.assertTrue(report["passed"])
        self.assertEqual(report["source_ref"], SOURCE)
        self.assertTrue(all(report["checks"].values()))
        self.assertTrue(all(report["promotion_eligible"].values()))
        self.assertEqual(len(report["artifact_sha256"]), 10)
        self.assertTrue(report["verification_sha256"].startswith("sha256:"))
        validate_verification_receipt(report, expected_source_ref=SOURCE)

    def test_uncanonicalized_suite_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo_root, bench_root, task_set = _build_artifacts(root)
            with self.assertRaisesRegex(BenchmarkEvidenceError, "MANIFEST_PATH_NOT_CANONICAL"):
                BenchmarkEvidenceVerifier(bench_root, repo_root).verify(
                    source_ref=SOURCE,
                    task_set_path=task_set,
                )

    def test_tampered_suite_comparison_is_rejected_by_recompute(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo_root, bench_root, task_set = _build_artifacts(root)
            canonicalize_suite_manifest_paths(bench_root)
            path = bench_root / "suite.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["comparisons"]["ranked-40k"]["promotion_eligible"] = False
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                BenchmarkEvidenceError,
                "SUITE_COMPARISON_RECOMPUTE_MISMATCH",
            ):
                BenchmarkEvidenceVerifier(bench_root, repo_root).verify(
                    source_ref=SOURCE,
                    task_set_path=task_set,
                )

    def test_tampered_manifest_metrics_fail_lineage_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo_root, bench_root, task_set = _build_artifacts(root)
            canonicalize_suite_manifest_paths(bench_root)
            path = bench_root / "ranked-40k" / "benchmark.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["metrics"]["token_efficiency"]["total_tokens_per_verified_task"] = 1.0
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                BenchmarkEvidenceError,
                "BENCHMARK_MANIFEST_LINEAGE_INVALID",
            ):
                BenchmarkEvidenceVerifier(bench_root, repo_root).verify(
                    source_ref=SOURCE,
                    task_set_path=task_set,
                )

    def test_missing_isolation_receipt_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo_root, bench_root, task_set = _build_artifacts(root)
            canonicalize_suite_manifest_paths(bench_root)
            (bench_root / "ranked-32k" / "isolation.json").unlink()
            with self.assertRaisesRegex(BenchmarkEvidenceError, "ISOLATION_RECEIPT_MISSING"):
                BenchmarkEvidenceVerifier(bench_root, repo_root).verify(
                    source_ref=SOURCE,
                    task_set_path=task_set,
                )

    def test_readiness_source_mismatch_fails_before_suite_claims(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo_root, bench_root, task_set = _build_artifacts(root)
            canonicalize_suite_manifest_paths(bench_root)
            with self.assertRaisesRegex(BenchmarkEvidenceError, "READINESS_RECEIPT_INVALID"):
                BenchmarkEvidenceVerifier(bench_root, repo_root).verify(
                    source_ref="b" * 40,
                    task_set_path=task_set,
                )


if __name__ == "__main__":
    unittest.main()
