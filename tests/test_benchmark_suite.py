import json
import tempfile
import unittest
from pathlib import Path

from three_agent.benchmark_isolation import BenchmarkVariantSpec
from three_agent.benchmark_suite import (
    BenchmarkSuiteError,
    FixedBenchmarkTaskSet,
    FixedTaskBenchmarkSuite,
    VariantExecution,
)
from three_agent.config import AppConfig, GatewayConfig, LLMConfig, ModelPolicyConfig


def config(root: Path, *, public_search: bool = False) -> AppConfig:
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
        environment="benchmark-test",
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
            public_search_enabled=public_search,
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


def taskset(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema_version": "workspace-benchmark-taskset/v1",
                "task_set_id": "fixed-v1",
                "tasks": [
                    {
                        "case_id": "case-a",
                        "title": "Case A",
                        "request": "Use only the attached fixture to explain the policy.",
                        "fixtures": ["docs/a.md"],
                        "language": "en",
                        "slide_count": 6,
                    },
                    {
                        "case_id": "case-b",
                        "title": "Case B",
                        "request": "Use only the attached fixture to explain the validator gate.",
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


def metrics(task_ids, *, tokens=100.0, verified=1.0, first_pass=1.0, evidence=1.0):
    return {
        "schema_version": "workspace-unified-metrics/v1",
        "scope": {
            "date": None,
            "selected_task_count": len(task_ids),
            "task_ids": list(task_ids),
        },
        "verified_work": {
            "verified_task_success_rate": verified,
            "first_pass_verified_success_rate": first_pass,
            "verified_tasks": len(task_ids) if verified == 1.0 else 1,
        },
        "token_efficiency": {"total_tokens_per_verified_task": tokens},
        "resource_efficiency": {
            "tool_calls_per_verified_task": 2.0,
            "model_retries_per_verified_task": 0.0,
            "model_escalations_per_verified_task": 0.0,
        },
        "evidence_coverage": {"evidence_coverage": evidence},
        "context_precision_proxy": {"context_precision_proxy": 0.7},
        "context_recall_proxy": {"context_recall_proxy": 0.9},
    }


def case_rows(task_ids, *, lose_schema=False):
    rows = []
    for index, task_id in enumerate(task_ids):
        passed = ["policy", "evidence", "schema"]
        failed = []
        if lose_schema and index == 0:
            passed = ["policy", "evidence"]
            failed = ["schema"]
        rows.append(
            {
                "case_id": f"case-{'ab'[index]}",
                "task_id": task_id,
                "workflow_status": "completed" if not failed else "failed",
                "task_status": "done" if not failed else "failed",
                "elapsed_ms": 100,
                "contract_bound": True,
                "required_validators": ["policy", "evidence", "schema"],
                "passed_validators": passed,
                "failed_validators": failed,
                "missing_validators": [],
                "verified": not failed,
                "first_pass_verified": not failed,
            }
        )
    return tuple(rows)


class FixedBenchmarkTaskSetTests(unittest.TestCase):
    def test_load_is_deterministic_and_rejects_duplicate_case_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = taskset(root / "tasks.json")
            first = FixedBenchmarkTaskSet.load(source)
            second = FixedBenchmarkTaskSet.load(source)
            self.assertEqual(first.sha256, second.sha256)
            self.assertEqual([case.case_id for case in first.cases], ["case-a", "case-b"])

            payload = json.loads(source.read_text(encoding="utf-8"))
            payload["tasks"][1]["case_id"] = "case-a"
            source.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ValueError):
                FixedBenchmarkTaskSet.load(source)

    def test_fixture_paths_cannot_escape_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = taskset(root / "tasks.json")
            payload = json.loads(source.read_text(encoding="utf-8"))
            payload["tasks"][0]["fixtures"] = ["../secret.md"]
            source.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsafe or unsupported"):
                FixedBenchmarkTaskSet.load(source)


class FixedTaskBenchmarkSuiteTests(unittest.TestCase):
    def test_local_fixture_benchmark_rejects_public_search_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            suite = FixedTaskBenchmarkSuite(
                config(root, public_search=True),
                root / "bench",
                root,
                verify_source_checkout=False,
            )
            with self.assertRaises(BenchmarkSuiteError):
                suite.run(taskset(root / "tasks.json"), source_ref="a" * 40)

    def test_required_validator_gate_rejects_lost_pass(self):
        task_ids = ("TASK-1", "TASK-2")
        baseline = VariantExecution(
            metrics=metrics(task_ids),
            cases=case_rows(task_ids),
            elapsed_ms=200,
            corpus_sha256="sha256:" + "1" * 64,
        )
        candidate = VariantExecution(
            metrics=metrics(task_ids),
            cases=case_rows(task_ids, lose_schema=True),
            elapsed_ms=180,
            corpus_sha256=baseline.corpus_sha256,
        )
        report = FixedTaskBenchmarkSuite._validator_gate(baseline, candidate)
        self.assertFalse(report["passed"])
        self.assertIn("VALIDATOR_REGRESSION:case-a:schema", report["failures"])

    def test_suite_gates_efficiency_until_quality_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            (root / "docs" / "a.md").write_text("fixture a", encoding="utf-8")
            (root / "docs" / "b.md").write_text("fixture b", encoding="utf-8")
            source = taskset(root / "tasks.json")
            task_ids = ("TASK-20260101-0001", "TASK-20260101-0002")

            def executor(prepared, fixed, repo_root):
                del fixed, repo_root
                label = prepared.spec.label
                if label == "ranked-40k":
                    return VariantExecution(
                        metrics=metrics(task_ids, tokens=75.0),
                        cases=case_rows(task_ids),
                        elapsed_ms=150,
                        corpus_sha256="sha256:" + "2" * 64,
                    )
                if label == "ranked-32k":
                    return VariantExecution(
                        metrics=metrics(task_ids, tokens=60.0, first_pass=0.5),
                        cases=case_rows(task_ids, lose_schema=True),
                        elapsed_ms=120,
                        corpus_sha256="sha256:" + "2" * 64,
                    )
                return VariantExecution(
                    metrics=metrics(task_ids, tokens=100.0),
                    cases=case_rows(task_ids),
                    elapsed_ms=200,
                    corpus_sha256="sha256:" + "2" * 64,
                )

            variants = (
                BenchmarkVariantSpec("baseline-legacy-48k", "legacy_v1", 48000),
                BenchmarkVariantSpec("ranked-40k", "quality_ranked_v1", 40000),
                BenchmarkVariantSpec("ranked-32k", "quality_ranked_v1", 32000),
            )
            suite = FixedTaskBenchmarkSuite(
                config(root),
                root / "bench",
                root,
                variants=variants,
                variant_executor=executor,
                verify_source_checkout=False,
            ).run(source, source_ref="b" * 40)

            ranked40 = suite["comparisons"]["ranked-40k"]
            self.assertTrue(ranked40["quality_preserved"])
            self.assertTrue(ranked40["efficiency_evaluated"])
            self.assertTrue(ranked40["promotion_eligible"])
            self.assertEqual(
                ranked40["optimization_acceptance"]["token_efficiency"]["reduction_pct"],
                25.0,
            )

            ranked32 = suite["comparisons"]["ranked-32k"]
            self.assertFalse(ranked32["quality_preserved"])
            self.assertFalse(ranked32["efficiency_evaluated"])
            self.assertFalse(ranked32["promotion_eligible"])
            self.assertIsNone(ranked32["latency"])

    def test_runtime_task_scope_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = taskset(root / "tasks.json")

            def executor(prepared, fixed, repo_root):
                del fixed, repo_root
                ids = (
                    ("TASK-1", "TASK-2")
                    if prepared.spec.label == "baseline-legacy-48k"
                    else ("TASK-1", "TASK-3")
                )
                return VariantExecution(
                    metrics=metrics(ids),
                    cases=case_rows(ids),
                    elapsed_ms=100,
                    corpus_sha256="sha256:" + "3" * 64,
                )

            variants = (
                BenchmarkVariantSpec("baseline-legacy-48k", "legacy_v1", 48000),
                BenchmarkVariantSpec("ranked-40k", "quality_ranked_v1", 40000),
            )
            runner = FixedTaskBenchmarkSuite(
                config(root),
                root / "bench",
                root,
                variants=variants,
                variant_executor=executor,
                verify_source_checkout=False,
            )
            with self.assertRaisesRegex(BenchmarkSuiteError, "different runtime task IDs"):
                runner.run(source, source_ref="c" * 40)


if __name__ == "__main__":
    unittest.main()
