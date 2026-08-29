import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from three_agent.benchmark_snapshot import (
    build_benchmark_manifest,
    effective_config_fingerprint,
    unpack_metrics_payload,
    write_benchmark_manifest,
)
from three_agent.cli import build_parser
from three_agent.config import (
    AppConfig,
    GatewayConfig,
    LLMConfig,
    ModelPolicyConfig,
)
from three_agent.optimization_gate import (
    OptimizationAcceptanceGate,
    OptimizationGateError,
)


SOURCE_A = "a" * 40
SOURCE_B = "b" * 40


def metrics(tokens=100.0):
    return {
        "schema_version": "workspace-unified-metrics/v1",
        "scope": {
            "date": None,
            "selected_task_count": 2,
            "task_ids": ["TASK-1", "TASK-2"],
        },
        "verified_work": {
            "verified_task_success_rate": 1.0,
            "first_pass_verified_success_rate": 1.0,
            "verified_tasks": 2,
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


def config(root: Path, *, model: str = "qwen-test") -> AppConfig:
    llm = LLMConfig(
        provider="ollama",
        base_url="http://127.0.0.1:11434",
        model=model,
        timeout_seconds=120,
        keep_alive="2m",
    )
    policy = ModelPolicyConfig(
        enabled=True,
        fast_model=model,
        research_model=model,
        presentation_model=model,
        report_model=model,
        deep_model="qwen-deep",
        deep_escalation=True,
        deep_prompt_chars=14000,
    )
    internet = GatewayConfig(
        enabled=True,
        allow_all=False,
        audit_log=root / "internet.jsonl",
        mode="strict",
        public_search_enabled=False,
        direct_egress=False,
    )
    execution = GatewayConfig(
        enabled=False,
        allow_all=False,
        audit_log=root / "execution.jsonl",
    )
    return AppConfig(
        environment="test",
        test_mode_full_access=False,
        database_path=root / "tasks.db",
        artifact_root=root / "data",
        profile_root=root / "profiles",
        llm=llm,
        internet_gateway=internet,
        execution_gateway=execution,
        raw={"password": "RAW_CONFIG_SECRET", "token": "RAW_TOKEN_SECRET"},
        model_policy=policy,
        product_name="WorkSpace",
        confidentiality_mode="confidential",
    )


class BenchmarkSnapshotTests(unittest.TestCase):
    def test_manifest_binds_metrics_scope_source_and_effective_config_without_raw_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config(Path(tmp))
            manifest = build_benchmark_manifest(
                metrics(),
                cfg,
                variant_label="baseline",
                source_ref=SOURCE_A,
                captured_at="2026-08-29T00:00:00+00:00",
            )
            raw = json.dumps(manifest, ensure_ascii=False)
            self.assertEqual(manifest["schema_version"], "workspace-benchmark-snapshot/v1")
            self.assertEqual(manifest["lineage"]["source_ref"], SOURCE_A)
            self.assertTrue(manifest["lineage"]["configuration_sha256"].startswith("sha256:"))
            self.assertTrue(manifest["lineage"]["task_scope_sha256"].startswith("sha256:"))
            self.assertTrue(manifest["lineage"]["metrics_sha256"].startswith("sha256:"))
            self.assertNotIn("RAW_CONFIG_SECRET", raw)
            self.assertNotIn("RAW_TOKEN_SECRET", raw)
            unpacked, lineage = unpack_metrics_payload(manifest)
            self.assertEqual(unpacked, metrics())
            self.assertEqual(lineage["variant_label"], "baseline")

    def test_effective_config_fingerprint_changes_when_model_route_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = config(root, model="qwen-a")
            second = replace(first, llm=replace(first.llm, model="qwen-b"))
            self.assertNotEqual(
                effective_config_fingerprint(first),
                effective_config_fingerprint(second),
            )

    def test_exact_source_sha_and_variant_label_are_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config(Path(tmp))
            with self.assertRaises(ValueError):
                build_benchmark_manifest(
                    metrics(), cfg, variant_label="baseline", source_ref="main"
                )
            with self.assertRaises(ValueError):
                build_benchmark_manifest(
                    metrics(), cfg, variant_label="bad label", source_ref=SOURCE_A
                )

    def test_tampered_metrics_are_rejected_by_manifest_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = build_benchmark_manifest(
                metrics(), config(Path(tmp)), variant_label="baseline", source_ref=SOURCE_A
            )
            manifest["metrics"]["token_efficiency"]["total_tokens_per_verified_task"] = 1
            with self.assertRaises(ValueError):
                unpack_metrics_payload(manifest)

    def test_write_is_atomic_and_does_not_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = build_benchmark_manifest(
                metrics(), config(root), variant_label="baseline", source_ref=SOURCE_A
            )
            path = root / "bench" / "baseline.json"
            write_benchmark_manifest(path, manifest)
            self.assertTrue(path.exists())
            self.assertFalse(path.with_name(path.name + ".tmp").exists())
            with self.assertRaises(FileExistsError):
                write_benchmark_manifest(path, manifest)
            write_benchmark_manifest(path, manifest, overwrite=True)

    def test_optimization_gate_accepts_two_lineage_bound_manifests(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config(Path(tmp))
            baseline = build_benchmark_manifest(
                metrics(100), cfg, variant_label="baseline", source_ref=SOURCE_A
            )
            candidate_cfg = replace(cfg, llm=replace(cfg.llm, model="qwen-faster"))
            candidate = build_benchmark_manifest(
                metrics(80), candidate_cfg, variant_label="candidate", source_ref=SOURCE_B
            )
            report = OptimizationAcceptanceGate().evaluate(baseline, candidate)
            self.assertTrue(report["accepted"])
            self.assertTrue(report["lineage"]["source_changed"])
            self.assertTrue(report["lineage"]["configuration_changed"])

    def test_mixed_raw_and_manifest_comparison_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = build_benchmark_manifest(
                metrics(), config(Path(tmp)), variant_label="candidate", source_ref=SOURCE_A
            )
            with self.assertRaises(OptimizationGateError):
                OptimizationAcceptanceGate().evaluate(metrics(), manifest)

    def test_cli_capture_contract(self):
        args = build_parser().parse_args(
            [
                "metrics-capture",
                "--output",
                "baseline.json",
                "--variant-label",
                "baseline",
                "--source-ref",
                SOURCE_A,
                "--task-id",
                "TASK-1",
                "--task-id",
                "TASK-2",
            ]
        )
        self.assertEqual(args.command, "metrics-capture")
        self.assertEqual(args.task_ids, ["TASK-1", "TASK-2"])
        self.assertFalse(args.force)


if __name__ == "__main__":
    unittest.main()
