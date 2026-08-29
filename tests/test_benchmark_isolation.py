import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from three_agent.benchmark_isolation import (
    BENCHMARK_ISOLATION_SCHEMA,
    BenchmarkIsolation,
    BenchmarkVariantSpec,
    PreparedBenchmarkVariant,
    assert_isolated_variants,
)
from three_agent.benchmark_snapshot import effective_config_fingerprint
from three_agent.config import AppConfig, GatewayConfig, LLMConfig, ModelPolicyConfig


def config(root: Path) -> AppConfig:
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
        deep_model="qwen-deep",
        deep_escalation=True,
        deep_prompt_chars=14000,
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
            public_search_enabled=False,
            direct_egress=False,
        ),
        execution_gateway=GatewayConfig(
            enabled=False,
            allow_all=False,
            audit_log=root / "production" / "execution.jsonl",
        ),
        raw={},
        model_policy=policy,
        confidentiality_mode="confidential",
    )


class BenchmarkIsolationTests(unittest.TestCase):
    def test_prepare_moves_every_mutable_sink_under_variant_sandbox(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = config(root)
            isolation = BenchmarkIsolation(base, root / "bench")
            prepared = isolation.prepare(BenchmarkVariantSpec("baseline-48k"))

            self.assertEqual(
                prepared.config.database_path,
                prepared.paths.database_path,
            )
            self.assertEqual(
                prepared.config.artifact_root,
                prepared.paths.artifact_root,
            )
            self.assertEqual(
                prepared.config.internet_gateway.audit_log,
                prepared.paths.internet_audit_log,
            )
            self.assertEqual(
                prepared.config.execution_gateway.audit_log,
                prepared.paths.execution_audit_log,
            )
            self.assertNotEqual(prepared.config.database_path, base.database_path)
            self.assertNotEqual(prepared.config.artifact_root, base.artifact_root)

            manifest = prepared.manifest()
            self.assertEqual(manifest["schema_version"], BENCHMARK_ISOLATION_SCHEMA)
            self.assertTrue(manifest["storage"]["database_isolated"])
            self.assertFalse(manifest["raw_prompt_logged"])
            self.assertTrue(prepared.paths.manifest_path.is_file())

    def test_activation_sets_variant_env_and_restores_operator_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            isolation = BenchmarkIsolation(config(root), root / "bench")
            keys = (
                "WORKSPACE_INFERENCE_TELEMETRY",
                "WORKSPACE_RESOURCE_TELEMETRY",
                "WORKSPACE_EVIDENCE_PACKING_MODE",
                "WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS",
            )
            previous = {key: os.environ.get(key) for key in keys}
            os.environ["WORKSPACE_EVIDENCE_PACKING_MODE"] = "legacy_v1"
            os.environ["WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS"] = "48000"
            try:
                with isolation.activate(
                    BenchmarkVariantSpec(
                        "candidate-40k",
                        evidence_packing_mode="quality_ranked_v1",
                        synthesis_context_budget_chars=40000,
                    )
                ) as prepared:
                    self.assertEqual(
                        os.environ["WORKSPACE_INFERENCE_TELEMETRY"],
                        str(prepared.paths.inference_telemetry),
                    )
                    self.assertEqual(
                        os.environ["WORKSPACE_RESOURCE_TELEMETRY"],
                        str(prepared.paths.resource_telemetry),
                    )
                    self.assertEqual(
                        os.environ["WORKSPACE_EVIDENCE_PACKING_MODE"],
                        "quality_ranked_v1",
                    )
                    self.assertEqual(
                        os.environ["WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS"],
                        "40000",
                    )
                self.assertEqual(
                    os.environ.get("WORKSPACE_EVIDENCE_PACKING_MODE"),
                    "legacy_v1",
                )
                self.assertEqual(
                    os.environ.get("WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS"),
                    "48000",
                )
            finally:
                for key, value in previous.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value

    def test_nonempty_sandbox_is_never_implicitly_reused_or_deleted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            isolation = BenchmarkIsolation(config(root), root / "bench")
            spec = BenchmarkVariantSpec("baseline-48k")
            prepared = isolation.prepare(spec)
            sentinel = prepared.paths.sandbox_root / "keep.txt"
            sentinel.write_text("do not delete\n", encoding="utf-8")

            with self.assertRaisesRegex(FileExistsError, "already contains data"):
                isolation.prepare(spec)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "do not delete\n")

    def test_variant_label_cannot_escape_benchmark_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            isolation = BenchmarkIsolation(config(Path(tmp)), Path(tmp) / "bench")
            for label in ("../escape", "/absolute", "bad label", ""):
                with self.subTest(label=label):
                    with self.assertRaises(ValueError):
                        isolation.paths_for(BenchmarkVariantSpec(label))

    def test_storage_location_does_not_change_config_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            isolation = BenchmarkIsolation(config(root), root / "bench")
            hashes = []
            for label in ("same-a", "same-b"):
                with isolation.activate(
                    BenchmarkVariantSpec(
                        label,
                        evidence_packing_mode="legacy_v1",
                        synthesis_context_budget_chars=48000,
                    )
                ) as prepared:
                    hashes.append(effective_config_fingerprint(prepared.config))
            self.assertEqual(hashes[0], hashes[1])

    def test_packing_candidate_changes_config_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            isolation = BenchmarkIsolation(config(root), root / "bench")
            with isolation.activate(
                BenchmarkVariantSpec("baseline", synthesis_context_budget_chars=48000)
            ) as baseline:
                baseline_hash = effective_config_fingerprint(baseline.config)
            with isolation.activate(
                BenchmarkVariantSpec(
                    "candidate",
                    evidence_packing_mode="quality_ranked_v1",
                    synthesis_context_budget_chars=40000,
                )
            ) as candidate:
                candidate_hash = effective_config_fingerprint(candidate.config)
            self.assertNotEqual(baseline_hash, candidate_hash)

    def test_isolation_assertion_rejects_shared_sinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            isolation = BenchmarkIsolation(config(root), root / "bench")
            prepared = isolation.prepare(BenchmarkVariantSpec("one"))
            with self.assertRaisesRegex(ValueError, "share storage/telemetry sinks"):
                assert_isolated_variants(prepared, prepared)


if __name__ == "__main__":
    unittest.main()
