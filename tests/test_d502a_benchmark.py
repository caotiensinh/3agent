import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from three_agent.benchmark_isolation import BenchmarkIsolation, BenchmarkVariantSpec
from three_agent.benchmark_snapshot import effective_config_fingerprint
from three_agent.benchmark_suite import FixedBenchmarkTaskSet
from three_agent.config import AppConfig, GatewayConfig, LLMConfig, ModelPolicyConfig
from three_agent.d502a_benchmark import (
    D502A_BASELINE_LABEL,
    D502A_CANDIDATE_LABEL,
    D502A_MIRROR_A,
    D502A_MIRROR_B,
    D502A_PROFILE_ID,
    D502A_TASK_SET,
    D502A_VARIANTS,
    _decision,
    _mirror_fixture_sha256,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


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


def comparison(*, reduction_pct: float, quality: bool = True, validators: bool = True):
    return {
        "schema_version": "workspace-fixed-benchmark-comparison/v1",
        "quality_preserved": quality,
        "required_validator_acceptance": {
            "schema_version": "workspace-required-validator-acceptance/v1",
            "passed": validators,
            "checks": {},
            "failures": [] if validators else ["VALIDATOR_REGRESSION:case:schema"],
        },
        "optimization_acceptance": {
            "schema_version": "workspace-optimization-acceptance/v1",
            "accepted": quality and reduction_pct >= 0.0,
            "token_efficiency": {
                "reduction_pct": reduction_pct,
            },
            "failures": [],
        },
        "efficiency_evaluated": quality,
        "latency": None,
        "promotion_eligible": quality and validators and reduction_pct >= 0.0,
    }


class D502ABenchmarkTests(unittest.TestCase):
    def test_profile_is_exactly_one_off_and_one_on_legacy_48k_variant(self):
        self.assertEqual([item.label for item in D502A_VARIANTS], [D502A_BASELINE_LABEL, D502A_CANDIDATE_LABEL])
        baseline = D502A_VARIANTS[0].policy()
        candidate = D502A_VARIANTS[1].policy()
        self.assertEqual(baseline.mode, "legacy_v1")
        self.assertEqual(candidate.mode, "legacy_v1")
        self.assertEqual(baseline.budget_chars, 48000)
        self.assertEqual(candidate.budget_chars, 48000)
        self.assertFalse(baseline.exact_body_dedupe)
        self.assertTrue(candidate.exact_body_dedupe)

    def test_exact_dedupe_variant_is_fingerprinted_and_env_is_restored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            isolation = BenchmarkIsolation(config(root), root / "bench")
            with patch.dict(
                os.environ,
                {"WORKSPACE_EVIDENCE_EXACT_BODY_DEDUPE": "false"},
                clear=False,
            ):
                with isolation.activate(D502A_VARIANTS[0]) as baseline:
                    baseline_hash = effective_config_fingerprint(baseline.config)
                    self.assertEqual(os.environ["WORKSPACE_EVIDENCE_EXACT_BODY_DEDUPE"], "false")
                with isolation.activate(D502A_VARIANTS[1]) as candidate:
                    candidate_hash = effective_config_fingerprint(candidate.config)
                    self.assertEqual(os.environ["WORKSPACE_EVIDENCE_EXACT_BODY_DEDUPE"], "true")
                    self.assertTrue(candidate.manifest()["evidence_packing"]["exact_body_dedupe"])
                self.assertEqual(os.environ["WORKSPACE_EVIDENCE_EXACT_BODY_DEDUPE"], "false")
            self.assertNotEqual(baseline_hash, candidate_hash)

    def test_representative_task_set_contains_byte_identical_mirror_pair_in_every_case(self):
        task_set = FixedBenchmarkTaskSet.load(REPO_ROOT / D502A_TASK_SET)
        digest = _mirror_fixture_sha256(task_set, REPO_ROOT)
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(
            (REPO_ROOT / D502A_MIRROR_A).read_bytes(),
            (REPO_ROOT / D502A_MIRROR_B).read_bytes(),
        )
        for case in task_set.cases:
            self.assertIn(D502A_MIRROR_A, case.fixtures)
            self.assertIn(D502A_MIRROR_B, case.fixtures)

    def test_d502a_requires_strictly_positive_measured_token_benefit(self):
        task_set = FixedBenchmarkTaskSet.load(REPO_ROOT / D502A_TASK_SET)
        mirror_sha = _mirror_fixture_sha256(task_set, REPO_ROOT)
        zero = _decision(
            source_ref="a" * 40,
            task_set=task_set,
            mirror_sha256=mirror_sha,
            comparison=comparison(reduction_pct=0.0),
        )
        self.assertEqual(zero["profile_id"], D502A_PROFILE_ID)
        self.assertFalse(zero["measurable_token_benefit"])
        self.assertFalse(zero["promotion_eligible"])
        self.assertIn("D502A_MEASURABLE_TOKEN_BENEFIT_MISSING", zero["failures"])

        positive = _decision(
            source_ref="a" * 40,
            task_set=task_set,
            mirror_sha256=mirror_sha,
            comparison=comparison(reduction_pct=0.000001),
        )
        self.assertTrue(positive["measurable_token_benefit"])
        self.assertTrue(positive["promotion_eligible"])

    def test_quality_or_validator_regression_blocks_promotion_even_with_savings(self):
        task_set = FixedBenchmarkTaskSet.load(REPO_ROOT / D502A_TASK_SET)
        mirror_sha = _mirror_fixture_sha256(task_set, REPO_ROOT)
        for payload in (
            comparison(reduction_pct=25.0, quality=False),
            comparison(reduction_pct=25.0, validators=False),
        ):
            with self.subTest(payload=payload):
                decision = _decision(
                    source_ref="b" * 40,
                    task_set=task_set,
                    mirror_sha256=mirror_sha,
                    comparison=payload,
                )
                self.assertFalse(decision["promotion_eligible"])

    def test_variant_spec_rejects_non_boolean_exact_dedupe(self):
        with self.assertRaises(ValueError):
            BenchmarkVariantSpec("bad", exact_body_dedupe="true").validate()


if __name__ == "__main__":
    unittest.main()
