import json
import re
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from three_agent.benchmark_readiness import BenchmarkReadinessProbe
from three_agent.efficiency_concurrency_observer import (
    EfficiencyConcurrencyObservationError,
    EfficiencyConcurrencyObserver,
    observe_execution_budget_concurrency,
    observe_prefix_reuse_trust_isolation,
    observe_structured_output_concurrency,
    validate_observation_receipt,
)
from three_agent.runtime_efficiency import build_prompt_envelope


ROOT = Path(__file__).resolve().parents[1]
MODEL = "qwen3:30b"


def current_head() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip().lower()


def readiness_receipt(source_ref: str) -> dict:
    outputs = {
        ("git", "rev-parse", "HEAD"): source_ref + "\n",
        ("git", "status", "--porcelain", "--untracked-files=no"): "",
        (
            "nvidia-smi",
            "--query-gpu=name,driver_version,memory.total",
            "--format=csv,noheader,nounits",
        ): "NVIDIA GeForce RTX 5090, 590.00, 32607\nNVIDIA GeForce RTX 5090, 590.00, 32607\n",
        ("ollama", "--version"): "ollama version 0.12.0\n",
        ("ollama", "show", MODEL): "PRIVATE_MODEL_METADATA_MUST_NOT_BE_RECORDED",
    }

    def runner(argv, cwd):
        del cwd
        return outputs[tuple(argv)]

    return BenchmarkReadinessProbe(ROOT, runner=runner).collect(
        source_ref=source_ref,
        model=MODEL,
    )


class FakeStructuredClient:
    def __init__(self, recorder, *, bad_index=None, raise_index=None):
        self.recorder = recorder
        self.bad_index = bad_index
        self.raise_index = raise_index

    def generate_json(
        self,
        system_prompt,
        user_prompt,
        *,
        schema,
        schema_id,
        think,
        num_predict,
        trust_domain,
        template_version,
    ):
        del schema, think, num_predict
        match = re.search(r"Observation index (\d+)", user_prompt)
        index = int(match.group(1))
        time.sleep(0.02)
        envelope = build_prompt_envelope(
            system_prompt,
            user_prompt,
            trust_domain=trust_domain,
            template_version=template_version,
        )
        if self.raise_index == index:
            self.recorder.record(
                model=MODEL,
                envelope=envelope,
                structured=True,
                schema_id=schema_id,
                payload=None,
                success=False,
                wall_duration_ms=20.0,
                error_type="SyntheticFailure",
            )
            raise RuntimeError("RAW_PRIVATE_FAILURE_MUST_NOT_BE_RECORDED")
        self.recorder.record(
            model=MODEL,
            envelope=envelope,
            structured=True,
            schema_id=schema_id,
            payload={
                "prompt_eval_count": 12,
                "eval_count": 4,
                "total_duration": 20_000_000,
                "load_duration": 1_000_000,
                "prompt_eval_duration": 8_000_000,
                "eval_duration": 9_000_000,
            },
            success=True,
            wall_duration_ms=20.0,
        )
        returned_index = index + 1 if self.bad_index == index else index
        return {"ok": True, "index": returned_index}


class EfficiencyConcurrencyObserverTests(unittest.TestCase):
    def test_prefix_reuse_opportunity_isolated_by_trust_domain_without_cache_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = observe_prefix_reuse_trust_isolation(Path(tmp))
        self.assertTrue(report["passed"])
        self.assertFalse(report["cross_domain_reuse_candidate"])
        self.assertTrue(report["same_domain_repeat_reuse_candidate"])
        self.assertFalse(report["backend_cache_hit_claim_present"])
        self.assertFalse(report["backend_cache_isolation_measured"])

    def test_execution_budget_reservations_remain_atomic_under_concurrency(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = observe_execution_budget_concurrency(Path(tmp), concurrency=4)
        self.assertTrue(report["passed"])
        for row in report["dimensions"].values():
            self.assertTrue(row["passed"])
            self.assertEqual(row["reserved"], row["limit"])
            self.assertEqual(row["final_used"], row["limit"])
            self.assertFalse(row["unexpected_failure_types"])

    def test_structured_output_observer_executes_overlapping_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            from three_agent.runtime_efficiency import InferenceTelemetryRecorder

            recorder = InferenceTelemetryRecorder(Path(tmp) / "inference.jsonl")
            report = observe_structured_output_concurrency(
                FakeStructuredClient(recorder),
                concurrency=4,
                samples=8,
            )
        self.assertTrue(report["passed"])
        self.assertEqual(report["succeeded"], 8)
        self.assertEqual(report["semantic_match_count"], 8)
        self.assertGreaterEqual(report["max_in_flight_observed"], 2)
        self.assertFalse(report["failure_types"])

    def test_complete_observation_is_metadata_only_and_not_promotion_evidence(self):
        source = current_head()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            environment = root / "environment.json"
            environment.write_text(
                json.dumps(readiness_receipt(source)),
                encoding="utf-8",
            )

            def factory(config, recorder):
                self.assertEqual(config.model, MODEL)
                return FakeStructuredClient(recorder)

            payload = EfficiencyConcurrencyObserver(
                ROOT,
                client_factory=factory,
            ).collect(
                source_ref=source,
                environment_path=environment,
                model=MODEL,
                concurrency=4,
                samples=8,
            )
            validate_observation_receipt(payload, expected_source_ref=source)

        self.assertTrue(payload["observation_complete"])
        self.assertTrue(payload["claims"]["structured_output_concurrency_observed"])
        self.assertTrue(payload["claims"]["execution_budget_concurrency_observed"])
        self.assertTrue(payload["claims"]["prefix_reuse_trust_domain_isolation_observed"])
        self.assertFalse(payload["claims"]["backend_cache_isolation_measured"])
        self.assertFalse(payload["claims"]["backend_cache_hit_claimed"])
        self.assertFalse(payload["claims"]["resource_benefit_measured"])
        self.assertFalse(payload["claims"]["gpu_active_time_measured"])
        self.assertFalse(payload["claims"]["evaluator_attested"])
        self.assertFalse(payload["claims"]["promotion_evidence_emitted"])
        raw = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("PRIVATE_MODEL_METADATA_MUST_NOT_BE_RECORDED", raw)
        self.assertNotIn("Return only the requested JSON object", raw)
        self.assertNotIn("Observation index", raw)

    def test_semantic_failure_produces_incomplete_but_hash_valid_observation(self):
        source = current_head()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            environment = root / "environment.json"
            environment.write_text(
                json.dumps(readiness_receipt(source)),
                encoding="utf-8",
            )
            payload = EfficiencyConcurrencyObserver(
                ROOT,
                client_factory=lambda config, recorder: FakeStructuredClient(
                    recorder, bad_index=3
                ),
            ).collect(
                source_ref=source,
                environment_path=environment,
                model=MODEL,
                concurrency=4,
                samples=8,
            )
        self.assertFalse(payload["observation_complete"])
        validate_observation_receipt(
            payload,
            expected_source_ref=source,
            require_complete=False,
        )
        with self.assertRaisesRegex(
            EfficiencyConcurrencyObservationError, "incomplete"
        ):
            validate_observation_receipt(payload, expected_source_ref=source)

    def test_tampered_observation_fingerprint_fails_closed(self):
        source = current_head()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            environment = root / "environment.json"
            environment.write_text(
                json.dumps(readiness_receipt(source)),
                encoding="utf-8",
            )
            payload = EfficiencyConcurrencyObserver(
                ROOT,
                client_factory=lambda config, recorder: FakeStructuredClient(recorder),
            ).collect(
                source_ref=source,
                environment_path=environment,
                model=MODEL,
                concurrency=2,
                samples=2,
            )
        payload["claims"]["evaluator_attested"] = True
        with self.assertRaises(EfficiencyConcurrencyObservationError):
            validate_observation_receipt(
                payload,
                expected_source_ref=source,
                require_complete=False,
            )

    def test_readiness_model_mismatch_is_rejected_before_live_requests(self):
        source = current_head()
        with tempfile.TemporaryDirectory() as tmp:
            environment = Path(tmp) / "environment.json"
            environment.write_text(
                json.dumps(readiness_receipt(source)),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                EfficiencyConcurrencyObservationError, "model does not match"
            ):
                EfficiencyConcurrencyObserver(
                    ROOT,
                    client_factory=lambda config, recorder: self.fail(
                        "client must not be constructed"
                    ),
                ).collect(
                    source_ref=source,
                    environment_path=environment,
                    model="different-model:1b",
                    concurrency=2,
                    samples=2,
                )


if __name__ == "__main__":
    unittest.main()
