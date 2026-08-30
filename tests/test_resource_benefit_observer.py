import json
import re
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from three_agent.benchmark_readiness import BenchmarkReadinessProbe
from three_agent.resource_benefit_observer import (
    NvidiaSmiSampler,
    ResourceBenefitObservationError,
    ResourceBenefitObserver,
    _canonical_sha256,
    validate_receipt,
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
        ): (
            "NVIDIA GeForce RTX 5090, 590.00, 32607\n"
            "NVIDIA GeForce RTX 5090, 590.00, 32607\n"
        ),
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


class FakeClient:
    def __init__(self, recorder):
        self.recorder = recorder

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
        match = re.search(r"Observation index (-?\d+)", user_prompt)
        index = int(match.group(1))
        time.sleep(0.02)
        envelope = build_prompt_envelope(
            system_prompt,
            user_prompt,
            trust_domain=trust_domain,
            template_version=template_version,
        )
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
        return {"ok": True, "index": index}


class FakeSampler:
    def __init__(self, *, available=True):
        self.available = available

    def start(self):
        return self

    def stop(self):
        return {
            "available": self.available,
            "sample_count": 4 if self.available else 0,
            "sampling_interval_seconds": 0.2,
            "failure_type": None if self.available else "SamplerUnavailable",
            "thread_stopped": True,
            "average_total_utilization_pct": 100.0 if self.available else None,
            "utilization_weighted_gpu_seconds": 0.25 if self.available else None,
            "estimated_energy_j": 50.0 if self.available else None,
            "peak_total_vram_used_mib": 20000.0 if self.available else None,
            "gpu_active_time_measured": False,
            "device_identity_recorded": False,
        }


class ResourceBenefitObserverTests(unittest.TestCase):
    def test_nvidia_smi_parser_accepts_only_numeric_aggregate_fields(self):
        util, power, vram = NvidiaSmiSampler.parse_sample(
            "50, 120.5, 1000\n75, 130.5, 2000\n"
        )
        self.assertEqual(util, 125.0)
        self.assertEqual(power, 251.0)
        self.assertEqual(vram, 3000.0)
        with self.assertRaises(ResourceBenefitObservationError):
            NvidiaSmiSampler.parse_sample("GPU-UUID, 120, 1000")

    def test_serial_vs_concurrent_measurement_is_complete_and_metadata_only(self):
        source = current_head()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            environment = root / "environment.json"
            environment.write_text(
                json.dumps(readiness_receipt(source)),
                encoding="utf-8",
            )
            payload = ResourceBenefitObserver(
                ROOT,
                client_factory=lambda config, recorder: FakeClient(recorder),
                sampler_factory=lambda: FakeSampler(),
            ).collect(
                source_ref=source,
                environment_path=environment,
                model=MODEL,
                concurrency=4,
                samples=8,
            )
            validate_receipt(payload, expected_source_ref=source)

        self.assertTrue(payload["observation_complete"])
        self.assertTrue(payload["claims"]["resource_benefit_measured"])
        self.assertTrue(
            payload["claims"]["gpu_utilization_weighted_time_measured"]
        )
        self.assertFalse(payload["claims"]["gpu_active_time_measured"])
        self.assertFalse(payload["claims"]["backend_cache_hit_claimed"])
        self.assertFalse(payload["claims"]["evaluator_attested"])
        self.assertEqual(payload["serial"]["total_tokens"], 128)
        self.assertEqual(payload["concurrent"]["total_tokens"], 128)
        self.assertGreater(
            payload["comparison"]["throughput_speedup"],
            1.0,
        )
        raw = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("PRIVATE_MODEL_METADATA_MUST_NOT_BE_RECORDED", raw)
        self.assertNotIn("Return only the requested JSON object", raw)
        self.assertNotIn("Observation index", raw)
        self.assertNotIn("GPU-UUID", raw)

    def test_missing_gpu_measurement_fails_closed_without_cache_claim(self):
        source = current_head()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            environment = root / "environment.json"
            environment.write_text(
                json.dumps(readiness_receipt(source)),
                encoding="utf-8",
            )
            payload = ResourceBenefitObserver(
                ROOT,
                client_factory=lambda config, recorder: FakeClient(recorder),
                sampler_factory=lambda: FakeSampler(available=False),
            ).collect(
                source_ref=source,
                environment_path=environment,
                model=MODEL,
                concurrency=2,
                samples=2,
            )
        self.assertFalse(payload["observation_complete"])
        self.assertFalse(payload["claims"]["resource_benefit_measured"])
        self.assertFalse(
            payload["claims"]["gpu_utilization_weighted_time_measured"]
        )
        self.assertFalse(payload["claims"]["backend_cache_hit_claimed"])
        validate_receipt(
            payload,
            expected_source_ref=source,
            require_complete=False,
        )
        with self.assertRaisesRegex(
            ResourceBenefitObservationError, "incomplete"
        ):
            validate_receipt(payload, expected_source_ref=source)

    def test_receipt_cannot_self_attest_or_claim_exact_gpu_active_time(self):
        source = current_head()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            environment = root / "environment.json"
            environment.write_text(
                json.dumps(readiness_receipt(source)),
                encoding="utf-8",
            )
            payload = ResourceBenefitObserver(
                ROOT,
                client_factory=lambda config, recorder: FakeClient(recorder),
                sampler_factory=lambda: FakeSampler(),
            ).collect(
                source_ref=source,
                environment_path=environment,
                model=MODEL,
                concurrency=2,
                samples=2,
            )
        payload["claims"]["evaluator_attested"] = True
        with self.assertRaises(ResourceBenefitObservationError):
            validate_receipt(
                payload,
                expected_source_ref=source,
                require_complete=False,
            )

        payload["claims"]["evaluator_attested"] = False
        payload["claims"]["gpu_active_time_measured"] = True
        with self.assertRaisesRegex(
            ResourceBenefitObservationError, "exact GPU active time"
        ):
            validate_receipt(
                payload,
                expected_source_ref=source,
                require_complete=False,
            )

    def test_rehashed_false_resource_claim_is_rejected_by_derived_validation(self):
        source = current_head()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            environment = root / "environment.json"
            environment.write_text(
                json.dumps(readiness_receipt(source)),
                encoding="utf-8",
            )
            payload = ResourceBenefitObserver(
                ROOT,
                client_factory=lambda config, recorder: FakeClient(recorder),
                sampler_factory=lambda: FakeSampler(),
            ).collect(
                source_ref=source,
                environment_path=environment,
                model=MODEL,
                concurrency=2,
                samples=2,
            )

        payload["serial"]["gpu_measurement"]["available"] = False
        payload["comparison"]["gpu_measurement_available"] = False
        payload["claims"]["gpu_utilization_weighted_time_measured"] = False
        payload["claims"]["resource_benefit_measured"] = True
        payload["observation_complete"] = True
        unsigned = dict(payload)
        unsigned.pop("observation_sha256", None)
        payload["observation_sha256"] = _canonical_sha256(unsigned)

        with self.assertRaisesRegex(
            ResourceBenefitObservationError, "comparison|derived claim"
        ):
            validate_receipt(
                payload,
                expected_source_ref=source,
                require_complete=False,
            )


if __name__ == "__main__":
    unittest.main()
