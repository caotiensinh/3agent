from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .benchmark_readiness import load_readiness_receipt
from .config import LLMConfig
from .efficiency_concurrency_observer import (
    PROFILE_ID,
    _bounded_int,
    _canonical_sha256,
    _error_type,
    _model_id,
    _source_ref,
    _verify_checkout,
    aggregate_structured_telemetry,
    observe_structured_output_concurrency,
)
from .llm import OllamaClient
from .runtime_efficiency import InferenceTelemetryRecorder

RESOURCE_BENEFIT_SCHEMA = "workspace-resource-benefit-observation/v1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_STRUCTURED_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "ok": {"type": "boolean"},
        "index": {"type": "integer"},
    },
    "required": ["ok", "index"],
}


class ResourceBenefitObservationError(ValueError):
    """Resource-benefit observation input or metadata is incomplete/unsafe."""


ClientFactory = Callable[[LLMConfig, InferenceTelemetryRecorder], Any]
SamplerFactory = Callable[[], Any]


def _structured_request(client: Any, index: int) -> dict[str, Any]:
    started = time.monotonic()
    try:
        result = client.generate_json(
            "Return only the requested JSON object.",
            f"Observation index {index}. Return ok=true and index exactly {index}.",
            schema=_STRUCTURED_SCHEMA,
            schema_id="workspace-d7-structured-concurrency-v1",
            think=False,
            num_predict=64,
            trust_domain="workspace-d7-efficiency-observation",
            template_version="workspace.d7.efficiency-observe.v1",
        )
        semantic = (
            isinstance(result, dict)
            and result.get("ok") is True
            and result.get("index") == index
            and set(result) == {"ok", "index"}
        )
        return {
            "success": True,
            "semantic_match": semantic,
            "failure_type": None,
            "elapsed_ms": round((time.monotonic() - started) * 1000.0, 3),
        }
    except BaseException as exc:  # raw error content is never persisted
        return {
            "success": False,
            "semantic_match": False,
            "failure_type": _error_type(exc),
            "elapsed_ms": round((time.monotonic() - started) * 1000.0, 3),
        }


def observe_structured_output_serial(client: Any, *, samples: int) -> dict[str, Any]:
    started = time.monotonic()
    rows = [_structured_request(client, index) for index in range(samples)]
    wall_ms = round((time.monotonic() - started) * 1000.0, 3)
    succeeded = sum(1 for row in rows if row["success"] is True)
    semantic = sum(1 for row in rows if row["semantic_match"] is True)
    failures: dict[str, int] = {}
    for row in rows:
        failure = row.get("failure_type")
        if failure:
            failures[str(failure)] = failures.get(str(failure), 0) + 1
    return {
        "passed": succeeded == samples and semantic == samples,
        "attempted": samples,
        "succeeded": succeeded,
        "semantic_match_count": semantic,
        "failure_types": dict(sorted(failures.items())),
        "wall_duration_ms": wall_ms,
    }


def _usage_totals(telemetry: dict[str, Any]) -> dict[str, float | int | None]:
    totals = telemetry.get("measured_usage_totals")
    if not isinstance(totals, dict):
        return {}
    return dict(totals)


def _total_tokens(telemetry: dict[str, Any]) -> int | None:
    totals = _usage_totals(telemetry)
    prompt = totals.get("prompt_eval_count")
    output = totals.get("eval_count")
    if not isinstance(prompt, (int, float)) or isinstance(prompt, bool):
        return None
    if not isinstance(output, (int, float)) or isinstance(output, bool):
        return None
    return int(prompt + output)


def _percent_delta(baseline: float, candidate: float) -> float | None:
    if baseline == 0:
        return None
    return round(((candidate - baseline) / baseline) * 100.0, 6)


class NvidiaSmiSampler:
    """Sample aggregate GPU utilization/power/VRAM without recording device identity."""

    def __init__(
        self,
        *,
        interval_seconds: float = 0.2,
        runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    ) -> None:
        self.interval_seconds = max(0.05, float(interval_seconds))
        self.runner = runner or subprocess.run
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._rows: list[tuple[float, float, float, float]] = []
        self._failure_type: str | None = None
        self._started_at: float | None = None

    @staticmethod
    def parse_sample(text: str) -> tuple[float, float, float]:
        util_total = 0.0
        power_total = 0.0
        vram_total = 0.0
        count = 0
        for line in str(text or "").splitlines():
            if not line.strip():
                continue
            parts = [part.strip() for part in line.split(",")]
            if len(parts) != 3:
                raise ResourceBenefitObservationError("unexpected nvidia-smi sample format")
            try:
                util, power, vram = (float(part) for part in parts)
            except ValueError as exc:
                raise ResourceBenefitObservationError(
                    "nvidia-smi sample must contain numeric aggregate fields"
                ) from exc
            if util < 0 or util > 100 or power < 0 or vram < 0:
                raise ResourceBenefitObservationError("nvidia-smi sample is outside valid bounds")
            util_total += util
            power_total += power
            vram_total += vram
            count += 1
        if count < 1:
            raise ResourceBenefitObservationError("nvidia-smi returned no GPU rows")
        return util_total, power_total, vram_total

    def _sample_once(self) -> None:
        result = self.runner(
            [
                "nvidia-smi",
                "--query-gpu=utilization.gpu,power.draw,memory.used",
                "--format=csv,noheader,nounits",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        util_total, power_total, vram_total = self.parse_sample(result.stdout)
        self._rows.append((time.monotonic(), util_total, power_total, vram_total))

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._sample_once()
            except BaseException as exc:
                self._failure_type = _error_type(exc)
                self._stop.set()
                break
            self._stop.wait(self.interval_seconds)

    def start(self) -> "NvidiaSmiSampler":
        if self._thread is not None:
            raise ResourceBenefitObservationError("GPU sampler already started")
        self._stop.clear()
        self._started_at = time.monotonic()
        self._thread = threading.Thread(
            target=self._loop,
            name="workspace-gpu-sampler",
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self) -> dict[str, Any]:
        if self._thread is None:
            raise ResourceBenefitObservationError("GPU sampler was not started")
        self._stop.set()
        self._thread.join(timeout=15)
        thread_alive = self._thread.is_alive()
        rows = list(self._rows)
        available = bool(rows) and not thread_alive and self._failure_type is None
        util_weighted_gpu_seconds = None
        estimated_energy_j = None
        average_total_utilization_pct = None
        peak_total_vram_used_mib = None
        if available:
            stopped_at = time.monotonic()
            started_at = self._started_at if self._started_at is not None else rows[0][0]
            duration_s = max(0.0, stopped_at - started_at)
            mean_util = sum(row[1] for row in rows) / len(rows)
            mean_power = sum(row[2] for row in rows) / len(rows)
            util_weighted_gpu_seconds = (mean_util / 100.0) * duration_s
            estimated_energy_j = mean_power * duration_s
            average_total_utilization_pct = round(mean_util, 3)
            peak_total_vram_used_mib = round(max(row[3] for row in rows), 3)
            util_weighted_gpu_seconds = round(float(util_weighted_gpu_seconds), 6)
            estimated_energy_j = round(float(estimated_energy_j), 3)
        return {
            "available": available,
            "sample_count": len(rows),
            "sampling_interval_seconds": self.interval_seconds,
            "failure_type": self._failure_type,
            "thread_stopped": not thread_alive,
            "average_total_utilization_pct": average_total_utilization_pct,
            "utilization_weighted_gpu_seconds": util_weighted_gpu_seconds,
            "estimated_energy_j": estimated_energy_j,
            "peak_total_vram_used_mib": peak_total_vram_used_mib,
            "gpu_active_time_measured": False,
            "device_identity_recorded": False,
        }


def _measure_phase(
    client: Any,
    recorder_path: Path,
    sampler_factory: SamplerFactory,
    *,
    mode: str,
    concurrency: int,
    samples: int,
) -> dict[str, Any]:
    sampler = sampler_factory()
    started = time.monotonic()
    sampler.start()
    try:
        if mode == "serial":
            execution = observe_structured_output_serial(client, samples=samples)
        elif mode == "concurrent":
            execution = observe_structured_output_concurrency(
                client, concurrency=concurrency, samples=samples
            )
        else:
            raise ResourceBenefitObservationError(f"unsupported observation mode: {mode}")
    finally:
        gpu = sampler.stop()
    execution = dict(execution)
    execution["wall_duration_ms"] = round(
        (time.monotonic() - started) * 1000.0, 3
    )
    telemetry = aggregate_structured_telemetry(recorder_path)
    total_tokens = _total_tokens(telemetry)
    return {
        "mode": mode,
        "execution": execution,
        "inference_usage": telemetry,
        "total_tokens": total_tokens,
        "gpu_measurement": gpu,
    }


def _gpu_measurement_complete(gpu: Any) -> bool:
    if not isinstance(gpu, dict) or gpu.get("available") is not True:
        return False
    sample_count = gpu.get("sample_count")
    if not isinstance(sample_count, int) or isinstance(sample_count, bool) or sample_count < 1:
        return False
    for field in (
        "utilization_weighted_gpu_seconds",
        "estimated_energy_j",
        "peak_total_vram_used_mib",
    ):
        value = gpu.get(field)
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or float(value) < 0
        ):
            return False
    return (
        gpu.get("gpu_active_time_measured") is False
        and gpu.get("device_identity_recorded") is False
    )


def _derive_comparison(
    serial: dict[str, Any],
    concurrent: dict[str, Any],
    *,
    samples: int,
) -> tuple[dict[str, Any], bool]:
    serial_wall = serial["execution"].get("wall_duration_ms")
    concurrent_wall = concurrent["execution"].get("wall_duration_ms")
    serial_tokens = serial.get("total_tokens")
    concurrent_tokens = concurrent.get("total_tokens")
    serial_gpu = serial["gpu_measurement"]
    concurrent_gpu = concurrent["gpu_measurement"]

    token_measurement = (
        isinstance(serial_tokens, int)
        and not isinstance(serial_tokens, bool)
        and serial_tokens >= 0
        and isinstance(concurrent_tokens, int)
        and not isinstance(concurrent_tokens, bool)
        and concurrent_tokens >= 0
        and serial["inference_usage"].get("event_count") == samples
        and serial["inference_usage"].get("successful_event_count") == samples
        and concurrent["inference_usage"].get("event_count") == samples
        and concurrent["inference_usage"].get("successful_event_count") == samples
    )
    gpu_measurement = (
        _gpu_measurement_complete(serial_gpu)
        and _gpu_measurement_complete(concurrent_gpu)
    )
    semantic_non_regression = (
        serial["execution"].get("passed") is True
        and concurrent["execution"].get("passed") is True
    )
    wall_measurement = (
        isinstance(serial_wall, (int, float))
        and not isinstance(serial_wall, bool)
        and float(serial_wall) >= 0
        and isinstance(concurrent_wall, (int, float))
        and not isinstance(concurrent_wall, bool)
        and float(concurrent_wall) > 0
    )
    complete = (
        token_measurement
        and gpu_measurement
        and semantic_non_regression
        and wall_measurement
    )

    serial_ugpu = serial_gpu.get("utilization_weighted_gpu_seconds")
    concurrent_ugpu = concurrent_gpu.get("utilization_weighted_gpu_seconds")
    serial_energy = serial_gpu.get("estimated_energy_j")
    concurrent_energy = concurrent_gpu.get("estimated_energy_j")

    comparison = {
        "semantic_non_regression_observed": semantic_non_regression,
        "token_measurement_available": token_measurement,
        "gpu_measurement_available": gpu_measurement,
        "serial_wall_duration_ms": serial_wall,
        "concurrent_wall_duration_ms": concurrent_wall,
        "throughput_speedup": (
            round(float(serial_wall) / float(concurrent_wall), 6)
            if complete
            else None
        ),
        "serial_total_tokens": serial_tokens,
        "concurrent_total_tokens": concurrent_tokens,
        "total_token_delta_pct": (
            _percent_delta(float(serial_tokens), float(concurrent_tokens))
            if token_measurement
            else None
        ),
        "serial_utilization_weighted_gpu_seconds": serial_ugpu,
        "concurrent_utilization_weighted_gpu_seconds": concurrent_ugpu,
        "utilization_weighted_gpu_seconds_delta_pct": (
            _percent_delta(float(serial_ugpu), float(concurrent_ugpu))
            if isinstance(serial_ugpu, (int, float))
            and not isinstance(serial_ugpu, bool)
            and isinstance(concurrent_ugpu, (int, float))
            and not isinstance(concurrent_ugpu, bool)
            else None
        ),
        "serial_estimated_energy_j": serial_energy,
        "concurrent_estimated_energy_j": concurrent_energy,
        "estimated_energy_delta_pct": (
            _percent_delta(float(serial_energy), float(concurrent_energy))
            if isinstance(serial_energy, (int, float))
            and not isinstance(serial_energy, bool)
            and isinstance(concurrent_energy, (int, float))
            and not isinstance(concurrent_energy, bool)
            else None
        ),
    }
    return comparison, bool(complete)


class ResourceBenefitObserver:
    """A/B serial vs concurrent measurement. Never self-attests promotion."""

    def __init__(
        self,
        repo_root: Path,
        *,
        client_factory: ClientFactory | None = None,
        sampler_factory: SamplerFactory | None = None,
    ) -> None:
        self.repo_root = Path(repo_root).expanduser().resolve()
        self.client_factory = client_factory or (
            lambda config, recorder: OllamaClient(config, telemetry=recorder)
        )
        self.sampler_factory = sampler_factory or (lambda: NvidiaSmiSampler())

    def collect(
        self,
        *,
        source_ref: str,
        environment_path: Path,
        model: str,
        concurrency: int = 4,
        samples: int = 8,
        base_url: str = "http://127.0.0.1:11434",
        timeout_seconds: int = 1200,
        keep_alive: str = "20m",
    ) -> dict[str, Any]:
        source = _source_ref(source_ref)
        model_id = _model_id(model)
        concurrency_value = _bounded_int(
            concurrency, field="concurrency", minimum=2, maximum=32
        )
        samples_value = _bounded_int(samples, field="samples", minimum=2, maximum=128)
        if samples_value < concurrency_value:
            raise ResourceBenefitObservationError(
                "samples must be greater than or equal to concurrency"
            )
        _verify_checkout(self.repo_root, source)
        readiness = load_readiness_receipt(
            Path(environment_path),
            expected_source_ref=source,
            require_ready=True,
        )
        environment = readiness.get("environment")
        if not isinstance(environment, dict) or environment.get("model") != model_id:
            raise ResourceBenefitObservationError(
                "readiness receipt model does not match observation model"
            )

        config = LLMConfig(
            provider="ollama",
            base_url=str(base_url).rstrip("/"),
            model=model_id,
            timeout_seconds=_bounded_int(
                timeout_seconds,
                field="timeout_seconds",
                minimum=10,
                maximum=3600,
            ),
            keep_alive=str(keep_alive or "20m").strip() or "20m",
        )

        with tempfile.TemporaryDirectory(prefix="workspace-d7-resource-benefit-") as tmp:
            root = Path(tmp)

            warm_telemetry = InferenceTelemetryRecorder(root / "warm" / "inference.jsonl")
            warm_client = self.client_factory(config, warm_telemetry)
            warm = _structured_request(warm_client, 999999)
            if warm["success"] is not True or warm["semantic_match"] is not True:
                raise ResourceBenefitObservationError("warm-up structured request failed")

            serial_path = root / "serial" / "inference.jsonl"
            serial_client = self.client_factory(
                config, InferenceTelemetryRecorder(serial_path)
            )
            serial = _measure_phase(
                serial_client,
                serial_path,
                self.sampler_factory,
                mode="serial",
                concurrency=1,
                samples=samples_value,
            )

            concurrent_path = root / "concurrent" / "inference.jsonl"
            concurrent_client = self.client_factory(
                config, InferenceTelemetryRecorder(concurrent_path)
            )
            concurrent = _measure_phase(
                concurrent_client,
                concurrent_path,
                self.sampler_factory,
                mode="concurrent",
                concurrency=concurrency_value,
                samples=samples_value,
            )

        comparison, resource_benefit_measured = _derive_comparison(
            serial,
            concurrent,
            samples=samples_value,
        )

        payload: dict[str, Any] = {
            "schema_version": RESOURCE_BENEFIT_SCHEMA,
            "profile_id": PROFILE_ID,
            "source_ref": source,
            "captured_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "observation_complete": resource_benefit_measured,
            "environment": {
                "environment_sha256": readiness["environment_sha256"],
                "readiness_receipt_sha256": readiness["receipt_sha256"],
                "model": model_id,
            },
            "experiment": {
                "warmup_requests": 1,
                "samples_per_mode": samples_value,
                "serial_concurrency": 1,
                "candidate_concurrency": concurrency_value,
                "same_model": True,
                "same_prompt_template": True,
                "same_output_schema": True,
            },
            "serial": serial,
            "concurrent": concurrent,
            "comparison": comparison,
            "claims": {
                "resource_benefit_measured": resource_benefit_measured,
                "gpu_utilization_weighted_time_measured": comparison["gpu_measurement_available"],
                "gpu_active_time_measured": False,
                "backend_cache_isolation_measured": False,
                "backend_cache_hit_claimed": False,
                "evaluator_attested": False,
                "promotion_evidence_emitted": False,
            },
            "privacy": {
                "raw_prompt_recorded": False,
                "raw_response_recorded": False,
                "raw_business_data_recorded": False,
                "hostname_recorded": False,
                "username_recorded": False,
                "ip_address_recorded": False,
                "gpu_uuid_or_serial_recorded": False,
                "gpu_process_recorded": False,
            },
        }
        payload["observation_sha256"] = _canonical_sha256(payload)
        return payload


def _validate_phase(phase: Any, *, mode: str, samples: int) -> None:
    if not isinstance(phase, dict) or set(phase) != {
        "mode",
        "execution",
        "inference_usage",
        "total_tokens",
        "gpu_measurement",
    }:
        raise ResourceBenefitObservationError(f"{mode} phase metadata is invalid")
    if phase.get("mode") != mode:
        raise ResourceBenefitObservationError(f"{mode} phase mode mismatch")
    execution = phase["execution"]
    usage = phase["inference_usage"]
    gpu = phase["gpu_measurement"]
    if not isinstance(execution, dict) or not isinstance(usage, dict) or not isinstance(gpu, dict):
        raise ResourceBenefitObservationError(f"{mode} phase metadata is incomplete")
    if not isinstance(execution.get("passed"), bool):
        raise ResourceBenefitObservationError(f"{mode} execution pass flag is invalid")
    if execution.get("attempted") != samples:
        raise ResourceBenefitObservationError(f"{mode} attempted count mismatch")
    if usage.get("event_count") != samples:
        raise ResourceBenefitObservationError(f"{mode} telemetry event count mismatch")
    if not isinstance(gpu.get("available"), bool):
        raise ResourceBenefitObservationError(f"{mode} GPU availability flag is invalid")
    if gpu.get("gpu_active_time_measured") is not False:
        raise ResourceBenefitObservationError(
            f"{mode} GPU sample cannot claim exact GPU active time"
        )
    if gpu.get("device_identity_recorded") is not False:
        raise ResourceBenefitObservationError(
            f"{mode} GPU sample cannot record device identity"
        )
    if gpu["available"] is True:
        sample_count = gpu.get("sample_count")
        if not isinstance(sample_count, int) or isinstance(sample_count, bool) or sample_count < 1:
            raise ResourceBenefitObservationError(f"{mode} GPU sample count is invalid")
        for field in (
            "utilization_weighted_gpu_seconds",
            "estimated_energy_j",
            "peak_total_vram_used_mib",
        ):
            value = gpu.get(field)
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or float(value) < 0
            ):
                raise ResourceBenefitObservationError(
                    f"{mode} GPU measurement {field} is invalid"
                )


def validate_receipt(
    payload: Any,
    *,
    expected_source_ref: str | None = None,
    require_complete: bool = True,
) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema_version") != RESOURCE_BENEFIT_SCHEMA:
        raise ResourceBenefitObservationError(
            f"resource-benefit schema must be {RESOURCE_BENEFIT_SCHEMA}"
        )
    required = {
        "schema_version",
        "profile_id",
        "source_ref",
        "captured_at_utc",
        "observation_complete",
        "environment",
        "experiment",
        "serial",
        "concurrent",
        "comparison",
        "claims",
        "privacy",
        "observation_sha256",
    }
    if set(payload) != required:
        raise ResourceBenefitObservationError(
            "resource-benefit receipt contains unsupported or missing fields"
        )
    if payload.get("profile_id") != PROFILE_ID:
        raise ResourceBenefitObservationError("profile_id mismatch")
    source = _source_ref(payload.get("source_ref"))
    if expected_source_ref is not None and source != _source_ref(expected_source_ref):
        raise ResourceBenefitObservationError("source_ref mismatch")
    if not isinstance(payload.get("observation_complete"), bool):
        raise ResourceBenefitObservationError("observation_complete must be boolean")

    environment = payload.get("environment")
    if not isinstance(environment, dict) or set(environment) != {
        "environment_sha256",
        "readiness_receipt_sha256",
        "model",
    }:
        raise ResourceBenefitObservationError("environment metadata is invalid")
    for key in ("environment_sha256", "readiness_receipt_sha256"):
        if not _SHA256_RE.fullmatch(str(environment.get(key) or "").lower()):
            raise ResourceBenefitObservationError(f"{key} is invalid")
    _model_id(environment.get("model"))

    experiment = payload.get("experiment")
    expected_experiment_keys = {
        "warmup_requests",
        "samples_per_mode",
        "serial_concurrency",
        "candidate_concurrency",
        "same_model",
        "same_prompt_template",
        "same_output_schema",
    }
    if not isinstance(experiment, dict) or set(experiment) != expected_experiment_keys:
        raise ResourceBenefitObservationError("experiment metadata is invalid")
    samples = experiment.get("samples_per_mode")
    candidate_concurrency = experiment.get("candidate_concurrency")
    if (
        not isinstance(samples, int)
        or isinstance(samples, bool)
        or not 2 <= samples <= 128
        or not isinstance(candidate_concurrency, int)
        or isinstance(candidate_concurrency, bool)
        or not 2 <= candidate_concurrency <= 32
        or samples < candidate_concurrency
        or experiment.get("warmup_requests") != 1
        or experiment.get("serial_concurrency") != 1
        or experiment.get("same_model") is not True
        or experiment.get("same_prompt_template") is not True
        or experiment.get("same_output_schema") is not True
    ):
        raise ResourceBenefitObservationError("experiment invariants are invalid")

    _validate_phase(payload.get("serial"), mode="serial", samples=samples)
    _validate_phase(payload.get("concurrent"), mode="concurrent", samples=samples)
    expected_comparison, derived_complete = _derive_comparison(
        payload["serial"],
        payload["concurrent"],
        samples=samples,
    )
    if payload.get("comparison") != expected_comparison:
        raise ResourceBenefitObservationError("comparison does not match measured phase data")

    claims = payload.get("claims")
    expected_claim_keys = {
        "resource_benefit_measured",
        "gpu_utilization_weighted_time_measured",
        "gpu_active_time_measured",
        "backend_cache_isolation_measured",
        "backend_cache_hit_claimed",
        "evaluator_attested",
        "promotion_evidence_emitted",
    }
    if not isinstance(claims, dict) or set(claims) != expected_claim_keys or any(
        not isinstance(value, bool) for value in claims.values()
    ):
        raise ResourceBenefitObservationError("claims are invalid")
    if claims["resource_benefit_measured"] is not derived_complete:
        raise ResourceBenefitObservationError("resource-benefit derived claim mismatch")
    if claims["gpu_utilization_weighted_time_measured"] is not expected_comparison[
        "gpu_measurement_available"
    ]:
        raise ResourceBenefitObservationError("GPU-time proxy claim mismatch")
    if claims["gpu_active_time_measured"] is not False:
        raise ResourceBenefitObservationError(
            "nvidia-smi utilization sampling cannot claim exact GPU active time"
        )
    for forbidden in (
        "backend_cache_isolation_measured",
        "backend_cache_hit_claimed",
        "evaluator_attested",
        "promotion_evidence_emitted",
    ):
        if claims[forbidden] is not False:
            raise ResourceBenefitObservationError(
                f"resource-benefit observer cannot self-claim {forbidden}"
            )
    if payload["observation_complete"] is not derived_complete:
        raise ResourceBenefitObservationError("observation completeness claim mismatch")

    privacy = payload.get("privacy")
    if not isinstance(privacy, dict) or not privacy or any(
        value is not False for value in privacy.values()
    ):
        raise ResourceBenefitObservationError("privacy boundary is invalid")

    claim = str(payload.get("observation_sha256") or "").lower()
    if not _SHA256_RE.fullmatch(claim):
        raise ResourceBenefitObservationError("observation_sha256 is invalid")
    unsigned = dict(payload)
    unsigned.pop("observation_sha256", None)
    if _canonical_sha256(unsigned) != claim:
        raise ResourceBenefitObservationError("observation fingerprint mismatch")
    if require_complete and payload["observation_complete"] is not True:
        raise ResourceBenefitObservationError("resource-benefit observation is incomplete")
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workspace-eval-resource-benefit",
        description=(
            "Measure serial-vs-concurrent WorkSpace resource benefit using metadata-only "
            "token and aggregate nvidia-smi telemetry without claiming cache hits or "
            "exact GPU active time."
        ),
    )
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--environment", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--samples", type=int, default=8)
    parser.add_argument("--base-url", default="http://127.0.0.1:11434")
    parser.add_argument("--timeout-seconds", type=int, default=1200)
    parser.add_argument("--keep-alive", default="20m")
    parser.add_argument("--output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    destination = Path(args.output)
    try:
        payload = ResourceBenefitObserver(Path(args.repo_root)).collect(
            source_ref=args.source_ref,
            environment_path=Path(args.environment),
            model=args.model,
            concurrency=args.concurrency,
            samples=args.samples,
            base_url=args.base_url,
            timeout_seconds=args.timeout_seconds,
            keep_alive=args.keep_alive,
        )
        validate_receipt(
            payload,
            expected_source_ref=args.source_ref,
            require_complete=False,
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + ".tmp")
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(destination)
    except (
        OSError,
        json.JSONDecodeError,
        ResourceBenefitObservationError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {
                    "schema_version": RESOURCE_BENEFIT_SCHEMA,
                    "observation_complete": False,
                    "failure_type": _error_type(exc),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 3
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload["observation_complete"] is True else 3


if __name__ == "__main__":
    raise SystemExit(main())
