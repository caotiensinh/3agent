from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
import tempfile
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .benchmark_readiness import load_readiness_receipt
from .config import LLMConfig
from .execution_budget import ExecutionBudgetExceeded, TaskExecutionBudgetState
from .llm import OllamaClient
from .runtime_efficiency import InferenceTelemetryRecorder, build_prompt_envelope
from .store import TaskStore
from .task_contract import TaskContractCompiler

OBSERVATION_SCHEMA = "workspace-efficiency-concurrency-observation/v1"
PROFILE_ID = "workspace-efficiency-cache-concurrency-v1"
_SOURCE_REF_RE = re.compile(r"^[0-9a-f]{40}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+\-]{0,127}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ERROR_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,79}$")


class EfficiencyConcurrencyObservationError(ValueError):
    """D7-06 observation input or evidence is incomplete or unsafe."""


ClientFactory = Callable[[LLMConfig, InferenceTelemetryRecorder], Any]


_STRUCTURED_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "ok": {"type": "boolean"},
        "index": {"type": "integer"},
    },
    "required": ["ok", "index"],
}


def _canonical_sha256(payload: Any) -> str:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _source_ref(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not _SOURCE_REF_RE.fullmatch(text):
        raise EfficiencyConcurrencyObservationError(
            "source_ref must be an exact 40-hex Git SHA"
        )
    return text


def _model_id(value: Any) -> str:
    text = str(value or "").strip()
    if not _MODEL_RE.fullmatch(text):
        raise EfficiencyConcurrencyObservationError(
            "model must be a compact local model identifier"
        )
    return text


def _bounded_int(value: Any, *, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise EfficiencyConcurrencyObservationError(f"{field} must be an integer")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise EfficiencyConcurrencyObservationError(f"{field} must be an integer") from exc
    if not minimum <= result <= maximum:
        raise EfficiencyConcurrencyObservationError(
            f"{field} must be between {minimum} and {maximum}"
        )
    return result


def _error_type(exc: BaseException) -> str:
    name = type(exc).__name__
    return name if _ERROR_RE.fullmatch(name) else "ObservationError"


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(float(item) for item in values)
    index = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return round(ordered[index], 3)


def _verify_checkout(repo_root: Path, source_ref: str) -> None:
    root = Path(repo_root).expanduser().resolve()
    try:
        head = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip().lower()
        dirty = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise EfficiencyConcurrencyObservationError(
            "exact source checkout is not readable"
        ) from exc
    if head != source_ref:
        raise EfficiencyConcurrencyObservationError("checkout HEAD does not match source_ref")
    if dirty:
        raise EfficiencyConcurrencyObservationError("tracked checkout must be clean")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not Path(path).exists():
        return rows
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EfficiencyConcurrencyObservationError(
                "metadata telemetry contains invalid JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise EfficiencyConcurrencyObservationError(
                "metadata telemetry row must be an object"
            )
        rows.append(payload)
    return rows


def observe_prefix_reuse_trust_isolation(root: Path) -> dict[str, Any]:
    """Verify WorkSpace reuse-opportunity metadata does not cross trust domains.

    This deliberately does not claim anything about an inference backend's own cache.
    """

    telemetry = Path(root) / "prefix-reuse.jsonl"
    recorder = InferenceTelemetryRecorder(telemetry)
    sequence = (
        ("workspace-internal-a", "first"),
        ("workspace-internal-b", "second"),
        ("workspace-internal-a", "third"),
    )
    for trust_domain, suffix in sequence:
        envelope = build_prompt_envelope(
            "stable observation system prefix",
            suffix,
            template_version="workspace.d7.efficiency-observe.v1",
            trust_domain=trust_domain,
        )
        recorder.record(
            model="observation-model",
            envelope=envelope,
            structured=True,
            schema_id="observation-schema-v1",
            payload=None,
            success=True,
            wall_duration_ms=0.0,
        )
    rows = _read_jsonl(telemetry)
    candidates = [row.get("prefix_reuse_candidate") for row in rows]
    forbidden_claim_present = any(
        "cache_hit" in row or "backend_cache_hit" in row for row in rows
    )
    passed = candidates == [False, False, True] and not forbidden_claim_present
    return {
        "passed": passed,
        "observation_count": len(rows),
        "cross_domain_reuse_candidate": bool(candidates[1]) if len(candidates) > 1 else None,
        "same_domain_repeat_reuse_candidate": bool(candidates[2]) if len(candidates) > 2 else None,
        "backend_cache_hit_claim_present": forbidden_claim_present,
        "backend_cache_isolation_measured": False,
    }


def _budget_state(root: Path) -> TaskExecutionBudgetState:
    store = TaskStore(Path(root) / "tasks.db")
    store.initialize()
    task = store.create_task("d7-concurrency-observation", "synthetic metadata-only observation")
    contract = TaskContractCompiler().compile(
        task_id=task.task_id,
        task_type="analysis",
        sensitivity="internal",
        risk_level="low",
    )
    store.bind_task_contract(task.task_id, contract.to_dict())
    return TaskExecutionBudgetState.from_bound_contract(store, task.task_id)


def _observe_budget_dimension(
    root: Path,
    *,
    name: str,
    concurrency: int,
    limit: int,
    reserve_kwargs: dict[str, int],
    snapshot_field: str,
    expected_exhaustion: str,
) -> dict[str, Any]:
    if limit < 1 or limit > 128:
        raise EfficiencyConcurrencyObservationError(
            f"unexpected {name} budget outside observation bounds"
        )
    state = _budget_state(Path(root) / name)
    attempts = limit + concurrency
    first_wave = min(concurrency, attempts)
    barrier = threading.Barrier(first_wave) if first_wave > 1 else None

    def reserve(index: int) -> str:
        if barrier is not None and index < first_wave:
            barrier.wait(timeout=10)
        try:
            state.reserve(**reserve_kwargs)
            return "reserved"
        except ExecutionBudgetExceeded as exc:
            return exc.reason_code
        except BaseException as exc:  # evidence records type only, never raw exception text
            return _error_type(exc)

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        outcomes = list(pool.map(reserve, range(attempts)))
    counts = Counter(outcomes)
    final_used = int(state.snapshot()[snapshot_field])
    unexpected = {
        key: value
        for key, value in counts.items()
        if key not in {"reserved", expected_exhaustion}
    }
    passed = (
        counts.get("reserved", 0) == limit
        and counts.get(expected_exhaustion, 0) == attempts - limit
        and not unexpected
        and final_used == limit
    )
    return {
        "passed": passed,
        "limit": limit,
        "attempts": attempts,
        "reserved": counts.get("reserved", 0),
        "exhausted": counts.get(expected_exhaustion, 0),
        "unexpected_failure_types": dict(sorted(unexpected.items())),
        "final_used": final_used,
        "expected_exhaustion_code": expected_exhaustion,
    }


def observe_execution_budget_concurrency(root: Path, *, concurrency: int) -> dict[str, Any]:
    probe = _budget_state(Path(root) / "limits")
    specs = (
        (
            "tool_calls",
            int(probe.max_tool_calls),
            {"tool_calls": 1},
            "tool_calls_used",
            "TASK_TOOL_CALL_BUDGET_EXHAUSTED",
        ),
        (
            "model_retries",
            int(probe.max_model_retries),
            {"retries": 1},
            "model_retries_used",
            "MODEL_RETRY_BUDGET_EXHAUSTED",
        ),
        (
            "model_escalations",
            int(probe.max_model_escalations),
            {"escalations": 1},
            "model_escalations_used",
            "MODEL_ESCALATION_BUDGET_EXHAUSTED",
        ),
    )
    dimensions: dict[str, Any] = {}
    for name, limit, kwargs, snapshot_field, exhaustion in specs:
        dimensions[name] = _observe_budget_dimension(
            Path(root),
            name=name,
            concurrency=concurrency,
            limit=limit,
            reserve_kwargs=kwargs,
            snapshot_field=snapshot_field,
            expected_exhaustion=exhaustion,
        )
    return {
        "passed": all(item["passed"] is True for item in dimensions.values()),
        "concurrency": concurrency,
        "dimensions": dimensions,
    }


def observe_structured_output_concurrency(
    client: Any,
    *,
    concurrency: int,
    samples: int,
) -> dict[str, Any]:
    workers = min(concurrency, samples)
    barrier = threading.Barrier(workers) if workers > 1 else None
    active_lock = threading.Lock()
    active = 0
    max_active = 0

    def run(index: int) -> dict[str, Any]:
        nonlocal active, max_active
        if barrier is not None and index < workers:
            barrier.wait(timeout=30)
        started = time.monotonic()
        with active_lock:
            active += 1
            max_active = max(max_active, active)
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
        except BaseException as exc:  # raw model/error content is intentionally discarded
            return {
                "success": False,
                "semantic_match": False,
                "failure_type": _error_type(exc),
                "elapsed_ms": round((time.monotonic() - started) * 1000.0, 3),
            }
        finally:
            with active_lock:
                active -= 1

    rows: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(run, index) for index in range(samples)]
        for future in as_completed(futures):
            rows.append(future.result())

    latencies = [float(row["elapsed_ms"]) for row in rows]
    failures = Counter(
        str(row["failure_type"])
        for row in rows
        if row.get("failure_type") is not None
    )
    succeeded = sum(1 for row in rows if row["success"] is True)
    semantic = sum(1 for row in rows if row["semantic_match"] is True)
    concurrency_observed = max_active >= 2
    passed = succeeded == samples and semantic == samples and concurrency_observed
    return {
        "passed": passed,
        "attempted": samples,
        "succeeded": succeeded,
        "semantic_match_count": semantic,
        "concurrency_requested": concurrency,
        "max_in_flight_observed": max_active,
        "concurrency_observed": concurrency_observed,
        "failure_types": dict(sorted(failures.items())),
        "latency_ms": {
            "min": round(min(latencies), 3) if latencies else None,
            "p50": _percentile(latencies, 0.50),
            "p95": _percentile(latencies, 0.95),
            "max": round(max(latencies), 3) if latencies else None,
        },
    }


def aggregate_structured_telemetry(path: Path) -> dict[str, Any]:
    rows = _read_jsonl(path)
    structured = [
        row
        for row in rows
        if row.get("schema_version") == "workspace-inference-telemetry/v2"
        and row.get("structured") is True
    ]
    usage_fields = (
        "prompt_eval_count",
        "eval_count",
        "total_duration_ns",
        "load_duration_ns",
        "prompt_eval_duration_ns",
        "eval_duration_ns",
        "wall_duration_ms",
    )
    totals: dict[str, float | int | None] = {}
    for field in usage_fields:
        values = [
            row.get("usage", {}).get(field)
            for row in structured
            if isinstance(row.get("usage"), dict)
            and isinstance(row.get("usage", {}).get(field), (int, float))
            and not isinstance(row.get("usage", {}).get(field), bool)
        ]
        totals[field] = round(sum(values), 3) if values else None
    return {
        "event_count": len(structured),
        "successful_event_count": sum(1 for row in structured if row.get("success") is True),
        "prefix_reuse_candidate_count": sum(
            1 for row in structured if row.get("prefix_reuse_candidate") is True
        ),
        "measured_usage_totals": totals,
        "backend_cache_hit_measured": False,
        "gpu_active_time_measured": False,
    }


class EfficiencyConcurrencyObserver:
    """Collect D7-06 precursor observations without self-attesting promotion PASS."""

    def __init__(
        self,
        repo_root: Path,
        *,
        client_factory: ClientFactory | None = None,
    ):
        self.repo_root = Path(repo_root).expanduser().resolve()
        self.client_factory = client_factory or (
            lambda config, recorder: OllamaClient(config, telemetry=recorder)
        )

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
            raise EfficiencyConcurrencyObservationError(
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
            raise EfficiencyConcurrencyObservationError(
                "readiness receipt model does not match observation model"
            )

        with tempfile.TemporaryDirectory(prefix="workspace-d7-efficiency-") as tmp:
            temp_root = Path(tmp)
            prefix_isolation = observe_prefix_reuse_trust_isolation(temp_root / "prefix")
            budget = observe_execution_budget_concurrency(
                temp_root / "budget",
                concurrency=concurrency_value,
            )
            telemetry_path = temp_root / "structured" / "inference.jsonl"
            recorder = InferenceTelemetryRecorder(telemetry_path)
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
            client = self.client_factory(config, recorder)
            structured = observe_structured_output_concurrency(
                client,
                concurrency=concurrency_value,
                samples=samples_value,
            )
            telemetry = aggregate_structured_telemetry(telemetry_path)

        observation_complete = (
            prefix_isolation["passed"] is True
            and budget["passed"] is True
            and structured["passed"] is True
            and telemetry["event_count"] == samples_value
            and telemetry["successful_event_count"] == samples_value
        )
        payload: dict[str, Any] = {
            "schema_version": OBSERVATION_SCHEMA,
            "profile_id": PROFILE_ID,
            "source_ref": source,
            "captured_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "observation_complete": observation_complete,
            "environment": {
                "environment_sha256": readiness["environment_sha256"],
                "readiness_receipt_sha256": readiness["receipt_sha256"],
                "model": model_id,
            },
            "structured_output_concurrency": structured,
            "execution_budget_concurrency": budget,
            "prefix_reuse_trust_isolation": prefix_isolation,
            "inference_usage": telemetry,
            "claims": {
                "structured_output_concurrency_observed": structured["passed"] is True,
                "execution_budget_concurrency_observed": budget["passed"] is True,
                "prefix_reuse_trust_domain_isolation_observed": prefix_isolation["passed"] is True,
                "backend_cache_isolation_measured": False,
                "backend_cache_hit_claimed": False,
                "resource_benefit_measured": False,
                "gpu_active_time_measured": False,
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
            },
        }
        payload["observation_sha256"] = _canonical_sha256(payload)
        return payload


def validate_observation_receipt(
    payload: Any,
    *,
    expected_source_ref: str | None = None,
    require_complete: bool = True,
) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema_version") != OBSERVATION_SCHEMA:
        raise EfficiencyConcurrencyObservationError(
            f"observation schema must be {OBSERVATION_SCHEMA}"
        )
    required = {
        "schema_version",
        "profile_id",
        "source_ref",
        "captured_at_utc",
        "observation_complete",
        "environment",
        "structured_output_concurrency",
        "execution_budget_concurrency",
        "prefix_reuse_trust_isolation",
        "inference_usage",
        "claims",
        "privacy",
        "observation_sha256",
    }
    if set(payload) != required:
        raise EfficiencyConcurrencyObservationError(
            "observation contains unsupported or missing fields"
        )
    if payload.get("profile_id") != PROFILE_ID:
        raise EfficiencyConcurrencyObservationError("observation profile_id mismatch")
    source = _source_ref(payload.get("source_ref"))
    if expected_source_ref is not None and source != _source_ref(expected_source_ref):
        raise EfficiencyConcurrencyObservationError("observation source_ref mismatch")
    if not isinstance(payload.get("observation_complete"), bool):
        raise EfficiencyConcurrencyObservationError(
            "observation_complete must be boolean"
        )
    claims = payload.get("claims")
    if not isinstance(claims, dict):
        raise EfficiencyConcurrencyObservationError("claims must be an object")
    forbidden_true = (
        "backend_cache_isolation_measured",
        "backend_cache_hit_claimed",
        "resource_benefit_measured",
        "gpu_active_time_measured",
        "evaluator_attested",
        "promotion_evidence_emitted",
    )
    if any(claims.get(name) is not False for name in forbidden_true):
        raise EfficiencyConcurrencyObservationError(
            "observation cannot self-claim cache/resource/GPU measurement, attestation, or promotion"
        )
    privacy = payload.get("privacy")
    if not isinstance(privacy, dict) or not privacy or any(
        value is not False for value in privacy.values()
    ):
        raise EfficiencyConcurrencyObservationError("observation privacy boundary is invalid")
    environment = payload.get("environment")
    if not isinstance(environment, dict):
        raise EfficiencyConcurrencyObservationError("environment must be an object")
    for key in ("environment_sha256", "readiness_receipt_sha256"):
        if not _SHA256_RE.fullmatch(str(environment.get(key) or "")):
            raise EfficiencyConcurrencyObservationError(f"{key} is invalid")
    claim = str(payload.get("observation_sha256") or "").lower()
    if not _SHA256_RE.fullmatch(claim):
        raise EfficiencyConcurrencyObservationError("observation_sha256 is invalid")
    unsigned = dict(payload)
    unsigned.pop("observation_sha256", None)
    if _canonical_sha256(unsigned) != claim:
        raise EfficiencyConcurrencyObservationError("observation fingerprint mismatch")
    if require_complete and payload["observation_complete"] is not True:
        raise EfficiencyConcurrencyObservationError("observation is incomplete")
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workspace-eval-efficiency-observe",
        description=(
            "Collect metadata-only D7-06 structured-output/budget/reuse observations "
            "without self-attesting promotion evidence."
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
        payload = EfficiencyConcurrencyObserver(Path(args.repo_root)).collect(
            source_ref=args.source_ref,
            environment_path=Path(args.environment),
            model=args.model,
            concurrency=args.concurrency,
            samples=args.samples,
            base_url=args.base_url,
            timeout_seconds=args.timeout_seconds,
            keep_alive=args.keep_alive,
        )
        validate_observation_receipt(
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
        EfficiencyConcurrencyObservationError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {
                    "schema_version": OBSERVATION_SCHEMA,
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
