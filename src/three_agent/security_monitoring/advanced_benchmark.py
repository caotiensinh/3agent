from __future__ import annotations

import hashlib
import json
import math
import statistics
import time
import tracemalloc
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable

from .baseline_benchmark import BaselineBenchmarkCase
from .baselines import assess_robust_anomaly, robust_baseline
from .contracts import MonitoringContractError

ADVANCED_BENCHMARK_SCHEMA = "workspace-security-monitoring/advanced-anomaly-benchmark-v1"
FIXTURE_SCHEMA = "workspace-security-monitoring/anomaly-benchmark-fixture-v1"


@dataclass(frozen=True)
class DetectorMetrics:
    detector_id: str
    case_count: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    detection_rate: float | None
    false_positive_rate: float | None
    wall_ms: float
    cpu_ms: float
    peak_allocated_bytes: int
    state_bytes: int
    external_dependencies: int
    complexity_points: int
    security_risk_points: int
    llm_calls: int = 0


@dataclass(frozen=True)
class BenchmarkAdmissionPolicy:
    min_detection_gain: float = 0.05
    max_false_positive_increase: float = 0.0
    max_wall_ms: float = 1000.0
    max_cpu_ms: float = 1000.0
    max_peak_allocated_bytes: int = 8 * 1024 * 1024
    max_state_bytes: int = 2 * 1024 * 1024
    max_external_dependencies: int = 0
    max_complexity_points: int = 3
    max_security_risk_points: int = 0
    min_net_benefit_score: float = 0.03


@dataclass(frozen=True)
class AdvancedBenchmarkResult:
    dataset_fingerprint: str
    baseline: DetectorMetrics
    candidate: DetectorMetrics
    detection_gain: float | None
    false_positive_delta: float | None
    benefit_score: float
    cost_score: float
    benchmark_gate_passed: bool
    decision: str
    reason_codes: tuple[str, ...]
    production_promotion_authorized: bool = False
    schema_version: str = ADVANCED_BENCHMARK_SCHEMA


def _number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise MonitoringContractError(f"{field} must be a finite number")
    return float(value)


def load_fixed_benchmark(path: str | Path) -> tuple[BaselineBenchmarkCase, ...]:
    fixture_path = Path(path)
    payload = json.loads(fixture_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != FIXTURE_SCHEMA:
        raise MonitoringContractError("unsupported anomaly benchmark fixture schema")
    if set(payload) != {"schema_version", "cases"} or not isinstance(payload.get("cases"), list):
        raise MonitoringContractError("invalid anomaly benchmark fixture shape")
    raw_cases = payload["cases"]
    if not 1 <= len(raw_cases) <= 1000:
        raise MonitoringContractError("benchmark fixture requires 1..1000 cases")

    cases: list[BaselineBenchmarkCase] = []
    seen: set[str] = set()
    for raw in raw_cases:
        if not isinstance(raw, dict) or set(raw) != {
            "case_id",
            "history",
            "current_value",
            "expected_anomaly",
        }:
            raise MonitoringContractError("invalid benchmark case shape")
        case_id = str(raw["case_id"] or "").strip()
        if not case_id or len(case_id) > 128 or case_id in seen:
            raise MonitoringContractError("benchmark case_id must be unique and nonempty")
        history_raw = raw["history"]
        if not isinstance(history_raw, list) or not 5 <= len(history_raw) <= 10000:
            raise MonitoringContractError("benchmark history must contain 5..10000 samples")
        history = tuple(_number(value, "history sample") for value in history_raw)
        expected = raw["expected_anomaly"]
        if not isinstance(expected, bool):
            raise MonitoringContractError("expected_anomaly must be boolean")
        cases.append(
            BaselineBenchmarkCase(
                case_id=case_id,
                history=history,
                current_value=_number(raw["current_value"], "current_value"),
                expected_anomaly=expected,
            )
        )
        seen.add(case_id)
    return tuple(cases)


def benchmark_fingerprint(cases: Iterable[BaselineBenchmarkCase]) -> str:
    payload = [
        {
            "case_id": case.case_id,
            "history": list(case.history),
            "current_value": case.current_value,
            "expected_anomaly": case.expected_anomaly,
        }
        for case in cases
    ]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _baseline_predict(case: BaselineBenchmarkCase) -> bool:
    baseline = robust_baseline(case.history, min_samples=5)
    return assess_robust_anomaly(
        case.current_value,
        baseline,
        threshold=6.0,
        absolute_floor=1.0,
    ).status == "anomaly"


def _baseline_state_bytes(case: BaselineBenchmarkCase) -> int:
    baseline = robust_baseline(case.history, min_samples=5)
    payload = {
        "median": baseline.median_value,
        "mad": baseline.mad_value,
        "samples": baseline.sample_count,
        "version": baseline.version,
    }
    return len(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _median(values: list[float]) -> float:
    return float(statistics.median(values))


def _knn_reference_scores(history: tuple[float, ...], *, k: int) -> list[float]:
    scores: list[float] = []
    for index, value in enumerate(history):
        distances = sorted(abs(value - other) for other_index, other in enumerate(history) if other_index != index)
        use = distances[: min(k, len(distances))]
        scores.append(sum(use) / len(use))
    return scores


def knn_distance_predict(case: BaselineBenchmarkCase, *, k: int = 3) -> bool:
    """Tiny dependency-free 1-D kNN anomaly candidate used only by the benchmark lane."""
    if not 1 <= k <= 8 or len(case.history) < 5:
        raise MonitoringContractError("kNN benchmark requires k=1..8 and at least five history samples")
    distances = sorted(abs(case.current_value - value) for value in case.history)
    current_score = sum(distances[: min(k, len(distances))]) / min(k, len(distances))
    reference = _knn_reference_scores(case.history, k=k)
    center = _median(reference)
    deviations = [abs(value - center) for value in reference]
    mad = _median(deviations)
    robust_spread = 1.4826 * mad
    threshold = max(3.0, center + (6.0 * robust_spread))
    return current_score > threshold


def _knn_state_bytes(case: BaselineBenchmarkCase) -> int:
    payload = {"k": 3, "history": list(case.history), "version": "knn-distance-v1"}
    return len(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _profile_detector(
    cases: tuple[BaselineBenchmarkCase, ...],
    *,
    detector_id: str,
    predict: Callable[[BaselineBenchmarkCase], bool],
    state_bytes: Callable[[BaselineBenchmarkCase], int],
    external_dependencies: int,
    complexity_points: int,
    security_risk_points: int,
) -> DetectorMetrics:
    if not cases:
        raise MonitoringContractError("benchmark case set must not be empty")
    already_tracing = tracemalloc.is_tracing()
    if not already_tracing:
        tracemalloc.start()
    tracemalloc.reset_peak()
    wall_started = time.perf_counter()
    cpu_started = time.process_time()
    tp = fp = tn = fn = 0
    stored = 0
    try:
        for case in cases:
            predicted = bool(predict(case))
            stored += max(0, int(state_bytes(case)))
            if predicted and case.expected_anomaly:
                tp += 1
            elif predicted and not case.expected_anomaly:
                fp += 1
            elif not predicted and case.expected_anomaly:
                fn += 1
            else:
                tn += 1
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        if not already_tracing:
            tracemalloc.stop()
    wall_ms = (time.perf_counter() - wall_started) * 1000.0
    cpu_ms = (time.process_time() - cpu_started) * 1000.0
    positives = tp + fn
    negatives = tn + fp
    return DetectorMetrics(
        detector_id=detector_id,
        case_count=len(cases),
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        detection_rate=(tp / positives) if positives else None,
        false_positive_rate=(fp / negatives) if negatives else None,
        wall_ms=round(wall_ms, 6),
        cpu_ms=round(cpu_ms, 6),
        peak_allocated_bytes=int(peak),
        state_bytes=stored,
        external_dependencies=int(external_dependencies),
        complexity_points=int(complexity_points),
        security_risk_points=int(security_risk_points),
    )


def _normalized_cost(candidate: DetectorMetrics, policy: BenchmarkAdmissionPolicy) -> float:
    components = (
        candidate.wall_ms / max(policy.max_wall_ms, 0.001),
        candidate.cpu_ms / max(policy.max_cpu_ms, 0.001),
        candidate.peak_allocated_bytes / max(policy.max_peak_allocated_bytes, 1),
        candidate.state_bytes / max(policy.max_state_bytes, 1),
        candidate.complexity_points / max(policy.max_complexity_points, 1),
        candidate.external_dependencies / max(policy.max_external_dependencies or 1, 1),
        candidate.security_risk_points / max(policy.max_security_risk_points or 1, 1),
    )
    return round(sum(max(0.0, value) for value in components) * 0.01, 6)


def evaluate_candidate(
    *,
    dataset_fingerprint: str,
    baseline: DetectorMetrics,
    candidate: DetectorMetrics,
    policy: BenchmarkAdmissionPolicy | None = None,
) -> AdvancedBenchmarkResult:
    effective = policy or BenchmarkAdmissionPolicy()
    reasons: list[str] = []
    detection_gain: float | None = None
    false_positive_delta: float | None = None
    if baseline.case_count != candidate.case_count or baseline.case_count < 1:
        reasons.append("CASE_SET_NOT_COMPARABLE")
    if baseline.detection_rate is None or candidate.detection_rate is None:
        reasons.append("DETECTION_RATE_UNDEFINED")
    else:
        detection_gain = candidate.detection_rate - baseline.detection_rate
        if detection_gain < effective.min_detection_gain:
            reasons.append("USEFUL_DETECTION_GAIN_NOT_PROVEN")
    if baseline.false_positive_rate is None or candidate.false_positive_rate is None:
        reasons.append("FALSE_POSITIVE_RATE_UNDEFINED")
    else:
        false_positive_delta = candidate.false_positive_rate - baseline.false_positive_rate
        if false_positive_delta > effective.max_false_positive_increase:
            reasons.append("FALSE_POSITIVE_REGRESSION")

    if candidate.wall_ms > effective.max_wall_ms:
        reasons.append("WALL_LATENCY_BUDGET_EXCEEDED")
    if candidate.cpu_ms > effective.max_cpu_ms:
        reasons.append("CPU_BUDGET_EXCEEDED")
    if candidate.peak_allocated_bytes > effective.max_peak_allocated_bytes:
        reasons.append("RAM_BUDGET_EXCEEDED")
    if candidate.state_bytes > effective.max_state_bytes:
        reasons.append("STORAGE_BUDGET_EXCEEDED")
    if candidate.external_dependencies > effective.max_external_dependencies:
        reasons.append("DEPENDENCY_BUDGET_EXCEEDED")
    if candidate.complexity_points > effective.max_complexity_points:
        reasons.append("COMPLEXITY_BUDGET_EXCEEDED")
    if candidate.security_risk_points > effective.max_security_risk_points:
        reasons.append("SECURITY_COST_EXCEEDED")
    if candidate.llm_calls != 0:
        reasons.append("LLM_CALLS_NOT_ALLOWED_IN_ANOMALY_DETECTOR")

    fp_penalty = max(0.0, false_positive_delta or 0.0) * 2.0
    benefit_score = round(max(0.0, detection_gain or 0.0) - fp_penalty, 6)
    cost_score = _normalized_cost(candidate, effective)
    if benefit_score - cost_score < effective.min_net_benefit_score:
        reasons.append("NET_BENEFIT_NOT_PROVEN")

    passed = not reasons
    return AdvancedBenchmarkResult(
        dataset_fingerprint=dataset_fingerprint,
        baseline=baseline,
        candidate=candidate,
        detection_gain=None if detection_gain is None else round(detection_gain, 6),
        false_positive_delta=None if false_positive_delta is None else round(false_positive_delta, 6),
        benefit_score=benefit_score,
        cost_score=cost_score,
        benchmark_gate_passed=passed,
        decision="ELIGIBLE_FOR_REVIEW" if passed else "REJECT_ML_PATH",
        reason_codes=tuple(dict.fromkeys(reasons)),
        production_promotion_authorized=False,
    )


def run_advanced_benchmark(
    cases: Iterable[BaselineBenchmarkCase],
    *,
    policy: BenchmarkAdmissionPolicy | None = None,
) -> AdvancedBenchmarkResult:
    items = tuple(cases)
    if not 1 <= len(items) <= 1000:
        raise MonitoringContractError("advanced benchmark requires 1..1000 cases")
    baseline = _profile_detector(
        items,
        detector_id="median-mad-v1",
        predict=_baseline_predict,
        state_bytes=_baseline_state_bytes,
        external_dependencies=0,
        complexity_points=1,
        security_risk_points=0,
    )
    candidate = _profile_detector(
        items,
        detector_id="knn-distance-v1",
        predict=knn_distance_predict,
        state_bytes=_knn_state_bytes,
        external_dependencies=0,
        complexity_points=2,
        security_risk_points=0,
    )
    return evaluate_candidate(
        dataset_fingerprint=benchmark_fingerprint(items),
        baseline=baseline,
        candidate=candidate,
        policy=policy,
    )


def result_to_json(result: AdvancedBenchmarkResult) -> str:
    return json.dumps(asdict(result), ensure_ascii=False, sort_keys=True, indent=2) + "\n"
