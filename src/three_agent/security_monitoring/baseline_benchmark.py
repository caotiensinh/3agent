from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Iterable

from .baselines import assess_robust_anomaly, robust_baseline
from .contracts import MonitoringContractError

BENCHMARK_SCHEMA = "workspace-security-monitoring/baseline-benchmark-v1"


@dataclass(frozen=True)
class BaselineBenchmarkCase:
    case_id: str
    history: tuple[float, ...]
    current_value: float
    expected_anomaly: bool


@dataclass(frozen=True)
class BaselineBenchmarkResult:
    case_count: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    detection_rate: float | None
    false_positive_rate: float | None
    evaluated_samples: int
    elapsed_ms: float
    llm_calls: int = 0
    schema_version: str = BENCHMARK_SCHEMA


def run_baseline_benchmark(cases: Iterable[BaselineBenchmarkCase]) -> BaselineBenchmarkResult:
    items = tuple(cases)
    if not 1 <= len(items) <= 1000:
        raise MonitoringContractError("benchmark requires 1..1000 cases")
    started = perf_counter()
    tp = fp = tn = fn = evaluated = 0
    for case in items:
        if len(case.history) > 10000:
            raise MonitoringContractError("benchmark case history exceeds 10000 samples")
        baseline = robust_baseline(case.history, min_samples=5)
        assessment = assess_robust_anomaly(
            case.current_value,
            baseline,
            threshold=6.0,
            absolute_floor=1.0,
        )
        predicted = assessment.status == "anomaly"
        if predicted and case.expected_anomaly:
            tp += 1
        elif predicted and not case.expected_anomaly:
            fp += 1
        elif not predicted and case.expected_anomaly:
            fn += 1
        else:
            tn += 1
        evaluated += len(case.history) + 1
    positives = tp + fn
    negatives = tn + fp
    return BaselineBenchmarkResult(
        case_count=len(items),
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        detection_rate=(tp / positives) if positives else None,
        false_positive_rate=(fp / negatives) if negatives else None,
        evaluated_samples=evaluated,
        elapsed_ms=round((perf_counter() - started) * 1000.0, 6),
    )
