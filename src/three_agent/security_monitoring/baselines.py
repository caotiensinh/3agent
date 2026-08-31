from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from statistics import median
from typing import Iterable

from .contracts import MonitoringContractError, _compact

BASELINE_VERSION = "workspace-security-monitoring/baseline-v1"


@dataclass(frozen=True)
class RobustBaseline:
    sample_count: int
    median_value: float | None
    mad: float | None
    warm: bool
    version: str = BASELINE_VERSION


@dataclass(frozen=True)
class BaselineAssessment:
    status: str
    reason_code: str
    value: float
    center: float | None
    deviation_score: float | None
    baseline_version: str = BASELINE_VERSION


@dataclass(frozen=True)
class EwmaState:
    value: float | None = None
    sample_count: int = 0
    alpha: float = 0.2
    version: str = BASELINE_VERSION

    def validate(self) -> "EwmaState":
        if not 0.01 <= float(self.alpha) <= 1.0:
            raise MonitoringContractError("EWMA alpha must be within [0.01,1]")
        if self.sample_count < 0:
            raise MonitoringContractError("EWMA sample_count must be non-negative")
        if self.sample_count == 0 and self.value is not None:
            raise MonitoringContractError("empty EWMA cannot contain a value")
        return self

    def update(self, sample: float) -> "EwmaState":
        self.validate()
        current = float(sample)
        next_value = current if self.value is None else (self.alpha * current + (1.0 - self.alpha) * self.value)
        return EwmaState(
            value=next_value,
            sample_count=self.sample_count + 1,
            alpha=self.alpha,
        ).validate()


@dataclass(frozen=True)
class MaintenanceWindow:
    change_id: str
    starts_at: str
    ends_at: str
    asset_refs: tuple[str, ...]
    category_prefixes: tuple[str, ...] = ()

    def validate(self) -> "MaintenanceWindow":
        object.__setattr__(self, "change_id", _compact(self.change_id, "change_id", max_len=128))
        start = datetime.fromisoformat(self.starts_at.replace("Z", "+00:00"))
        end = datetime.fromisoformat(self.ends_at.replace("Z", "+00:00"))
        if start.tzinfo is None or end.tzinfo is None or end <= start:
            raise MonitoringContractError("maintenance window must have ordered timezone-aware timestamps")
        assets = tuple(_compact(value, "asset_ref", max_len=128) for value in self.asset_refs)
        if not assets:
            raise MonitoringContractError("maintenance window requires asset_refs")
        object.__setattr__(self, "asset_refs", assets)
        object.__setattr__(
            self,
            "category_prefixes",
            tuple(_compact(value, "category_prefix", max_len=96) for value in self.category_prefixes),
        )
        return self

    def matches(self, *, asset_id: str, category: str, observed_at: str) -> bool:
        self.validate()
        observed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        start = datetime.fromisoformat(self.starts_at.replace("Z", "+00:00"))
        end = datetime.fromisoformat(self.ends_at.replace("Z", "+00:00"))
        if observed.tzinfo is None:
            raise MonitoringContractError("observed_at must include timezone")
        if not start <= observed <= end or asset_id not in self.asset_refs:
            return False
        return not self.category_prefixes or any(category.startswith(prefix) for prefix in self.category_prefixes)


def robust_baseline(values: Iterable[float], *, min_samples: int = 5) -> RobustBaseline:
    if not 3 <= int(min_samples) <= 1000:
        raise MonitoringContractError("min_samples must be within 3..1000")
    samples = tuple(float(value) for value in values)
    if len(samples) > 10000:
        raise MonitoringContractError("baseline sample set exceeds 10000")
    if not samples:
        return RobustBaseline(sample_count=0, median_value=None, mad=None, warm=False)
    center = float(median(samples))
    mad = float(median(abs(value - center) for value in samples))
    return RobustBaseline(
        sample_count=len(samples),
        median_value=center,
        mad=mad,
        warm=len(samples) >= min_samples,
    )


def assess_robust_anomaly(
    value: float,
    baseline: RobustBaseline,
    *,
    threshold: float = 6.0,
    absolute_floor: float = 0.0,
) -> BaselineAssessment:
    if not 1.0 <= float(threshold) <= 20.0:
        raise MonitoringContractError("threshold must be within 1..20")
    if float(absolute_floor) < 0:
        raise MonitoringContractError("absolute_floor must be non-negative")
    current = float(value)
    if not baseline.warm or baseline.median_value is None or baseline.mad is None:
        return BaselineAssessment("data_gap", "BASELINE_WARMING", current, baseline.median_value, None)
    absolute_deviation = abs(current - baseline.median_value)
    if absolute_deviation <= float(absolute_floor):
        return BaselineAssessment("normal", "WITHIN_ABSOLUTE_FLOOR", current, baseline.median_value, 0.0)
    if baseline.mad == 0:
        return BaselineAssessment(
            "anomaly" if absolute_deviation > float(absolute_floor) else "normal",
            "ZERO_MAD_DEVIATION" if absolute_deviation > float(absolute_floor) else "WITHIN_ABSOLUTE_FLOOR",
            current,
            baseline.median_value,
            None,
        )
    score = 0.67448975 * absolute_deviation / baseline.mad
    return BaselineAssessment(
        "anomaly" if score >= threshold else "normal",
        "ROBUST_DEVIATION" if score >= threshold else "WITHIN_BASELINE",
        current,
        baseline.median_value,
        round(score, 6),
    )


def maintenance_suppression(
    *,
    asset_id: str,
    category: str,
    observed_at: str,
    windows: Iterable[MaintenanceWindow],
) -> str | None:
    """Return a change ID for presentation suppression; evidence is never deleted."""

    for window in windows:
        if window.matches(asset_id=asset_id, category=category, observed_at=observed_at):
            return window.change_id
    return None
