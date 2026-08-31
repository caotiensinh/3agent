from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Iterable

from .baselines import MaintenanceWindow, maintenance_suppression
from .contracts import FindingRecord, MonitoringContractError, SEVERITIES, sha256_fingerprint, _compact

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ALLOWED_TRANSITIONS = {
    "open": {"correlated", "investigating", "resolved"},
    "correlated": {"investigating", "resolved"},
    "investigating": {"resolved"},
    "resolved": {"reopened"},
    "reopened": {"correlated", "investigating", "resolved"},
}


@dataclass(frozen=True)
class FindingSignal:
    signal_id: str
    asset_id: str
    source_id: str
    category: str
    severity: str
    observed_at: str
    evidence_ref: str
    rule_id: str

    def validate(self) -> "FindingSignal":
        object.__setattr__(self, "signal_id", _compact(self.signal_id, "signal_id", max_len=128))
        object.__setattr__(self, "asset_id", _compact(self.asset_id, "asset_id", max_len=128))
        object.__setattr__(self, "source_id", _compact(self.source_id, "source_id", max_len=128))
        object.__setattr__(self, "category", _compact(self.category, "category", max_len=96))
        if self.severity not in SEVERITIES:
            raise MonitoringContractError(f"unsupported signal severity: {self.severity}")
        observed = datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
        if observed.tzinfo is None:
            raise MonitoringContractError("signal observed_at must include timezone")
        object.__setattr__(self, "evidence_ref", _compact(self.evidence_ref, "evidence_ref"))
        object.__setattr__(self, "rule_id", _compact(self.rule_id, "rule_id", max_len=128))
        return self


@dataclass(frozen=True)
class CorrelationResult:
    correlation_key: str
    finding: FindingRecord
    signal_count: int
    distinct_sources: int
    suppressed_by_change: str | None


def severity_max(values: Iterable[str]) -> str:
    items = tuple(values)
    if not items:
        raise MonitoringContractError("severity set cannot be empty")
    unknown = set(items) - SEVERITIES
    if unknown:
        raise MonitoringContractError(f"unsupported severities: {sorted(unknown)}")
    return max(items, key=lambda value: SEVERITY_ORDER[value])


def deterministic_correlation_key(signal: FindingSignal) -> str:
    signal.validate()
    # Category family is intentionally exact except a final detail segment. This
    # avoids model-driven grouping and keeps correlation explainable.
    parts = signal.category.split(".")
    family = ".".join(parts[:2]) if len(parts) >= 2 else signal.category
    return f"{signal.asset_id}:{family}"


def correlate_signals(
    signals: Iterable[FindingSignal],
    *,
    window_seconds: int = 900,
    maintenance_windows: Iterable[MaintenanceWindow] = (),
) -> tuple[CorrelationResult, ...]:
    if not 60 <= int(window_seconds) <= 86400:
        raise MonitoringContractError("correlation window must be within 60..86400 seconds")
    validated = sorted((signal.validate() for signal in signals), key=lambda item: item.observed_at)
    if len(validated) > 10000:
        raise MonitoringContractError("correlation input exceeds 10000 signals")
    grouped: dict[str, list[list[FindingSignal]]] = {}
    for signal in validated:
        key = deterministic_correlation_key(signal)
        windows = grouped.setdefault(key, [])
        observed = datetime.fromisoformat(signal.observed_at.replace("Z", "+00:00"))
        if not windows:
            windows.append([signal])
            continue
        last_group = windows[-1]
        first = datetime.fromisoformat(last_group[0].observed_at.replace("Z", "+00:00"))
        if (observed - first).total_seconds() <= window_seconds:
            last_group.append(signal)
        else:
            windows.append([signal])

    results: list[CorrelationResult] = []
    for key in sorted(grouped):
        for group in grouped[key]:
            first, last = group[0], group[-1]
            severity = severity_max(signal.severity for signal in group)
            evidence_refs = tuple(dict.fromkeys(signal.evidence_ref for signal in group))
            sources = tuple(dict.fromkeys(signal.source_id for signal in group))
            rule_ids = tuple(dict.fromkeys(signal.rule_id for signal in group))
            finding_id = "finding-" + sha256_fingerprint(
                [key, first.observed_at, list(evidence_refs)]
            ).split(":", 1)[1][:24]
            suppression_ids = {
                maintenance_suppression(
                    asset_id=first.asset_id,
                    category=signal.category,
                    observed_at=signal.observed_at,
                    windows=maintenance_windows,
                )
                for signal in group
            }
            suppression_ids.discard(None)
            suppression = sorted(suppression_ids)[0] if len(suppression_ids) == 1 else None
            finding = FindingRecord(
                finding_id=finding_id,
                category=first.category,
                severity=severity,
                status="correlated" if len(group) > 1 else "open",
                first_seen=first.observed_at,
                last_seen=last.observed_at,
                asset_refs=(first.asset_id,),
                evidence_refs=evidence_refs,
                correlation_key=key,
                rule_id=rule_ids[0] if len(rule_ids) == 1 else "multi-rule",
            ).validate()
            results.append(
                CorrelationResult(
                    correlation_key=key,
                    finding=finding,
                    signal_count=len(group),
                    distinct_sources=len(sources),
                    suppressed_by_change=suppression,
                )
            )
    return tuple(results)


def transition_finding(finding: FindingRecord, *, new_status: str, changed_at: str) -> FindingRecord:
    finding.validate()
    target = str(new_status or "").strip().lower()
    if target not in ALLOWED_TRANSITIONS.get(finding.status, set()):
        raise MonitoringContractError(f"invalid finding transition: {finding.status}->{target}")
    changed = datetime.fromisoformat(changed_at.replace("Z", "+00:00"))
    last = datetime.fromisoformat(finding.last_seen.replace("Z", "+00:00"))
    if changed.tzinfo is None or changed < last:
        raise MonitoringContractError("finding transition time cannot precede last_seen")
    return replace(finding, status=target, last_seen=changed_at).validate()


def deterministic_severity(
    *,
    base_severity: str,
    distinct_sources: int,
    repeated_count: int,
    data_gap: bool = False,
) -> str:
    if base_severity not in SEVERITIES:
        raise MonitoringContractError("unsupported base severity")
    if distinct_sources < 1 or repeated_count < 1:
        raise MonitoringContractError("severity evidence counts must be positive")
    score = SEVERITY_ORDER[base_severity]
    if distinct_sources >= 2:
        score += 1
    if repeated_count >= 3:
        score += 1
    if data_gap:
        # Missing visibility is serious but must never manufacture CRITICAL.
        score = max(score, SEVERITY_ORDER["medium"])
    return next(name for name, rank in SEVERITY_ORDER.items() if rank == min(score, 4))
