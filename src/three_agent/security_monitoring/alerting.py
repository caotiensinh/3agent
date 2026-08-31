from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .contracts import FindingRecord, MonitoringContractError, sha256_fingerprint

ALERT_SCHEMA = "workspace-security-monitoring/internal-alert-v1"


@dataclass(frozen=True)
class InternalAlert:
    alert_id: str
    finding_id: str
    severity: str
    category: str
    asset_count: int
    evidence_count: int
    correlation_key_sha256: str
    schema_version: str = ALERT_SCHEMA


class InternalAlertSink(Protocol):
    def emit(self, alert: InternalAlert) -> None: ...


class MemoryAlertSink:
    """Test/reference sink. Production delivery is a later bounded internal adapter."""

    def __init__(self) -> None:
        self.alerts: list[InternalAlert] = []

    def emit(self, alert: InternalAlert) -> None:
        self.alerts.append(alert)


def build_internal_alert(finding: FindingRecord) -> InternalAlert | None:
    finding.validate()
    if finding.severity not in {"high", "critical"}:
        return None
    return InternalAlert(
        alert_id="alert-" + sha256_fingerprint(
            [finding.finding_id, finding.severity, finding.last_seen]
        ).split(":", 1)[1][:24],
        finding_id=finding.finding_id,
        severity=finding.severity,
        category=finding.category,
        asset_count=len(finding.asset_refs),
        evidence_count=len(finding.evidence_refs),
        correlation_key_sha256=sha256_fingerprint(finding.correlation_key),
    )


def emit_high_critical(finding: FindingRecord, sink: InternalAlertSink) -> InternalAlert | None:
    if sink is None:
        raise MonitoringContractError("internal alert sink is required")
    alert = build_internal_alert(finding)
    if alert is not None:
        sink.emit(alert)
    return alert
