from __future__ import annotations

from collections.abc import Iterable

from .runtime_config import MonitoringRuntimeConfig
from .ui_read_model import SecurityMonitoringUIReadModel

INCIDENT_POSTURE_SCHEMA = "workspace-security-monitoring/incident-posture-v1"
INCIDENT_POSTURE_SAMPLE_LIMIT = 100
_SEVERITY_BUCKETS = ("info", "low", "medium", "high", "critical")
_STATUS_BUCKETS = (
    "open",
    "active",
    "triaged",
    "investigating",
    "contained",
    "resolved",
    "closed",
)
_CLOSED_STATUSES = {"resolved", "closed"}


def _items(payload: dict[str, object]) -> list[dict[str, object]]:
    raw = payload.get("items")
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)][:INCIDENT_POSTURE_SAMPLE_LIMIT]


def _bucket(value: object, allowed: Iterable[str]) -> str:
    normalized = str(value or "").strip().lower()
    allowed_values = tuple(allowed)
    return normalized if normalized in allowed_values else "other"


def safe_incident_posture_summary(config: MonitoringRuntimeConfig) -> dict[str, object]:
    """Return a bounded aggregate-only incident posture projection.

    The function reads at most 100 recent findings through the existing query-only UI
    read model, reduces them to fixed severity/status buckets, and discards all detailed
    rows before returning. It never exposes finding IDs, asset refs, evidence refs,
    rule IDs, category strings, raw values, credentials, or execution controls.
    """

    read_model = SecurityMonitoringUIReadModel(config, config_state="configured")
    findings = _items(
        read_model.findings(limit=INCIDENT_POSTURE_SAMPLE_LIMIT, offset=0)
    )

    severity_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    open_severity_counts: dict[str, int] = {}
    open_count = 0

    for finding in findings:
        severity = _bucket(finding.get("severity"), _SEVERITY_BUCKETS)
        status = _bucket(finding.get("status"), _STATUS_BUCKETS)
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        status_counts[status] = status_counts.get(status, 0) + 1
        if status not in _CLOSED_STATUSES:
            open_count += 1
            open_severity_counts[severity] = open_severity_counts.get(severity, 0) + 1

    attention_level = "clear"
    if open_severity_counts.get("critical", 0):
        attention_level = "critical"
    elif open_severity_counts.get("high", 0):
        attention_level = "high"
    elif open_severity_counts.get("medium", 0):
        attention_level = "medium"
    elif open_count:
        attention_level = "low"

    return {
        "schema_version": INCIDENT_POSTURE_SCHEMA,
        "count_scope": "recent_bounded_findings",
        "max_findings": INCIDENT_POSTURE_SAMPLE_LIMIT,
        "sample_count": len(findings),
        "open_sample_count": open_count,
        "closed_sample_count": len(findings) - open_count,
        "severity_counts": dict(sorted(severity_counts.items())),
        "status_counts": dict(sorted(status_counts.items())),
        "attention_level": attention_level,
        "contains_identifiers": False,
        "contains_raw_evidence": False,
        "contains_raw_credentials": False,
        "authority": {
            "aggregate_only": True,
            "database_read_only": True,
            "finding_ids_exposed": False,
            "asset_refs_exposed": False,
            "evidence_refs_exposed": False,
            "rule_ids_exposed": False,
            "category_values_exposed": False,
            "browser_filters_exposed": False,
            "database_write": False,
            "network_execution": False,
            "collector_execution": False,
            "packet_capture_execution": False,
            "remediation_execution": False,
        },
    }
