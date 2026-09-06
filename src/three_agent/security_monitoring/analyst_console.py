from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any, Mapping

from .capability_matrix import safe_capability_matrix
from .runtime_config import MonitoringRuntimeConfig
from .ui_read_model import SecurityMonitoringUIReadModel

ANALYST_SNAPSHOT_SCHEMA = "workspace-security-monitoring/analyst-snapshot-v1"
ANALYST_ROW_LIMIT = 50

_ALLOWED_COLLECTORS = {
    "icmp_echo",
    "tcp_connect",
    "snmpv3_read",
    "local_net_read",
    "fixed_readonly_adapter",
}
_ALLOWED_STATUSES = {
    "ok",
    "error",
    "timeout",
    "unreachable",
    "unsupported",
    "discontinuity",
    "open",
    "active",
    "triaged",
    "investigating",
    "contained",
    "resolved",
    "closed",
    "completed",
    "failed",
    "partial",
}
_ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_ALLOWED_DATA_CLASSES = {"public", "internal", "confidential", "restricted"}
_ALLOWED_SOURCE_TYPES = {"workspace_audit", "suricata_eve", "zeek_json"}
_ALLOWED_REPORT_KINDS = {"hourly", "daily", "weekly", "monthly"}


def _fixed(value: object, allowed: set[str], *, fallback: str = "other") -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in allowed else fallback


def _asset_alias(index: int) -> str:
    return f"Asset {index:02d}"


def _recency(value: object, *, now: datetime) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "unknown"
    try:
        observed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return "unknown"
    if observed.tzinfo is None:
        return "unknown"
    age = (now - observed.astimezone(timezone.utc)).total_seconds()
    if age < 0:
        return "future"
    if age <= 15 * 60:
        return "last_15m"
    if age <= 60 * 60:
        return "15m_to_1h"
    if age <= 24 * 60 * 60:
        return "1h_to_24h"
    return "older"


def _event_stage(item: Mapping[str, Any]) -> str:
    source = str(item.get("source_type") or "").strip().lower()
    category = str(item.get("category") or "").strip().lower()
    if source == "workspace_audit":
        if category in {"workspace_audit.auth_success", "workspace_audit.auth_failure"}:
            return "AUTH"
        if category == "workspace_audit.process_start":
            return "PROCESS"
    if source == "suricata_eve":
        if category == "suricata.dns":
            return "DNS"
        if category == "suricata.flow":
            return "FLOW"
        if category == "suricata.alert":
            return "IDS"
    if source == "zeek_json":
        if category == "zeek.dns":
            return "DNS"
        if category == "zeek.conn":
            return "FLOW"
        if category in {"zeek.notice", "zeek.weird"}:
            return "IDS"
    return "OTHER"


def _list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def safe_analyst_snapshot(
    config: MonitoringRuntimeConfig,
    *,
    now: datetime | None = None,
    config_saved: bool = True,
) -> dict[str, object]:
    """Return bounded analyst rows without exposing raw identifiers or sensitive refs.

    This is intentionally a read-side projection over the existing query-only UI model.
    It creates no second execution authority and accepts no browser-controlled target,
    path, pagination, collector, evidence reference, or credential input.
    """

    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    read_model = SecurityMonitoringUIReadModel(config, config_state="configured")
    database_available = config.database_path.is_file() and not config.database_path.is_symlink()
    capability_matrix = safe_capability_matrix(config, config_saved=config_saved)

    if not database_available:
        return {
            "schema_version": ANALYST_SNAPSHOT_SCHEMA,
            "database_available": False,
            "data_state": "unavailable",
            "max_rows_per_stream": ANALYST_ROW_LIMIT,
            "assets": [],
            "network": [],
            "events": [],
            "findings": [],
            "reports": [],
            "admin": {
                "database_available": False,
                "capability_matrix": capability_matrix,
            },
            "authority": _authority(),
        }

    try:
        raw_assets = _list(read_model.assets().get("items"))[:ANALYST_ROW_LIMIT]
        raw_network = _list(read_model.network(limit=ANALYST_ROW_LIMIT, offset=0).get("items"))
        raw_events = _list(read_model.events(limit=ANALYST_ROW_LIMIT, offset=0).get("items"))
        raw_findings = _list(read_model.findings(limit=ANALYST_ROW_LIMIT, offset=0).get("items"))
        raw_reports = _list(read_model.reports(limit=ANALYST_ROW_LIMIT, offset=0).get("items"))
        raw_admin = read_model.admin_status()
    except sqlite3.OperationalError:
        return {
            "schema_version": ANALYST_SNAPSHOT_SCHEMA,
            "database_available": True,
            "data_state": "data_gap",
            "max_rows_per_stream": ANALYST_ROW_LIMIT,
            "assets": [],
            "network": [],
            "events": [],
            "findings": [],
            "reports": [],
            "admin": {
                "database_available": True,
                "capability_matrix": capability_matrix,
            },
            "authority": _authority(),
        }

    alias_by_id: dict[str, str] = {}
    assets: list[dict[str, object]] = []
    for index, raw in enumerate(raw_assets, start=1):
        if not isinstance(raw, Mapping):
            continue
        raw_id = str(raw.get("asset_id") or "")
        alias = _asset_alias(index)
        if raw_id:
            alias_by_id[raw_id] = alias
        observed = raw.get("observed_state")
        observed_map = observed if isinstance(observed, Mapping) else {}
        capabilities = [
            _fixed(item, _ALLOWED_COLLECTORS)
            for item in _list(raw.get("collector_capabilities"))[:16]
        ]
        assets.append(
            {
                "alias": alias,
                "enabled": raw.get("enabled") is True,
                "data_class": _fixed(raw.get("data_class"), _ALLOWED_DATA_CLASSES),
                "collector_capabilities": sorted(set(capabilities)),
                "last_status": _fixed(observed_map.get("last_status"), _ALLOWED_STATUSES, fallback="unknown"),
                "recency": _recency(observed_map.get("last_observed_at"), now=current),
            }
        )

    network: list[dict[str, object]] = []
    for raw in raw_network:
        if not isinstance(raw, Mapping):
            continue
        network.append(
            {
                "asset": alias_by_id.get(str(raw.get("asset_id") or ""), "Unmapped asset"),
                "collector": _fixed(raw.get("collector"), _ALLOWED_COLLECTORS),
                "status": _fixed(raw.get("status"), _ALLOWED_STATUSES, fallback="unknown"),
                "recency": _recency(raw.get("observed_at"), now=current),
                "has_value": raw.get("value") is not None,
                "has_evidence": bool(raw.get("evidence_ref")),
            }
        )

    events: list[dict[str, object]] = []
    for raw in raw_events:
        if not isinstance(raw, Mapping):
            continue
        events.append(
            {
                "source_type": _fixed(raw.get("source_type"), _ALLOWED_SOURCE_TYPES),
                "stage": _event_stage(raw),
                "severity": _fixed(raw.get("severity"), _ALLOWED_SEVERITIES, fallback="info"),
                "recency": _recency(raw.get("observed_at"), now=current),
                "has_evidence": bool(raw.get("evidence_ref")),
            }
        )

    findings: list[dict[str, object]] = []
    for raw in raw_findings:
        if not isinstance(raw, Mapping):
            continue
        findings.append(
            {
                "severity": _fixed(raw.get("severity"), _ALLOWED_SEVERITIES, fallback="info"),
                "status": _fixed(raw.get("status"), _ALLOWED_STATUSES, fallback="other"),
                "asset_link_count": len(_list(raw.get("asset_refs"))[:16]),
                "evidence_link_count": len(_list(raw.get("evidence_refs"))[:16]),
                "recency": _recency(raw.get("last_seen"), now=current),
            }
        )

    reports: list[dict[str, object]] = []
    for raw in raw_reports:
        if not isinstance(raw, Mapping):
            continue
        reports.append(
            {
                "period_kind": _fixed(raw.get("period_kind"), _ALLOWED_REPORT_KINDS),
                "status": _fixed(raw.get("status"), _ALLOWED_STATUSES, fallback="other"),
                "recency": _recency(raw.get("updated_at"), now=current),
            }
        )

    policy = raw_admin.get("policy") if isinstance(raw_admin, Mapping) else {}
    policy_map = policy if isinstance(policy, Mapping) else {}
    admin = {
        "database_available": bool(raw_admin.get("database_available")) if isinstance(raw_admin, Mapping) else False,
        "schema_version_db": raw_admin.get("schema_version_db") if isinstance(raw_admin, Mapping) else None,
        "monitoring_enabled": bool(raw_admin.get("enabled")) if isinstance(raw_admin, Mapping) else False,
        "real_network_allowed": bool(raw_admin.get("allow_real_network")) if isinstance(raw_admin, Mapping) else False,
        "read_only": bool(policy_map.get("read_only", True)),
        "active_liveness": bool(policy_map.get("allow_active_liveness", False)),
        "packet_analysis_mode": str(policy_map.get("packet_analysis_mode") or "unknown")[:64],
        "capability_matrix": capability_matrix,
    }

    return {
        "schema_version": ANALYST_SNAPSHOT_SCHEMA,
        "database_available": True,
        "data_state": "available",
        "max_rows_per_stream": ANALYST_ROW_LIMIT,
        "assets": assets,
        "network": network,
        "events": events,
        "findings": findings,
        "reports": reports,
        "admin": admin,
        "authority": _authority(),
    }


def _authority() -> dict[str, bool]:
    return {
        "database_read_only": True,
        "bounded_rows": True,
        "raw_asset_ids_exposed": False,
        "management_hosts_exposed": False,
        "credential_refs_exposed": False,
        "evidence_refs_exposed": False,
        "event_ids_exposed": False,
        "finding_ids_exposed": False,
        "rule_ids_exposed": False,
        "raw_values_exposed": False,
        "browser_filters_exposed": False,
        "database_write": False,
        "network_execution": False,
        "collector_execution": False,
        "packet_capture_execution": False,
        "remediation_execution": False,
    }
