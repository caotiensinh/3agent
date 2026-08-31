from __future__ import annotations

import json
import math
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from .contracts import MonitoringContractError
from .runtime_config import MonitoringRuntimeConfig, load_runtime_config

UI_SCHEMA = "workspace-security-monitoring/ui-read-v1"
MAX_PAGE_SIZE = 100
MAX_PAGE_OFFSET = 10_000
MAX_ASSETS = 1_000
STALE_HOURLY_SECONDS = 2 * 60 * 60
_ENV_CONFIG = "WORKSPACE_SECURITY_MONITORING_CONFIG"
_SENSITIVE_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "community",
    "credential_ref",
    "management_host",
    "auth_key",
    "priv_key",
}


def _page(limit: int, offset: int) -> tuple[int, int]:
    try:
        size = int(limit)
        start = int(offset)
    except (TypeError, ValueError) as exc:
        raise MonitoringContractError("UI pagination must be integer") from exc
    if not 1 <= size <= MAX_PAGE_SIZE:
        raise MonitoringContractError(f"UI page size must be within 1..{MAX_PAGE_SIZE}")
    if not 0 <= start <= MAX_PAGE_OFFSET:
        raise MonitoringContractError(f"UI page offset must be within 0..{MAX_PAGE_OFFSET}")
    return size, start


def _json_list(raw: str | None, *, max_items: int = 64) -> list[str]:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(value, list):
        return []
    return [str(item)[:160] for item in value[:max_items]]


def _safe_value(value: Any, *, depth: int = 0) -> Any:
    """Bound observation values without exposing credential-like nested fields."""
    if depth > 2:
        return None
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return value[:160]
    if isinstance(value, list):
        return [_safe_value(item, depth=depth + 1) for item in value[:16]]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key in sorted(value, key=str)[:16]:
            normalized = str(key).lower().strip()
            if normalized in _SENSITIVE_KEYS:
                continue
            result[str(key)[:64]] = _safe_value(value[key], depth=depth + 1)
        return result
    return None


def _decode_value(raw: str | None) -> Any:
    if raw is None:
        return None
    try:
        return _safe_value(json.loads(raw))
    except json.JSONDecodeError:
        return None


def _age_seconds(value: str | None, *, now: datetime) -> float | None:
    if not value:
        return None
    try:
        observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if observed.tzinfo is None:
        return None
    return max(0.0, (now - observed.astimezone(timezone.utc)).total_seconds())


class SecurityMonitoringUIReadModel:
    """Authenticated-UI read model. It never opens the monitoring DB for writes."""

    def __init__(
        self,
        config: MonitoringRuntimeConfig | None,
        *,
        config_state: str,
        reason_code: str | None = None,
    ) -> None:
        self.config = config
        self.config_state = config_state
        self.reason_code = reason_code

    @classmethod
    def from_environment(
        cls, env: Mapping[str, str] | None = None
    ) -> "SecurityMonitoringUIReadModel":
        source = os.environ if env is None else env
        raw = str(source.get(_ENV_CONFIG) or "").strip()
        if not raw:
            return cls(None, config_state="not_configured", reason_code="MONITORING_CONFIG_NOT_SET")
        path = Path(raw)
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            return cls(None, config_state="configuration_error", reason_code="MONITORING_CONFIG_UNAVAILABLE")
        try:
            config = load_runtime_config(path)
        except (OSError, ValueError, json.JSONDecodeError, MonitoringContractError):
            return cls(None, config_state="configuration_error", reason_code="MONITORING_CONFIG_INVALID")
        return cls(config, config_state="configured")

    @contextmanager
    def _connect_ro(self) -> Iterator[sqlite3.Connection | None]:
        if self.config is None:
            yield None
            return
        path = self.config.database_path
        if path.is_symlink() or not path.is_file():
            yield None
            return
        uri = path.resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=1.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA busy_timeout=1000")
        try:
            yield conn
        finally:
            conn.close()

    def summary(self, *, now: datetime | None = None) -> dict[str, Any]:
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        base: dict[str, Any] = {
            "schema_version": UI_SCHEMA,
            "configured": self.config_state == "configured",
            "config_state": self.config_state,
            "enabled": bool(self.config.enabled) if self.config else False,
            "health": "not_configured",
            "reason_codes": [],
            "high_critical_count": 0,
            "open_finding_count": 0,
            "enabled_asset_count": 0,
            "latest_hourly": None,
        }
        if self.config_state != "configured" or self.config is None:
            base["health"] = self.config_state
            base["reason_codes"] = [self.reason_code] if self.reason_code else []
            return base
        if not self.config.enabled:
            base["health"] = "disabled"
            base["reason_codes"] = ["MONITORING_DISABLED"]
            return base

        with self._connect_ro() as conn:
            if conn is None:
                base["health"] = "data_gap"
                base["reason_codes"] = ["MONITORING_DB_UNAVAILABLE"]
                return base
            latest = conn.execute(
                """
                SELECT run_id,status,coverage_pct,expected_assets,observed_assets,
                       started_at,completed_at
                FROM hourly_runs
                ORDER BY started_at DESC, run_id DESC
                LIMIT 1
                """
            ).fetchone()
            counts = conn.execute(
                """
                SELECT
                  SUM(CASE WHEN status!='resolved' THEN 1 ELSE 0 END) AS open_count,
                  SUM(CASE WHEN status!='resolved' AND severity IN ('high','critical') THEN 1 ELSE 0 END) AS high_critical
                FROM findings
                """
            ).fetchone()
            assets = conn.execute(
                "SELECT COUNT(*) AS c FROM approved_assets WHERE enabled=1"
            ).fetchone()

        base["open_finding_count"] = int((counts["open_count"] if counts else 0) or 0)
        base["high_critical_count"] = int((counts["high_critical"] if counts else 0) or 0)
        base["enabled_asset_count"] = int((assets["c"] if assets else 0) or 0)
        if latest is None:
            base["health"] = "data_gap"
            base["reason_codes"] = ["HOURLY_RUN_MISSING"]
            return base

        latest_time = latest["completed_at"] or latest["started_at"]
        age = _age_seconds(latest_time, now=current)
        base["latest_hourly"] = {
            "run_id": latest["run_id"],
            "status": latest["status"],
            "coverage_pct": float(latest["coverage_pct"]),
            "expected_assets": int(latest["expected_assets"]),
            "observed_assets": int(latest["observed_assets"]),
            "observed_at": latest_time,
            "age_seconds": None if age is None else round(age, 3),
        }
        reasons: list[str] = []
        health = "healthy"
        if age is None or age > STALE_HOURLY_SECONDS:
            health = "data_gap"
            reasons.append("HOURLY_RUN_STALE")
        elif latest["status"] != "completed" or float(latest["coverage_pct"]) < 100.0:
            health = "degraded"
            reasons.append("HOURLY_RUN_INCOMPLETE")
        if base["high_critical_count"] > 0:
            if health == "healthy":
                health = "attention"
            reasons.append("HIGH_CRITICAL_FINDINGS")
        base["health"] = health
        base["reason_codes"] = reasons
        return base

    def assets(self) -> dict[str, Any]:
        with self._connect_ro() as conn:
            if conn is None:
                return {"schema_version": UI_SCHEMA, "items": []}
            rows = conn.execute(
                """
                SELECT a.asset_id,a.role,a.collector_capabilities_json,a.data_class,a.enabled,
                       (SELECT o.observed_at FROM observations o WHERE o.asset_id=a.asset_id ORDER BY o.observed_at DESC,o.id DESC LIMIT 1) AS last_observed_at,
                       (SELECT o.status FROM observations o WHERE o.asset_id=a.asset_id ORDER BY o.observed_at DESC,o.id DESC LIMIT 1) AS last_status
                FROM approved_assets a
                ORDER BY a.asset_id
                LIMIT ?
                """,
                (MAX_ASSETS,),
            ).fetchall()
        items = [
            {
                "asset_id": row["asset_id"],
                "role": row["role"],
                "collector_capabilities": _json_list(row["collector_capabilities_json"]),
                "data_class": row["data_class"],
                "enabled": bool(row["enabled"]),
                "observed_state": {
                    "last_observed_at": row["last_observed_at"],
                    "last_status": row["last_status"],
                },
            }
            for row in rows
        ]
        return {"schema_version": UI_SCHEMA, "items": items}

    def network(self, *, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        size, start = _page(limit, offset)
        with self._connect_ro() as conn:
            if conn is None:
                rows = []
            else:
                rows = conn.execute(
                    """
                    SELECT id,asset_id,collector,observed_at,metric,status,value_json,unit,evidence_ref
                    FROM observations
                    ORDER BY observed_at DESC,id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (size, start),
                ).fetchall()
        items = [
            {
                "id": int(row["id"]),
                "asset_id": row["asset_id"],
                "collector": row["collector"],
                "observed_at": row["observed_at"],
                "metric": row["metric"],
                "status": row["status"],
                "value": _decode_value(row["value_json"]),
                "unit": row["unit"],
                "evidence_ref": row["evidence_ref"],
            }
            for row in rows
        ]
        return {"schema_version": UI_SCHEMA, "limit": size, "offset": start, "items": items}

    def findings(self, *, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        size, start = _page(limit, offset)
        with self._connect_ro() as conn:
            if conn is None:
                rows = []
            else:
                rows = conn.execute(
                    """
                    SELECT finding_id,category,severity,status,first_seen,last_seen,
                           asset_refs_json,evidence_refs_json,rule_id
                    FROM findings
                    ORDER BY last_seen DESC,finding_id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (size, start),
                ).fetchall()
        items = [
            {
                "finding_id": row["finding_id"],
                "category": row["category"],
                "severity": row["severity"],
                "status": row["status"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "asset_refs": _json_list(row["asset_refs_json"]),
                "evidence_refs": _json_list(row["evidence_refs_json"]),
                "rule_id": row["rule_id"],
            }
            for row in rows
        ]
        return {"schema_version": UI_SCHEMA, "limit": size, "offset": start, "items": items}

    def events(self, *, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        size, start = _page(limit, offset)
        with self._connect_ro() as conn:
            if conn is None:
                rows = []
            else:
                rows = conn.execute(
                    """
                    SELECT event_id,source_id,source_type,observed_at,category,severity,
                           parser_version,evidence_ref
                    FROM canonical_events
                    ORDER BY observed_at DESC,event_id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (size, start),
                ).fetchall()
        items = [dict(row) for row in rows]
        return {"schema_version": UI_SCHEMA, "limit": size, "offset": start, "items": items}

    def reports(self, *, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        size, start = _page(limit, offset)
        with self._connect_ro() as conn:
            if conn is None:
                rows = []
            else:
                rows = conn.execute(
                    """
                    SELECT archive_id,period_kind,period_key,status,manifest_sha256,attempt,updated_at
                    FROM archive_receipts
                    ORDER BY updated_at DESC,archive_id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (size, start),
                ).fetchall()
        return {
            "schema_version": UI_SCHEMA,
            "limit": size,
            "offset": start,
            "items": [dict(row) for row in rows],
        }

    def admin_status(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": UI_SCHEMA,
            "config_state": self.config_state,
            "reason_code": self.reason_code,
            "database_available": False,
            "schema_version_db": None,
            "read_only_ui": True,
            "mutations_exposed": False,
            "autonomous_remediation": False,
            "autonomous_pcap": False,
            "passive_sensors_optional": True,
        }
        if self.config is None:
            return payload
        policy = self.config.policy
        payload.update(
            {
                "enabled": self.config.enabled,
                "allow_real_network": self.config.allow_real_network,
                "asset_count": len(self.config.assets),
                "secret_boundary_configured": self.config.secret_directory is not None,
                "policy": {
                    "profile_id": policy.profile_id,
                    "network_scope": policy.network_scope,
                    "read_only": policy.read_only,
                    "production_safety_profile": policy.production_safety_profile,
                    "allow_active_liveness": policy.allow_active_liveness,
                    "bandwidth_measurement_mode": policy.bandwidth_measurement_mode,
                    "packet_analysis_mode": policy.packet_analysis_mode,
                    "max_workers": policy.max_workers,
                    "timeout_seconds": policy.timeout_seconds,
                    "max_retries": policy.max_retries,
                    "max_catch_up_runs": policy.max_catch_up_runs,
                    "allowed_capabilities": list(policy.allowed_capabilities),
                },
            }
        )
        with self._connect_ro() as conn:
            if conn is not None:
                payload["database_available"] = True
                try:
                    row = conn.execute(
                        "SELECT value FROM schema_meta WHERE key='schema_version'"
                    ).fetchone()
                    payload["schema_version_db"] = int(row["value"]) if row else None
                except (sqlite3.DatabaseError, ValueError):
                    payload["schema_version_db"] = None
        return payload
