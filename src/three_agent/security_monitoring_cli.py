from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .security_monitoring.dispatch import DefaultCollectorDispatcher
from .security_monitoring.hourly import HourlyMonitoringRunner
from .security_monitoring.locking import MonitoringRunAlreadyLocked
from .security_monitoring.policy import MonitoringPolicyEngine
from .security_monitoring.runtime_config import MonitoringRuntimeConfig, load_runtime_config
from .security_monitoring.snmp_backend import FileSecretResolver, PySnmpV3Backend
from .security_monitoring.storage import MonitoringStore

TOKYO = ZoneInfo("Asia/Tokyo")


def _sync_inventory(config: MonitoringRuntimeConfig, store: MonitoringStore) -> None:
    """Config is authoritative; stale DB assets are disabled, never silently trusted."""
    store.initialize()
    with store.connect() as conn:
        conn.execute("UPDATE approved_assets SET enabled=0")
    for asset in config.assets:
        store.upsert_asset(asset)


def _safe_config_summary(config: MonitoringRuntimeConfig) -> dict:
    snmp_assets = sum(1 for asset in config.assets if "snmpv3_read" in asset.collector_capabilities and asset.enabled)
    return {
        "enabled": config.enabled,
        "allow_real_network": config.allow_real_network,
        "profile_id": config.policy.profile_id,
        "policy_fingerprint": config.policy.fingerprint,
        "asset_count": len(config.assets),
        "enabled_asset_count": sum(1 for asset in config.assets if asset.enabled),
        "snmpv3_asset_count": snmp_assets,
        "snmpv3_secret_boundary_configured": bool(config.secret_directory),
        "database_parent": str(config.database_path.parent),
        "contains_raw_credentials": False,
    }


def cmd_validate(config_path: Path) -> int:
    config = load_runtime_config(config_path)
    print(json.dumps(_safe_config_summary(config), ensure_ascii=False, sort_keys=True))
    return 0


def cmd_init(config_path: Path) -> int:
    config = load_runtime_config(config_path)
    config.database_path.parent.mkdir(parents=True, exist_ok=True)
    store = MonitoringStore(config.database_path)
    _sync_inventory(config, store)
    print(json.dumps({"status": "initialized", **_safe_config_summary(config)}, ensure_ascii=False, sort_keys=True))
    return 0


def _snmp_backend(config: MonitoringRuntimeConfig):
    has_snmp_assets = any(asset.enabled and "snmpv3_read" in asset.collector_capabilities for asset in config.assets)
    if not has_snmp_assets or config.secret_directory is None:
        return None
    return PySnmpV3Backend(FileSecretResolver(config.secret_directory))


def cmd_run_hourly(config_path: Path, *, execute_readonly: bool) -> int:
    config = load_runtime_config(config_path)
    if not config.enabled:
        raise RuntimeError("MONITORING_DISABLED")
    if not config.allow_real_network:
        raise RuntimeError("REAL_NETWORK_NOT_ALLOWED_BY_CONFIG")
    if not execute_readonly:
        raise RuntimeError("EXPLICIT_READONLY_EXECUTION_FLAG_REQUIRED")

    config.database_path.parent.mkdir(parents=True, exist_ok=True)
    store = MonitoringStore(config.database_path)
    _sync_inventory(config, store)
    policy_engine = MonitoringPolicyEngine(config.policy)
    dispatcher = DefaultCollectorDispatcher(policy_engine, snmp_backend=_snmp_backend(config))
    runner = HourlyMonitoringRunner(
        store=store,
        policy=config.policy,
        execute_work_item=dispatcher,
    )
    # A persistent timer may invoke us after downtime. The measurement timestamp is
    # always current execution time; we never pretend a missed historic sample exists.
    scheduled_at = datetime.now(TOKYO).isoformat()
    try:
        receipt = runner.run(scheduled_at=scheduled_at)
    except MonitoringRunAlreadyLocked:
        print(json.dumps({"status": "blocked", "reason_code": "HOURLY_SLOT_ALREADY_LOCKED"}, sort_keys=True))
        return 3
    payload = asdict(receipt)
    payload["failure_codes"] = list(receipt.failure_codes)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="workspace-security-monitor")
    parser.add_argument("--config", required=True, type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate-config")
    sub.add_parser("init-db")
    hourly = sub.add_parser("run-hourly")
    hourly.add_argument("--execute-readonly", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "validate-config":
        return cmd_validate(args.config)
    if args.command == "init-db":
        return cmd_init(args.config)
    if args.command == "run-hourly":
        return cmd_run_hourly(args.config, execute_readonly=args.execute_readonly)
    raise RuntimeError("unsupported command")


if __name__ == "__main__":
    raise SystemExit(main())
