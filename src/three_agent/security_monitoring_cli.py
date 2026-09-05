from __future__ import annotations

import argparse
import json
from pathlib import Path

from .security_monitoring.locking import MonitoringRunAlreadyLocked
from .security_monitoring.service import (
    TOKYO,
    SecurityMonitoringService,
    build_snmp_backend,
    safe_config_summary,
    sync_inventory,
)
from .security_monitoring.storage import MonitoringStore

# Compatibility aliases for callers/tests that imported or patched the former CLI
# helpers. MonitoringStore is intentionally re-exported above for the same reason.
_sync_inventory = sync_inventory
_safe_config_summary = safe_config_summary
_snmp_backend = build_snmp_backend


def cmd_validate(config_path: Path) -> int:
    payload = SecurityMonitoringService(config_path).summary()
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


def cmd_init(config_path: Path) -> int:
    payload = SecurityMonitoringService(config_path).initialize()
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


def cmd_run_hourly(config_path: Path, *, execute_readonly: bool) -> int:
    try:
        payload = SecurityMonitoringService(config_path).run_hourly(
            execute_readonly=execute_readonly
        )
    except MonitoringRunAlreadyLocked:
        print(
            json.dumps(
                {"status": "blocked", "reason_code": "HOURLY_SLOT_ALREADY_LOCKED"},
                sort_keys=True,
            )
        )
        return 3
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
