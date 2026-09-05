from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from .security_monitoring.contracts import MonitoringContractError
from .security_monitoring.readiness import evaluate_monitoring_readiness
from .security_monitoring.runtime_config import load_runtime_config
from .security_monitoring_cli import cmd_run_hourly

ENV_CONFIG = "WORKSPACE_SECURITY_MONITORING_CONFIG"
SCHEDULER_SCHEMA = "workspace-security-monitoring/scheduler-v1"


def _config_path(value: str | Path | None = None) -> Path:
    raw = str(value or os.getenv(ENV_CONFIG) or "").strip()
    if not raw:
        raise MonitoringContractError(f"{ENV_CONFIG} is required")
    path = Path(raw)
    if not path.is_absolute():
        raise MonitoringContractError(f"{ENV_CONFIG} must be an absolute path")
    if path.is_symlink():
        raise MonitoringContractError("monitoring config path must not be a symlink")
    if not path.is_file():
        raise MonitoringContractError("monitoring config path is not a regular file")
    return path


def lifecycle_status(config_path: str | Path | None = None) -> dict[str, Any]:
    path = _config_path(config_path)
    config = load_runtime_config(path)
    readiness = evaluate_monitoring_readiness(config, config_saved=True)
    reason_codes = sorted({str(item.get("code")) for item in readiness.get("issues", [])})
    return {
        "schema_version": SCHEDULER_SCHEMA,
        "status": "ready" if readiness.get("ready") else "blocked",
        "monitoring_enabled": bool(config.enabled),
        "real_network_allowed": bool(config.allow_real_network),
        "approved_asset_count": len(config.assets),
        "enabled_asset_count": sum(1 for asset in config.assets if asset.enabled),
        "policy_fingerprint": config.policy.fingerprint,
        "reason_codes": reason_codes,
        "execution": {
            "scheduled": True,
            "read_only": True,
            "approved_inventory_only": True,
            "model_authority": False,
            "autonomous_remediation": False,
            "packet_capture": False,
        },
    }


def run_scheduled(config_path: str | Path | None = None) -> int:
    path = _config_path(config_path)
    config = load_runtime_config(path)
    if not config.enabled:
        print(
            json.dumps(
                {
                    "schema_version": SCHEDULER_SCHEMA,
                    "status": "skipped",
                    "reason_code": "MONITORING_DISABLED",
                    "network_execution": False,
                },
                sort_keys=True,
            )
        )
        return 0
    if not config.allow_real_network:
        print(
            json.dumps(
                {
                    "schema_version": SCHEDULER_SCHEMA,
                    "status": "skipped",
                    "reason_code": "REAL_NETWORK_NOT_ALLOWED_BY_CONFIG",
                    "network_execution": False,
                },
                sort_keys=True,
            )
        )
        return 0

    readiness = evaluate_monitoring_readiness(config, config_saved=True)
    if not readiness.get("ready"):
        reason_codes = sorted({str(item.get("code")) for item in readiness.get("issues", [])})
        print(
            json.dumps(
                {
                    "schema_version": SCHEDULER_SCHEMA,
                    "status": "blocked",
                    "reason_codes": reason_codes,
                    "network_execution": False,
                },
                sort_keys=True,
            )
        )
        return 4

    return cmd_run_hourly(path, execute_readonly=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="workspace-security-scheduler")
    parser.add_argument("--config", type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    sub.add_parser("run-scheduled")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "status":
            print(json.dumps(lifecycle_status(args.config), ensure_ascii=False, sort_keys=True))
            return 0
        if args.command == "run-scheduled":
            return run_scheduled(args.config)
        raise RuntimeError("unsupported scheduler command")
    except (MonitoringContractError, OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": SCHEDULER_SCHEMA,
                    "status": "failed",
                    "reason_code": str(exc)[:160] or "SCHEDULER_FAILED",
                    "network_execution": False,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
