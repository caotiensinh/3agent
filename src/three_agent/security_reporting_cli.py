from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .security_monitoring.report_orchestrator import (
    load_reporting_config,
    retry_pending_archive,
    run_reporting_cycle,
)

TOKYO = ZoneInfo("Asia/Tokyo")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="workspace-security-report")
    parser.add_argument("--config", required=True, type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate-config")
    daily = sub.add_parser("run-daily")
    daily.add_argument("--cutoff-at")
    retry = sub.add_parser("retry-nas")
    retry.add_argument("--report-id", required=True)
    retry.add_argument("--period-kind", required=True, choices=("daily", "weekly", "monthly"))
    retry.add_argument("--period-key", required=True)
    retry.add_argument("--attempt", required=True, type=int)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = load_reporting_config(args.config)
    if args.command == "validate-config":
        print(
            json.dumps(
                {
                    "enabled": config.enabled,
                    "timezone": config.timezone,
                    "report_time": f"{config.report_hour:02d}:{config.report_minute:02d}",
                    "database_parent": str(config.database_path.parent),
                    "spool_parent": str(config.spool_root.parent),
                    "nas_parent": str(config.nas_root.parent),
                    "contains_nas_credentials": False,
                },
                sort_keys=True,
            )
        )
        return 0
    if args.command == "run-daily":
        cutoff = args.cutoff_at or datetime.now(TOKYO).replace(second=0, microsecond=0).isoformat()
        receipts = run_reporting_cycle(config, cutoff_at=cutoff)
        print(json.dumps([asdict(receipt) for receipt in receipts], ensure_ascii=False, sort_keys=True))
        return 0 if all(receipt.status == "completed" for receipt in receipts) else 3
    if args.command == "retry-nas":
        receipt = retry_pending_archive(
            config,
            report_id=args.report_id,
            period_kind=args.period_kind,
            period_key=args.period_key,
            attempt=args.attempt,
        )
        print(json.dumps(asdict(receipt), ensure_ascii=False, sort_keys=True))
        return 0 if receipt.status == "archived" else 3
    raise RuntimeError("unsupported command")


if __name__ == "__main__":
    raise SystemExit(main())
