from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from .security_monitoring.report_orchestrator import (
    load_reporting_config,
    retry_pending_archive,
    run_reporting_cycle,
)

TOKYO = ZoneInfo("Asia/Tokyo")


def latest_canonical_cutoff(now: datetime | None = None) -> datetime:
    """Return the latest 17:30 Asia/Tokyo reporting slot that has already occurred.

    This is used by the persistent systemd timer after downtime. It never fabricates
    a measurement timestamp: it only selects the deterministic report cutoff over
    evidence that already exists in the monitoring store.
    """

    current = now or datetime.now(TOKYO)
    if current.tzinfo is None:
        raise ValueError("now must include timezone")
    current = current.astimezone(TOKYO)
    cutoff = current.replace(hour=17, minute=30, second=0, microsecond=0)
    if current < cutoff:
        cutoff -= timedelta(days=1)
    return cutoff


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="workspace-security-report")
    parser.add_argument("--config", required=True, type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate-config")
    daily = sub.add_parser("run-daily")
    daily.add_argument("--cutoff-at")
    sub.add_parser("run-canonical")
    retry = sub.add_parser("retry-nas")
    retry.add_argument("--report-id", required=True)
    retry.add_argument("--period-kind", required=True, choices=("daily", "weekly", "monthly"))
    retry.add_argument("--period-key", required=True)
    retry.add_argument("--attempt", required=True, type=int)
    return parser


def _emit_cycle(config, cutoff: datetime) -> int:
    receipts = run_reporting_cycle(config, cutoff_at=cutoff.isoformat())
    print(json.dumps([asdict(receipt) for receipt in receipts], ensure_ascii=False, sort_keys=True))
    return 0 if all(receipt.status == "completed" for receipt in receipts) else 3


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
        cutoff = datetime.fromisoformat(args.cutoff_at.replace("Z", "+00:00")) if args.cutoff_at else latest_canonical_cutoff()
        if cutoff.tzinfo is None:
            raise ValueError("cutoff-at must include timezone")
        return _emit_cycle(config, cutoff.astimezone(TOKYO))
    if args.command == "run-canonical":
        return _emit_cycle(config, latest_canonical_cutoff())
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
