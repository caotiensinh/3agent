from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .contracts import MonitoringContractError
from .nas_archive import NasArchiveConfig, archive_existing_bundle
from .receipts import ReportReceipt
from .report_state import ReportingReceiptStore
from .reporting import (
    ReportBundle,
    ReportRunLock,
    build_deterministic_report,
    is_canonical_monthly,
    is_canonical_weekly,
    write_report_bundle,
)
from .storage import MonitoringStore

TOKYO = ZoneInfo("Asia/Tokyo")


@dataclass(frozen=True)
class ReportingConfig:
    enabled: bool
    database_path: Path
    spool_root: Path
    nas_root: Path
    timezone: str = "Asia/Tokyo"
    report_hour: int = 17
    report_minute: int = 30
    max_archive_attempts_per_run: int = 4

    def validate(self) -> "ReportingConfig":
        for field_name, path in (
            ("database_path", self.database_path),
            ("spool_root", self.spool_root),
            ("nas_root", self.nas_root),
        ):
            if not Path(path).is_absolute():
                raise MonitoringContractError(f"{field_name} must be absolute")
        if Path(self.spool_root).is_symlink() or Path(self.nas_root).is_symlink():
            raise MonitoringContractError("reporting roots must not be symlinks")
        if self.timezone != "Asia/Tokyo":
            raise MonitoringContractError("ver.0.0.1 reporting timezone must be Asia/Tokyo")
        if (self.report_hour, self.report_minute) != (17, 30):
            raise MonitoringContractError("ver.0.0.1 canonical report time must be 17:30")
        if not 1 <= self.max_archive_attempts_per_run <= 16:
            raise MonitoringContractError("max_archive_attempts_per_run must be within 1..16")
        return self


def load_reporting_config(path: str | Path) -> ReportingConfig:
    config_path = Path(path)
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise MonitoringContractError("reporting config must be an object")
    allowed = {
        "enabled",
        "database_path",
        "spool_root",
        "nas_root",
        "timezone",
        "report_hour",
        "report_minute",
        "max_archive_attempts_per_run",
    }
    unknown = set(payload) - allowed
    if unknown:
        raise MonitoringContractError(f"unknown reporting config keys: {sorted(unknown)}")
    forbidden = {"password", "username", "community", "token", "secret", "mount_command"}
    if forbidden & {str(key).lower() for key in payload}:
        raise MonitoringContractError("NAS/network credentials or mount commands are forbidden")
    return ReportingConfig(
        enabled=bool(payload.get("enabled", False)),
        database_path=Path(str(payload.get("database_path") or "")),
        spool_root=Path(str(payload.get("spool_root") or "")),
        nas_root=Path(str(payload.get("nas_root") or "")),
        timezone=str(payload.get("timezone") or "Asia/Tokyo"),
        report_hour=int(payload.get("report_hour", 17)),
        report_minute=int(payload.get("report_minute", 30)),
        max_archive_attempts_per_run=int(payload.get("max_archive_attempts_per_run", 4)),
    ).validate()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def load_existing_bundle(*, report_id: str, spool_root: Path) -> ReportBundle:
    path = spool_root / report_id
    manifest = path / "manifest.sha256"
    report_json = path / "report.json"
    if not path.is_dir() or path.is_symlink() or not manifest.is_file() or not report_json.is_file():
        raise MonitoringContractError("existing report bundle is incomplete")
    payload = json.loads(report_json.read_text(encoding="utf-8"))
    evidence_refs = tuple(str(value) for value in payload.get("evidence_refs", []))
    coverage = payload.get("today", {}).get("average_coverage_pct")
    return ReportBundle(
        report_id=report_id,
        path=path,
        manifest_sha256=_sha256_file(manifest),
        evidence_refs=evidence_refs,
        coverage_pct=float(coverage) if isinstance(coverage, (int, float)) else 0.0,
    )


def _period_keys(cutoff: datetime) -> tuple[tuple[str, str], ...]:
    periods: list[tuple[str, str]] = [("daily", cutoff.strftime("%Y-%m-%d"))]
    if is_canonical_weekly(cutoff.isoformat()):
        iso_year, iso_week, _ = cutoff.isocalendar()
        periods.append(("weekly", f"{iso_year}-W{iso_week:02d}"))
    if is_canonical_monthly(cutoff.isoformat()):
        periods.append(("monthly", cutoff.strftime("%Y-%m")))
    return tuple(periods)


def run_reporting_cycle(config: ReportingConfig, *, cutoff_at: str) -> tuple[ReportReceipt, ...]:
    config.validate()
    if not config.enabled:
        raise RuntimeError("REPORTING_DISABLED")
    cutoff = datetime.fromisoformat(cutoff_at.replace("Z", "+00:00"))
    if cutoff.tzinfo is None:
        raise MonitoringContractError("cutoff_at must include timezone")
    cutoff = cutoff.astimezone(TOKYO)
    if (cutoff.hour, cutoff.minute) != (config.report_hour, config.report_minute):
        raise MonitoringContractError("report cutoff must be the configured 17:30 slot")

    store = MonitoringStore(config.database_path)
    state = ReportingReceiptStore(store)
    state.initialize()
    config.spool_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    report_id = f"report-{cutoff.strftime('%Y%m%d-1730')}"
    lock_key = f"daily-{cutoff.strftime('%Y-%m-%d')}"

    with ReportRunLock(config.spool_root, lock_key):
        final_path = config.spool_root / report_id
        if final_path.exists():
            bundle = load_existing_bundle(report_id=report_id, spool_root=config.spool_root)
        else:
            report = build_deterministic_report(store, cutoff_at=cutoff.isoformat())
            bundle = write_report_bundle(report, spool_root=config.spool_root)

        receipts: list[ReportReceipt] = []
        for period_kind, period_key in _period_keys(cutoff):
            archive = archive_existing_bundle(
                bundle,
                config=NasArchiveConfig(config.nas_root),
                period_kind=period_kind,
                period_key=period_key,
                attempt=1,
            )
            state.put_archive(archive)
            report_status = "completed" if archive.status == "archived" else "pending_nas"
            receipt = ReportReceipt(
                report_id=f"{report_id}-{period_kind}",
                period_kind=period_kind,
                period_key=period_key,
                cutoff_at=cutoff.isoformat(),
                status=report_status,
                coverage_pct=bundle.coverage_pct,
                bundle_ref=f"spool/{bundle.report_id}",
                manifest_sha256=bundle.manifest_sha256,
                evidence_refs=bundle.evidence_refs,
                ai_status="not_requested",
                archive_status=archive.status,
            ).validate()
            state.put_report(receipt)
            receipts.append(receipt)
        return tuple(receipts)


def retry_pending_archive(
    config: ReportingConfig,
    *,
    report_id: str,
    period_kind: str,
    period_key: str,
    attempt: int,
):
    """Retry NAS copy from the exact local bundle; never rebuild or re-analyze it."""

    config.validate()
    if attempt < 1 or attempt > config.max_archive_attempts_per_run:
        raise MonitoringContractError("archive retry attempt exceeds configured bound")
    bundle = load_existing_bundle(report_id=report_id, spool_root=config.spool_root)
    receipt = archive_existing_bundle(
        bundle,
        config=NasArchiveConfig(config.nas_root),
        period_kind=period_kind,
        period_key=period_key,
        attempt=attempt,
    )
    ReportingReceiptStore(MonitoringStore(config.database_path)).put_archive(receipt)
    return receipt
