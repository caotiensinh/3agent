from __future__ import annotations

import csv
import gzip
import hashlib
import json
import os
import shutil
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from statistics import fmean
from typing import Any
from zoneinfo import ZoneInfo

from .contracts import MonitoringContractError, _compact
from .storage import MonitoringStore

TOKYO = ZoneInfo("Asia/Tokyo")
REPORT_SCHEMA = "workspace-security-monitoring/deterministic-report-v1"
MAX_QUERY_ROWS = 100_000


@dataclass(frozen=True)
class MetricSummary:
    metric: str
    sample_count: int
    minimum: float
    maximum: float
    average: float


@dataclass(frozen=True)
class PeriodSummary:
    label: str
    starts_at: str
    ends_at: str
    hourly_runs: int
    average_coverage_pct: float | None
    event_count: int
    finding_count: int
    open_high_critical: int
    severity_counts: dict[str, int]
    finding_status_counts: dict[str, int]
    data_gap_count: int
    metric_summaries: tuple[MetricSummary, ...]


@dataclass(frozen=True)
class DeterministicReport:
    report_id: str
    cutoff_at: str
    generated_at: str
    today: PeriodSummary
    rolling_7d: PeriodSummary
    rolling_30d: PeriodSummary
    evidence_refs: tuple[str, ...]
    findings: tuple[dict[str, Any], ...]
    schema_version: str = REPORT_SCHEMA


@dataclass(frozen=True)
class ReportBundle:
    report_id: str
    path: Path
    manifest_sha256: str
    evidence_refs: tuple[str, ...]
    coverage_pct: float


class ReportAlreadyLocked(RuntimeError):
    pass


class ReportRunLock:
    def __init__(self, root: Path, key: str):
        self.root = root
        self.key = _compact(key, "report_lock_key", max_len=160)
        self.path = root / ".locks" / f"{self.key}.lock"
        self.fd: int | None = None

    def __enter__(self) -> "ReportRunLock":
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise ReportAlreadyLocked("REPORT_SLOT_ALREADY_LOCKED") from exc
        os.write(self.fd, str(os.getpid()).encode("ascii"))
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.fd is not None:
            os.close(self.fd)
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def _parse_cutoff(cutoff_at: str) -> datetime:
    value = datetime.fromisoformat(str(cutoff_at).replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise MonitoringContractError("report cutoff must include timezone")
    return value.astimezone(TOKYO)


def _utc_iso(value: datetime) -> str:
    return value.astimezone(ZoneInfo("UTC")).isoformat()


def _bounded_rows(conn, query: str, params: tuple[Any, ...]) -> list[Any]:
    rows = conn.execute(query + f" LIMIT {MAX_QUERY_ROWS + 1}", params).fetchall()
    if len(rows) > MAX_QUERY_ROWS:
        raise MonitoringContractError("REPORT_QUERY_LIMIT_EXCEEDED")
    return list(rows)


def _window_summary(store: MonitoringStore, *, label: str, start: datetime, end: datetime) -> PeriodSummary:
    start_iso, end_iso = _utc_iso(start), _utc_iso(end)
    with store.connect() as conn:
        runs = _bounded_rows(
            conn,
            "SELECT run_id,coverage_pct,failure_codes_json FROM hourly_runs "
            "WHERE julianday(scheduled_at)>=julianday(?) AND julianday(scheduled_at)<=julianday(?) ORDER BY scheduled_at",
            (start_iso, end_iso),
        )
        events = _bounded_rows(
            conn,
            "SELECT event_id,severity FROM canonical_events "
            "WHERE julianday(observed_at)>=julianday(?) AND julianday(observed_at)<=julianday(?) ORDER BY observed_at",
            (start_iso, end_iso),
        )
        findings = _bounded_rows(
            conn,
            "SELECT finding_id,severity,status FROM findings "
            "WHERE julianday(last_seen)>=julianday(?) AND julianday(last_seen)<=julianday(?) ORDER BY last_seen",
            (start_iso, end_iso),
        )
        observations = _bounded_rows(
            conn,
            "SELECT metric,status,value_json FROM observations "
            "WHERE julianday(observed_at)>=julianday(?) AND julianday(observed_at)<=julianday(?) ORDER BY observed_at",
            (start_iso, end_iso),
        )

    coverages = [float(row["coverage_pct"]) for row in runs]
    data_gaps = 0
    for row in runs:
        try:
            failures = json.loads(row["failure_codes_json"])
        except (TypeError, json.JSONDecodeError):
            failures = ["INVALID_FAILURE_METADATA"]
        data_gaps += sum(str(code).startswith("DATA_GAP") for code in failures)

    severity_counts: dict[str, int] = {}
    for row in events:
        severity_counts[row["severity"]] = severity_counts.get(row["severity"], 0) + 1
    finding_status_counts: dict[str, int] = {}
    for row in findings:
        finding_status_counts[row["status"]] = finding_status_counts.get(row["status"], 0) + 1

    values: dict[str, list[float]] = {}
    for row in observations:
        if row["status"] != "ok":
            continue
        try:
            value = json.loads(row["value_json"])
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        values.setdefault(row["metric"], []).append(float(value))
    metric_summaries = tuple(
        MetricSummary(
            metric=metric,
            sample_count=len(samples),
            minimum=min(samples),
            maximum=max(samples),
            average=fmean(samples),
        )
        for metric, samples in sorted(values.items())
    )
    open_high_critical = sum(
        1 for row in findings if row["status"] != "resolved" and row["severity"] in {"high", "critical"}
    )
    return PeriodSummary(
        label=label,
        starts_at=start.isoformat(),
        ends_at=end.isoformat(),
        hourly_runs=len(runs),
        average_coverage_pct=round(fmean(coverages), 3) if coverages else None,
        event_count=len(events),
        finding_count=len(findings),
        open_high_critical=open_high_critical,
        severity_counts=dict(sorted(severity_counts.items())),
        finding_status_counts=dict(sorted(finding_status_counts.items())),
        data_gap_count=data_gaps,
        metric_summaries=metric_summaries,
    )


def _finding_export(store: MonitoringStore, *, start: datetime, end: datetime) -> tuple[dict[str, Any], ...]:
    with store.connect() as conn:
        rows = _bounded_rows(
            conn,
            "SELECT finding_id,category,severity,status,first_seen,last_seen,asset_refs_json,evidence_refs_json,rule_id "
            "FROM findings WHERE julianday(last_seen)>=julianday(?) AND julianday(last_seen)<=julianday(?) "
            "ORDER BY last_seen,finding_id",
            (_utc_iso(start), _utc_iso(end)),
        )
    result = []
    for row in rows:
        result.append(
            {
                "finding_id": row["finding_id"],
                "category": row["category"],
                "severity": row["severity"],
                "status": row["status"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "asset_refs": json.loads(row["asset_refs_json"]),
                "evidence_refs": json.loads(row["evidence_refs_json"]),
                "rule_id": row["rule_id"],
            }
        )
    return tuple(result)


def build_deterministic_report(store: MonitoringStore, *, cutoff_at: str) -> DeterministicReport:
    cutoff = _parse_cutoff(cutoff_at)
    today_start = cutoff.replace(hour=0, minute=0, second=0, microsecond=0)
    rolling_7_start = cutoff - timedelta(days=7)
    rolling_30_start = cutoff - timedelta(days=30)
    today = _window_summary(store, label="today", start=today_start, end=cutoff)
    rolling_7 = _window_summary(store, label="rolling_7d", start=rolling_7_start, end=cutoff)
    rolling_30 = _window_summary(store, label="rolling_30d", start=rolling_30_start, end=cutoff)
    findings = _finding_export(store, start=rolling_30_start, end=cutoff)
    evidence_refs = tuple(
        dict.fromkeys(
            ref
            for finding in findings
            for ref in finding.get("evidence_refs", [])
            if isinstance(ref, str)
        )
    )
    report_id = f"report-{cutoff.strftime('%Y%m%d-1730')}"
    return DeterministicReport(
        report_id=report_id,
        cutoff_at=cutoff.isoformat(),
        generated_at=datetime.now(TOKYO).isoformat(),
        today=today,
        rolling_7d=rolling_7,
        rolling_30d=rolling_30,
        evidence_refs=evidence_refs,
        findings=findings,
    )


def _report_json_payload(report: DeterministicReport) -> dict[str, Any]:
    payload = asdict(report)
    payload["findings"] = list(report.findings)
    return payload


def _render_markdown(report: DeterministicReport) -> str:
    lines = [
        f"# Security Analyst Daily Report — {report.cutoff_at[:10]}",
        "",
        f"Cutoff: `{report.cutoff_at}`",
        f"Generated: `{report.generated_at}`",
        "",
    ]
    for period in (report.today, report.rolling_7d, report.rolling_30d):
        lines.extend(
            [
                f"## {period.label}",
                f"- Hourly runs: {period.hourly_runs}",
                f"- Average coverage: {period.average_coverage_pct if period.average_coverage_pct is not None else 'DATA GAP'}",
                f"- Events: {period.event_count}",
                f"- Findings: {period.finding_count}",
                f"- Open High/Critical: {period.open_high_critical}",
                f"- Data gaps: {period.data_gap_count}",
                "",
            ]
        )
    lines.append("AI narrative: NOT REQUESTED (deterministic NS-4 report).")
    return "\n".join(lines) + "\n"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def write_report_bundle(report: DeterministicReport, *, spool_root: Path) -> ReportBundle:
    root = Path(spool_root)
    if not root.is_absolute() or root.is_symlink():
        raise MonitoringContractError("report spool root must be an absolute non-symlink path")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    final = root / report.report_id
    if final.exists():
        raise MonitoringContractError("REPORT_BUNDLE_ALREADY_EXISTS")
    temp = root / f".{report.report_id}.{os.getpid()}.tmp"
    if temp.exists():
        shutil.rmtree(temp)
    temp.mkdir(mode=0o700)
    try:
        (temp / "report.md").write_text(_render_markdown(report), encoding="utf-8")
        (temp / "report.json").write_text(
            json.dumps(_report_json_payload(report), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        with (temp / "metrics-summary.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["period", "metric", "sample_count", "minimum", "maximum", "average"])
            for period in (report.today, report.rolling_7d, report.rolling_30d):
                for metric in period.metric_summaries:
                    writer.writerow([period.label, metric.metric, metric.sample_count, metric.minimum, metric.maximum, metric.average])
        with gzip.open(temp / "findings.jsonl.gz", "wt", encoding="utf-8") as handle:
            for finding in report.findings:
                handle.write(json.dumps(finding, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")

        manifest_lines = []
        for name in ("report.md", "report.json", "metrics-summary.csv", "findings.jsonl.gz"):
            manifest_lines.append(f"{_sha256_file(temp / name).removeprefix('sha256:')}  {name}")
        manifest = temp / "manifest.sha256"
        manifest.write_text("\n".join(manifest_lines) + "\n", encoding="ascii")
        manifest_digest = _sha256_file(manifest)
        os.replace(temp, final)
    except Exception:
        if temp.exists():
            shutil.rmtree(temp, ignore_errors=True)
        raise
    coverage = report.today.average_coverage_pct if report.today.average_coverage_pct is not None else 0.0
    return ReportBundle(
        report_id=report.report_id,
        path=final,
        manifest_sha256=manifest_digest,
        evidence_refs=report.evidence_refs,
        coverage_pct=coverage,
    )


def is_canonical_weekly(cutoff_at: str) -> bool:
    return _parse_cutoff(cutoff_at).weekday() == 6


def is_canonical_monthly(cutoff_at: str) -> bool:
    cutoff = _parse_cutoff(cutoff_at)
    return (cutoff + timedelta(days=1)).month != cutoff.month
