from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .contracts import CanonicalEvent, MonitoringContractError, _compact
from .log_pipeline import SourceFreshness, evaluate_source_freshness
from .parsers import JSON_SENSOR_PARSER_VERSION, QuarantinedRecord, parse_json_sensor_event

PASSIVE_SENSOR_SCHEMA = "workspace-security-monitoring/passive-sensor-v1"
PASSIVE_SENSOR_TYPES = {"zeek_json", "suricata_eve", "flow_json"}
FLOW_TYPES = {"netflow", "sflow", "ipfix"}
MAX_SENSOR_LINE_BYTES = 256 * 1024


@dataclass(frozen=True)
class PassiveSensorConfig:
    """Read-only contract for telemetry already emitted to a local JSONL file.

    WorkSpace does not install, launch, configure, sniff for, or open a listener for
    these sensors. `flow_json` is admitted only for telemetry already normalized by
    an existing exporter.
    """

    source_id: str
    source_type: str
    path: Path
    enabled: bool = False
    expected_interval_seconds: int = 300
    max_read_bytes: int = 4 * 1024 * 1024
    max_records: int = 4096
    existing_telemetry_only: bool = True

    def validate(self) -> "PassiveSensorConfig":
        object.__setattr__(self, "source_id", _compact(self.source_id, "source_id", max_len=128))
        if self.source_type not in PASSIVE_SENSOR_TYPES:
            raise MonitoringContractError("unsupported passive sensor source_type")
        path = Path(self.path)
        if not path.is_absolute():
            raise MonitoringContractError("passive sensor path must be absolute")
        object.__setattr__(self, "path", path)
        if not 1 <= int(self.expected_interval_seconds) <= 86400:
            raise MonitoringContractError("expected_interval_seconds must be within 1..86400")
        if not 4096 <= int(self.max_read_bytes) <= 16 * 1024 * 1024:
            raise MonitoringContractError("max_read_bytes must be within 4KiB..16MiB")
        if not 1 <= int(self.max_records) <= 10000:
            raise MonitoringContractError("max_records must be within 1..10000")
        if self.source_type == "flow_json" and not self.existing_telemetry_only:
            raise MonitoringContractError("FLOW_SENSOR_REQUIRES_EXISTING_TELEMETRY")
        return self


@dataclass(frozen=True)
class PassiveSensorHealth:
    source_id: str
    source_type: str
    evaluated_at: str
    state: str
    reason_codes: tuple[str, ...]
    last_seen_at: str | None
    age_seconds: float | None
    records_examined: int
    events_emitted: int
    quarantined_records: int
    dropped_records: int | None
    drop_percent: float | None
    bytes_read: int
    tail_truncated: bool
    schema_version: str = PASSIVE_SENSOR_SCHEMA


@dataclass(frozen=True)
class PassiveSensorBatch:
    events: tuple[CanonicalEvent, ...]
    quarantined: tuple[QuarantinedRecord, ...]
    health: PassiveSensorHealth


def _iso_timestamp(value: Any) -> str:
    if isinstance(value, bool):
        raise ValueError
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError
    return parsed.isoformat()


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _quarantine(source_id: str, source_type: str, raw: bytes, reason_code: str, evaluated_at: str) -> QuarantinedRecord:
    return QuarantinedRecord(
        source_id=source_id,
        source_type=source_type,
        parser_version=JSON_SENSOR_PARSER_VERSION,
        reason_code=reason_code,
        payload_sha256=_digest(raw),
        observed_at=evaluated_at,
    )


def _parse_flow_event(*, source_id: str, raw_line: str, evaluated_at: str) -> CanonicalEvent | QuarantinedRecord:
    raw = raw_line.encode("utf-8", errors="replace")
    digest = _digest(raw)
    try:
        payload = json.loads(raw_line)
        if not isinstance(payload, dict):
            raise ValueError
        flow_type = str(payload.get("flow_type") or "").strip().lower()
        if flow_type not in FLOW_TYPES:
            raise ValueError
        observed_at = _iso_timestamp(payload.get("timestamp", payload.get("ts")))
    except (json.JSONDecodeError, TypeError, ValueError, OverflowError):
        return _quarantine(source_id, "flow_json", raw, "FLOW_JSON_PARSE_FAILED", evaluated_at)

    return CanonicalEvent(
        event_id="evt-" + digest.removeprefix("sha256:")[:24],
        source_id=source_id,
        source_type="flow_json",
        observed_at=observed_at,
        category="flow." + flow_type,
        severity="info",
        message_sha256=digest,
        parser_version="workspace-flow-json/v1",
        evidence_ref="event:" + digest.removeprefix("sha256:")[:32],
    ).validate()


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return max(0.0, float(value))


def _drop_metrics(payload: dict[str, Any], source_type: str) -> tuple[int | None, float | None]:
    drop_count: float | None = None
    drop_percent: float | None = None
    if source_type == "suricata_eve" and payload.get("event_type") == "stats":
        stats = payload.get("stats") if isinstance(payload.get("stats"), dict) else {}
        capture = stats.get("capture") if isinstance(stats.get("capture"), dict) else {}
        drop_count = _number(capture.get("kernel_drops"))
        if drop_count is None:
            drop_count = _number(capture.get("kernel_drop"))
    elif source_type == "zeek_json" and str(payload.get("_path") or "") == "capture_loss":
        drop_percent = _number(payload.get("percent_lost"))
    elif source_type == "flow_json":
        drop_count = _number(payload.get("dropped_records"))
        drop_percent = _number(payload.get("drop_percent"))
    if drop_percent is not None:
        drop_percent = min(100.0, drop_percent)
    return (int(drop_count) if drop_count is not None else None, drop_percent)


def _read_bounded_tail(path: Path, *, max_bytes: int) -> tuple[bytes, bool]:
    size = path.stat().st_size
    start = max(0, size - max_bytes)
    with path.open("rb") as handle:
        handle.seek(start)
        data = handle.read(max_bytes)
    if start:
        newline = data.find(b"\n")
        data = b"" if newline < 0 else data[newline + 1 :]
    return data, start > 0


def _latest_event_timestamp(events: list[CanonicalEvent]) -> str | None:
    if not events:
        return None
    return max(
        events,
        key=lambda event: datetime.fromisoformat(event.observed_at.replace("Z", "+00:00")),
    ).observed_at


class PassiveJsonlSensorAdapter:
    """Bounded local-file adapter with no socket, subprocess, or packet-capture authority."""

    def __init__(self, config: PassiveSensorConfig):
        self.config = config.validate()

    def read_batch(self, *, evaluated_at: str) -> PassiveSensorBatch:
        evaluated = _iso_timestamp(evaluated_at)
        cfg = self.config
        if not cfg.enabled:
            health = PassiveSensorHealth(
                source_id=cfg.source_id,
                source_type=cfg.source_type,
                evaluated_at=evaluated,
                state="disabled",
                reason_codes=("SENSOR_DISABLED",),
                last_seen_at=None,
                age_seconds=None,
                records_examined=0,
                events_emitted=0,
                quarantined_records=0,
                dropped_records=None,
                drop_percent=None,
                bytes_read=0,
                tail_truncated=False,
            )
            return PassiveSensorBatch((), (), health)

        path = cfg.path
        if not path.exists():
            return self._gap(evaluated, "SENSOR_INPUT_MISSING")
        if path.is_symlink():
            raise MonitoringContractError("SENSOR_INPUT_SYMLINK_DENIED")
        if not path.is_file():
            raise MonitoringContractError("SENSOR_INPUT_NOT_REGULAR_FILE")

        raw, tail_truncated = _read_bounded_tail(path, max_bytes=cfg.max_read_bytes)
        raw_lines = raw.splitlines()
        if len(raw_lines) > cfg.max_records:
            raw_lines = raw_lines[-cfg.max_records :]
            tail_truncated = True

        events: list[CanonicalEvent] = []
        quarantined: list[QuarantinedRecord] = []
        drop_counts: list[int] = []
        drop_percents: list[float] = []
        for raw_line in raw_lines:
            if not raw_line.strip():
                continue
            if len(raw_line) > MAX_SENSOR_LINE_BYTES:
                quarantined.append(
                    _quarantine(cfg.source_id, cfg.source_type, raw_line, "SENSOR_RECORD_TOO_LARGE", evaluated)
                )
                continue
            text = raw_line.decode("utf-8", errors="replace")
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                count, percent = _drop_metrics(payload, cfg.source_type)
                if count is not None:
                    drop_counts.append(count)
                if percent is not None:
                    drop_percents.append(percent)

            if cfg.source_type in {"zeek_json", "suricata_eve"}:
                parsed = parse_json_sensor_event(
                    source_id=cfg.source_id,
                    source_type=cfg.source_type,
                    raw_line=text,
                )
            else:
                parsed = _parse_flow_event(source_id=cfg.source_id, raw_line=text, evaluated_at=evaluated)
            if isinstance(parsed, CanonicalEvent):
                events.append(parsed)
            else:
                quarantined.append(parsed)

        last_seen = _latest_event_timestamp(events)
        freshness: SourceFreshness = evaluate_source_freshness(
            source_id=cfg.source_id,
            expected_interval_seconds=cfg.expected_interval_seconds,
            last_seen_at=last_seen,
            evaluated_at=evaluated,
        )
        reasons: list[str] = []
        state = "healthy"
        if not freshness.fresh:
            state = "data_gap"
            reasons.append(freshness.reason_code or "SOURCE_NOT_FRESH")
        if quarantined:
            if state == "healthy":
                state = "degraded"
            reasons.append("SENSOR_QUARANTINE_PRESENT")
        dropped_records = max(drop_counts) if drop_counts else None
        drop_percent = max(drop_percents) if drop_percents else None
        if (dropped_records or 0) > 0 or (drop_percent or 0.0) > 0.0:
            if state == "healthy":
                state = "degraded"
            reasons.append("SENSOR_DROPS_REPORTED")
        if tail_truncated:
            reasons.append("BOUNDED_TAIL_WINDOW")

        health = PassiveSensorHealth(
            source_id=cfg.source_id,
            source_type=cfg.source_type,
            evaluated_at=evaluated,
            state=state,
            reason_codes=tuple(dict.fromkeys(reasons)),
            last_seen_at=freshness.last_seen_at,
            age_seconds=freshness.age_seconds,
            records_examined=len(raw_lines),
            events_emitted=len(events),
            quarantined_records=len(quarantined),
            dropped_records=dropped_records,
            drop_percent=drop_percent,
            bytes_read=len(raw),
            tail_truncated=tail_truncated,
        )
        return PassiveSensorBatch(tuple(events), tuple(quarantined), health)

    def _gap(self, evaluated_at: str, reason: str) -> PassiveSensorBatch:
        cfg = self.config
        health = PassiveSensorHealth(
            source_id=cfg.source_id,
            source_type=cfg.source_type,
            evaluated_at=evaluated_at,
            state="data_gap",
            reason_codes=(reason,),
            last_seen_at=None,
            age_seconds=None,
            records_examined=0,
            events_emitted=0,
            quarantined_records=0,
            dropped_records=None,
            drop_percent=None,
            bytes_read=0,
            tail_truncated=False,
        )
        return PassiveSensorBatch((), (), health)
