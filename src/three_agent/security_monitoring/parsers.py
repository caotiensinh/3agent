from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .contracts import CanonicalEvent, MonitoringContractError

SYSLOG_PARSER_VERSION = "workspace-syslog/v1"
JSON_SENSOR_PARSER_VERSION = "workspace-json-sensor/v1"
_SYSLOG_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<timestamp>\S+)\s+(?P<host>\S+)\s+(?P<app>[A-Za-z0-9_.\-/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)


@dataclass(frozen=True)
class QuarantinedRecord:
    source_id: str
    source_type: str
    parser_version: str
    reason_code: str
    payload_sha256: str
    observed_at: str


def _digest_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity_from_syslog_priority(priority: int) -> str:
    severity = priority & 7
    if severity <= 1:
        return "critical"
    if severity <= 3:
        return "high"
    if severity == 4:
        return "medium"
    if severity <= 6:
        return "low"
    return "info"


def parse_syslog_line(*, source_id: str, line: str) -> CanonicalEvent | QuarantinedRecord:
    raw = str(line).encode("utf-8", errors="replace")
    digest = _digest_bytes(raw)
    match = _SYSLOG_RE.match(str(line).strip())
    if not match:
        return QuarantinedRecord(
            source_id=source_id,
            source_type="syslog",
            parser_version=SYSLOG_PARSER_VERSION,
            reason_code="SYSLOG_PARSE_FAILED",
            payload_sha256=digest,
            observed_at=_now_iso(),
        )
    try:
        priority = int(match.group("pri"))
        if not 0 <= priority <= 191:
            raise ValueError
        timestamp = datetime.fromisoformat(match.group("timestamp").replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError
    except ValueError:
        return QuarantinedRecord(
            source_id=source_id,
            source_type="syslog",
            parser_version=SYSLOG_PARSER_VERSION,
            reason_code="SYSLOG_HEADER_INVALID",
            payload_sha256=digest,
            observed_at=_now_iso(),
        )
    category = "syslog." + match.group("app").lower().replace("/", "_")[:72]
    event_id = "evt-" + digest.removeprefix("sha256:")[:24]
    return CanonicalEvent(
        event_id=event_id,
        source_id=source_id,
        source_type="syslog",
        observed_at=timestamp.isoformat(),
        category=category,
        severity=_severity_from_syslog_priority(priority),
        message_sha256=digest,
        parser_version=SYSLOG_PARSER_VERSION,
        evidence_ref="event:" + digest.removeprefix("sha256:")[:32],
    ).validate()


def _event_timestamp(payload: dict[str, Any], source_type: str) -> str:
    candidates: list[Any]
    if source_type == "suricata_eve":
        candidates = [payload.get("timestamp")]
    elif source_type == "zeek_json":
        candidates = [payload.get("ts"), payload.get("timestamp")]
    else:
        candidates = [payload.get("timestamp"), payload.get("ts")]
    for candidate in candidates:
        if candidate is None:
            continue
        try:
            if isinstance(candidate, (int, float)):
                return datetime.fromtimestamp(float(candidate), tz=timezone.utc).isoformat()
            parsed = datetime.fromisoformat(str(candidate).replace("Z", "+00:00"))
            if parsed.tzinfo is not None:
                return parsed.isoformat()
        except (ValueError, TypeError, OverflowError):
            continue
    raise MonitoringContractError("sensor event timestamp missing/invalid")


def parse_json_sensor_event(*, source_id: str, source_type: str, raw_line: str) -> CanonicalEvent | QuarantinedRecord:
    raw = str(raw_line).encode("utf-8", errors="replace")
    digest = _digest_bytes(raw)
    if source_type not in {"suricata_eve", "zeek_json"}:
        raise MonitoringContractError("unsupported JSON sensor source_type")
    try:
        payload = json.loads(raw_line)
        if not isinstance(payload, dict):
            raise ValueError
        observed_at = _event_timestamp(payload, source_type)
    except (json.JSONDecodeError, ValueError, MonitoringContractError):
        return QuarantinedRecord(
            source_id=source_id,
            source_type=source_type,
            parser_version=JSON_SENSOR_PARSER_VERSION,
            reason_code="JSON_SENSOR_PARSE_FAILED",
            payload_sha256=digest,
            observed_at=_now_iso(),
        )

    if source_type == "suricata_eve":
        event_type = str(payload.get("event_type") or "unknown")
        alert = payload.get("alert") if isinstance(payload.get("alert"), dict) else {}
        severity_num = alert.get("severity")
        severity = "info"
        if event_type == "alert":
            severity = {1: "critical", 2: "high", 3: "medium", 4: "low"}.get(severity_num, "medium")
        category = "suricata." + re.sub(r"[^A-Za-z0-9_.-]+", "_", event_type.lower())[:72]
    else:
        event_type = str(payload.get("_path") or payload.get("event_type") or "conn")
        category = "zeek." + re.sub(r"[^A-Za-z0-9_.-]+", "_", event_type.lower().strip("/"))[:72]
        severity = "info"

    event_id = "evt-" + digest.removeprefix("sha256:")[:24]
    return CanonicalEvent(
        event_id=event_id,
        source_id=source_id,
        source_type=source_type,
        observed_at=observed_at,
        category=category,
        severity=severity,
        message_sha256=digest,
        parser_version=JSON_SENSOR_PARSER_VERSION,
        evidence_ref="event:" + digest.removeprefix("sha256:")[:32],
    ).validate()
