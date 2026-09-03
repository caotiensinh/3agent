from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Mapping

from .contracts import MonitoringContractError, sha256_fingerprint
from .forensic_evidence import ForensicEventTime
from .incident_timeline import IncidentTimeline

FORENSIC_TIMELINE_CLOCK_SCHEMA = "workspace-security-forensics/timeline-clock-view-v1"
FORENSIC_TIMELINE_CLOCK_ENTRY_SCHEMA = "workspace-security-forensics/timeline-clock-entry-v1"
MAX_FORENSIC_TIMELINE_CLOCK_ENTRIES = 256


def _instant(value: str, field_name: str) -> datetime:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MonitoringContractError(f"{field_name} must include timezone")
    return parsed


@dataclass(frozen=True)
class ForensicTimelineClockEntry:
    event_id: str
    evidence_ref: str
    timeline_observed_at: str
    original_timestamp: str
    normalized_utc: str
    source_clock_ref: str
    uncertainty_ms: int
    delta_ms: int
    clock_conflict: bool
    schema_version: str = FORENSIC_TIMELINE_CLOCK_ENTRY_SCHEMA

    def validate(self) -> "ForensicTimelineClockEntry":
        if not self.event_id or not self.evidence_ref:
            raise MonitoringContractError("forensic timeline clock entry requires event and evidence refs")
        timeline_dt = _instant(self.timeline_observed_at, "timeline_observed_at")
        normalized_dt = _instant(self.normalized_utc, "normalized_utc")
        expected_delta = int(round((normalized_dt - timeline_dt).total_seconds() * 1000.0))
        if self.delta_ms != expected_delta:
            raise MonitoringContractError("forensic timeline clock delta mismatch")
        if isinstance(self.uncertainty_ms, bool) or not isinstance(self.uncertainty_ms, int):
            raise MonitoringContractError("forensic timeline clock uncertainty must be an integer")
        if self.clock_conflict != (abs(self.delta_ms) > self.uncertainty_ms):
            raise MonitoringContractError("forensic timeline clock conflict flag mismatch")
        if self.schema_version != FORENSIC_TIMELINE_CLOCK_ENTRY_SCHEMA:
            raise MonitoringContractError("unsupported forensic timeline clock entry schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "evidence_ref": self.evidence_ref,
            "timeline_observed_at": self.timeline_observed_at,
            "original_timestamp": self.original_timestamp,
            "normalized_utc": self.normalized_utc,
            "source_clock_ref": self.source_clock_ref,
            "uncertainty_ms": self.uncertainty_ms,
            "delta_ms": self.delta_ms,
            "clock_conflict": self.clock_conflict,
        }


@dataclass(frozen=True)
class ForensicTimelineClockView:
    timeline_fingerprint: str
    entries: tuple[ForensicTimelineClockEntry, ...]
    missing_clock_event_ids: tuple[str, ...]
    conflict_event_ids: tuple[str, ...]
    authority: str = "advisory"
    schema_version: str = FORENSIC_TIMELINE_CLOCK_SCHEMA

    def validate(self) -> "ForensicTimelineClockView":
        if not self.timeline_fingerprint.startswith("sha256:"):
            raise MonitoringContractError("forensic timeline clock view requires timeline fingerprint")
        if len(self.entries) > MAX_FORENSIC_TIMELINE_CLOCK_ENTRIES:
            raise MonitoringContractError("forensic timeline clock entry bound exceeded")
        event_ids = tuple(entry.event_id for entry in self.entries)
        if len(event_ids) != len(set(event_ids)):
            raise MonitoringContractError("forensic timeline clock event IDs must be unique")
        for entry in self.entries:
            entry.validate()
        if tuple(sorted(set(self.missing_clock_event_ids))) != self.missing_clock_event_ids:
            raise MonitoringContractError("missing clock event IDs must be sorted and unique")
        expected_conflicts = tuple(sorted(entry.event_id for entry in self.entries if entry.clock_conflict))
        if self.conflict_event_ids != expected_conflicts:
            raise MonitoringContractError("forensic timeline clock conflict set mismatch")
        if set(self.missing_clock_event_ids) & set(event_ids):
            raise MonitoringContractError("clock-present and clock-missing event sets overlap")
        if self.authority != "advisory":
            raise MonitoringContractError("forensic timeline clock view must remain advisory")
        if self.schema_version != FORENSIC_TIMELINE_CLOCK_SCHEMA:
            raise MonitoringContractError("unsupported forensic timeline clock schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "timeline_fingerprint": self.timeline_fingerprint,
            "entries": [entry.public_dict() for entry in self.entries],
            "missing_clock_event_ids": list(self.missing_clock_event_ids),
            "conflict_event_ids": list(self.conflict_event_ids),
            "authority": self.authority,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


def build_forensic_timeline_clock_view(
    timeline: IncidentTimeline,
    event_times: Mapping[str, ForensicEventTime],
) -> ForensicTimelineClockView:
    if not isinstance(timeline, IncidentTimeline):
        raise MonitoringContractError("forensic clock view requires IncidentTimeline")
    timeline.validate()
    if len(event_times) > MAX_FORENSIC_TIMELINE_CLOCK_ENTRIES:
        raise MonitoringContractError("forensic clock input bound exceeded")

    known_ids = {entry.event_id for entry in timeline.entries}
    unknown_ids = set(event_times) - known_ids
    if unknown_ids:
        raise MonitoringContractError("forensic clock input contains event outside timeline")

    rows: list[ForensicTimelineClockEntry] = []
    missing: list[str] = []
    for entry in timeline.entries:
        forensic_time = event_times.get(entry.event_id)
        if forensic_time is None:
            missing.append(entry.event_id)
            continue
        if not isinstance(forensic_time, ForensicEventTime):
            raise MonitoringContractError("forensic clock input type is invalid")
        forensic_time.validate()
        timeline_dt = _instant(entry.observed_at, "timeline_observed_at")
        normalized_dt = _instant(forensic_time.normalized_utc, "normalized_utc")
        delta_ms = int(round((normalized_dt - timeline_dt).total_seconds() * 1000.0))
        rows.append(
            ForensicTimelineClockEntry(
                event_id=entry.event_id,
                evidence_ref=entry.evidence_ref,
                timeline_observed_at=entry.observed_at,
                original_timestamp=forensic_time.original_timestamp,
                normalized_utc=forensic_time.normalized_utc,
                source_clock_ref=forensic_time.source_clock_ref,
                uncertainty_ms=forensic_time.uncertainty_ms,
                delta_ms=delta_ms,
                clock_conflict=abs(delta_ms) > forensic_time.uncertainty_ms,
            ).validate()
        )

    rows.sort(key=lambda item: item.event_id)
    conflicts = tuple(sorted(row.event_id for row in rows if row.clock_conflict))
    return ForensicTimelineClockView(
        timeline_fingerprint=timeline.fingerprint,
        entries=tuple(rows),
        missing_clock_event_ids=tuple(sorted(missing)),
        conflict_event_ids=conflicts,
    ).validate()
