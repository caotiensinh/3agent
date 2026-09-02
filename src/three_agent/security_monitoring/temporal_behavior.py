from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

from .contracts import MonitoringContractError, canonical_json, sha256_fingerprint
from .correlation_graph import CorrelationEvent

TEMPORAL_WINDOW_SCHEMA = "workspace-security-monitoring/temporal-window-v1"
TEMPORAL_BUCKET_SCHEMA = "workspace-security-monitoring/temporal-bucket-v1"


def _utc(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise MonitoringContractError(f"{field_name} must be UTC")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass(frozen=True)
class TemporalBucketConfig:
    bucket_seconds: int = 60
    max_window_seconds: int = 3600
    max_events: int = 10000
    max_buckets: int = 360

    def validate(self) -> "TemporalBucketConfig":
        if isinstance(self.bucket_seconds, bool) or not isinstance(self.bucket_seconds, int):
            raise MonitoringContractError("bucket_seconds must be an integer")
        if isinstance(self.max_window_seconds, bool) or not isinstance(self.max_window_seconds, int):
            raise MonitoringContractError("max_window_seconds must be an integer")
        if isinstance(self.max_events, bool) or not isinstance(self.max_events, int):
            raise MonitoringContractError("max_events must be an integer")
        if isinstance(self.max_buckets, bool) or not isinstance(self.max_buckets, int):
            raise MonitoringContractError("max_buckets must be an integer")
        if not 10 <= self.bucket_seconds <= 3600:
            raise MonitoringContractError("bucket_seconds must be within 10..3600")
        if not self.bucket_seconds <= self.max_window_seconds <= 86400:
            raise MonitoringContractError("max_window_seconds is outside bounds")
        if not 1 <= self.max_events <= 50000:
            raise MonitoringContractError("max_events must be within 1..50000")
        if not 1 <= self.max_buckets <= 8640:
            raise MonitoringContractError("max_buckets must be within 1..8640")
        if (self.max_window_seconds + self.bucket_seconds - 1) // self.bucket_seconds > self.max_buckets:
            raise MonitoringContractError("max_buckets cannot cover max_window_seconds")
        return self

    def to_dict(self) -> dict[str, int]:
        self.validate()
        return {
            "bucket_seconds": self.bucket_seconds,
            "max_buckets": self.max_buckets,
            "max_events": self.max_events,
            "max_window_seconds": self.max_window_seconds,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


@dataclass(frozen=True)
class TemporalAnalysisWindow:
    starts_at: str
    ends_at: str
    schema_version: str = TEMPORAL_WINDOW_SCHEMA

    def validate(self, *, max_window_seconds: int = 3600) -> "TemporalAnalysisWindow":
        start_text = _utc(self.starts_at, "starts_at")
        end_text = _utc(self.ends_at, "ends_at")
        start = _dt(start_text)
        end = _dt(end_text)
        duration = (end - start).total_seconds()
        if duration <= 0:
            raise MonitoringContractError("temporal window must have positive duration")
        if duration > max_window_seconds:
            raise MonitoringContractError("temporal window exceeds configured bound")
        if self.schema_version != TEMPORAL_WINDOW_SCHEMA:
            raise MonitoringContractError("unsupported temporal window schema")
        object.__setattr__(self, "starts_at", start_text)
        object.__setattr__(self, "ends_at", end_text)
        return self

    def to_dict(self) -> dict[str, str]:
        return {
            "ends_at": self.ends_at,
            "schema_version": self.schema_version,
            "starts_at": self.starts_at,
        }


@dataclass(frozen=True)
class TemporalBucket:
    bucket_index: int
    starts_at: str
    ends_at: str
    event_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    stage_types: tuple[str, ...]
    schema_version: str = TEMPORAL_BUCKET_SCHEMA

    def validate(self) -> "TemporalBucket":
        if isinstance(self.bucket_index, bool) or not isinstance(self.bucket_index, int) or self.bucket_index < 0:
            raise MonitoringContractError("bucket_index must be a non-negative integer")
        object.__setattr__(self, "starts_at", _utc(self.starts_at, "starts_at"))
        object.__setattr__(self, "ends_at", _utc(self.ends_at, "ends_at"))
        if _dt(self.ends_at) <= _dt(self.starts_at):
            raise MonitoringContractError("temporal bucket must have positive duration")
        events = tuple(sorted(set(str(value) for value in self.event_ids)))
        if not events or len(events) > 50000:
            raise MonitoringContractError("temporal bucket event_ids are outside bounds")
        evidence = tuple(sorted(set(str(value) for value in self.evidence_refs if value)))
        stages = tuple(sorted(set(str(value) for value in self.stage_types if value)))
        object.__setattr__(self, "event_ids", events)
        object.__setattr__(self, "evidence_refs", evidence)
        object.__setattr__(self, "stage_types", stages)
        if self.schema_version != TEMPORAL_BUCKET_SCHEMA:
            raise MonitoringContractError("unsupported temporal bucket schema")
        return self

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "bucket_index": self.bucket_index,
            "ends_at": self.ends_at,
            "event_ids": list(self.event_ids),
            "evidence_refs": list(self.evidence_refs),
            "schema_version": self.schema_version,
            "stage_types": list(self.stage_types),
            "starts_at": self.starts_at,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


def _event_identity(item: CorrelationEvent) -> tuple[object, ...]:
    item.validate()
    return (
        item.event.event_id,
        item.event.source_id,
        item.event.source_type,
        item.event.observed_at,
        item.event.category,
        item.event.severity,
        item.event.message_sha256,
        item.event.parser_version,
        item.event.evidence_ref,
        tuple(item.context.references),
    )


class DeterministicTemporalBucketizer:
    """Build bounded temporal buckets from already-normalized correlation events without I/O."""

    def __init__(self, config: TemporalBucketConfig | None = None) -> None:
        self.config = (config or TemporalBucketConfig()).validate()

    def bucketize(
        self,
        *,
        window: TemporalAnalysisWindow,
        events: Iterable[CorrelationEvent],
    ) -> tuple[TemporalBucket, ...]:
        bound = window.validate(max_window_seconds=self.config.max_window_seconds)
        start = _dt(bound.starts_at)
        end = _dt(bound.ends_at)

        unique: dict[str, CorrelationEvent] = {}
        for raw in events:
            item = raw.validate()
            event_id = item.event.event_id
            previous = unique.get(event_id)
            if previous is not None:
                if _event_identity(previous) != _event_identity(item):
                    raise MonitoringContractError("temporal duplicate event_id has conflicting evidence")
                continue
            observed = item.observed.astimezone(timezone.utc)
            if observed < start or observed >= end:
                raise MonitoringContractError("temporal event falls outside analysis window")
            unique[event_id] = item
            if len(unique) > self.config.max_events:
                raise MonitoringContractError("temporal event bound exceeded")

        ordered = tuple(sorted(unique.values(), key=lambda item: (item.observed, item.event.event_id)))
        grouped: dict[int, list[CorrelationEvent]] = {}
        for item in ordered:
            delta_seconds = (item.observed.astimezone(timezone.utc) - start).total_seconds()
            index = int(delta_seconds // self.config.bucket_seconds)
            grouped.setdefault(index, []).append(item)

        if len(grouped) > self.config.max_buckets:
            raise MonitoringContractError("temporal bucket bound exceeded")

        buckets: list[TemporalBucket] = []
        for index in sorted(grouped):
            bucket_start = start + timedelta(seconds=index * self.config.bucket_seconds)
            bucket_end = min(bucket_start + timedelta(seconds=self.config.bucket_seconds), end)
            bucket_events = grouped[index]
            buckets.append(
                TemporalBucket(
                    bucket_index=index,
                    starts_at=bucket_start.isoformat().replace("+00:00", "Z"),
                    ends_at=bucket_end.isoformat().replace("+00:00", "Z"),
                    event_ids=tuple(item.event.event_id for item in bucket_events),
                    evidence_refs=tuple(item.event.evidence_ref or "" for item in bucket_events),
                    stage_types=tuple(item.stage or "" for item in bucket_events),
                ).validate()
            )
        return tuple(buckets)
