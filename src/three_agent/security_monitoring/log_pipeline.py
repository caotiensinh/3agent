from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .contracts import CanonicalEvent, MonitoringContractError, _compact


class SpoolFull(RuntimeError):
    pass


@dataclass(frozen=True)
class EvidencePartitionReceipt:
    partition_ref: str
    record_count: int
    uncompressed_bytes: int
    compressed_bytes: int
    sha256: str


class BoundedLogSpool:
    """Small local raw-input spool with explicit backpressure, never unbounded growth."""

    def __init__(self, root: str | Path, *, max_total_bytes: int = 64 * 1024 * 1024, max_file_bytes: int = 4 * 1024 * 1024):
        self.root = Path(root)
        if not self.root.is_absolute():
            raise MonitoringContractError("spool root must be absolute")
        if not 4096 <= max_file_bytes <= max_total_bytes:
            raise ValueError("invalid spool byte limits")
        self.max_total_bytes = int(max_total_bytes)
        self.max_file_bytes = int(max_file_bytes)

    def _size(self) -> int:
        if not self.root.exists():
            return 0
        return sum(path.stat().st_size for path in self.root.iterdir() if path.is_file() and not path.is_symlink())

    def append(self, *, source_id: str, raw_line: str) -> Path:
        source = _compact(source_id, "source_id", max_len=128)
        encoded = (str(raw_line).rstrip("\n") + "\n").encode("utf-8", errors="replace")
        if len(encoded) > 256 * 1024:
            raise MonitoringContractError("single log record exceeds 256KiB")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self._size() + len(encoded) > self.max_total_bytes:
            raise SpoolFull("LOG_SPOOL_FULL")
        current = self.root / f"{source}.current"
        if current.exists() and current.stat().st_size + len(encoded) > self.max_file_bytes:
            rotated = self.root / f"{source}.{time.time_ns()}.ready"
            os.replace(current, rotated)
        with current.open("ab") as handle:
            handle.write(encoded)
            handle.flush()
        return current

    def ready_files(self, *, limit: int = 32) -> tuple[Path, ...]:
        if limit < 1 or limit > 256:
            raise ValueError("limit must be within 1..256")
        if not self.root.exists():
            return ()
        paths = sorted((p for p in self.root.glob("*.ready") if p.is_file() and not p.is_symlink()), key=lambda p: p.stat().st_mtime_ns)
        return tuple(paths[:limit])


class EvidencePartitionWriter:
    """Atomic gzip JSONL writer for normalized evidence, with hard record/byte bounds."""

    def __init__(self, root: str | Path, *, max_records: int = 10000, max_uncompressed_bytes: int = 16 * 1024 * 1024):
        self.root = Path(root)
        if not self.root.is_absolute():
            raise MonitoringContractError("evidence root must be absolute")
        if not 1 <= max_records <= 100000:
            raise ValueError("max_records out of range")
        if not 4096 <= max_uncompressed_bytes <= 128 * 1024 * 1024:
            raise ValueError("max_uncompressed_bytes out of range")
        self.max_records = max_records
        self.max_uncompressed_bytes = max_uncompressed_bytes

    def write_events(self, *, partition_id: str, events: Iterable[CanonicalEvent]) -> EvidencePartitionReceipt:
        part = _compact(partition_id, "partition_id", max_len=160)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        final = self.root / f"{part}.jsonl.gz"
        temp = self.root / f".{part}.{os.getpid()}.tmp"
        count = 0
        raw_bytes = 0
        digest = hashlib.sha256()
        try:
            with gzip.open(temp, "wb", compresslevel=6) as handle:
                for event in events:
                    event.validate()
                    payload = asdict(event)
                    line = (json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
                    if count + 1 > self.max_records or raw_bytes + len(line) > self.max_uncompressed_bytes:
                        raise MonitoringContractError("evidence partition bound exceeded")
                    handle.write(line)
                    digest.update(line)
                    count += 1
                    raw_bytes += len(line)
            if count == 0:
                raise MonitoringContractError("evidence partition must not be empty")
            os.replace(temp, final)
        except Exception:
            temp.unlink(missing_ok=True)
            raise
        return EvidencePartitionReceipt(
            partition_ref="partition:" + part,
            record_count=count,
            uncompressed_bytes=raw_bytes,
            compressed_bytes=final.stat().st_size,
            sha256="sha256:" + digest.hexdigest(),
        )


_IP_RE = re.compile(r"(?<![A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9])")
_MAC_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")
_HEX_RE = re.compile(r"(?i)\b0x[0-9a-f]+\b|\b[0-9a-f]{12,}\b")
_NUM_RE = re.compile(r"(?<![A-Za-z])\b\d+\b")
_SPACE_RE = re.compile(r"\s+")


def deterministic_template(message: str, *, max_chars: int = 1024) -> str:
    """Cheap template normalization used before considering learned template miners."""
    text = str(message)[:max_chars]
    text = _IP_RE.sub("<IP>", text)
    text = _MAC_RE.sub("<MAC>", text)
    text = _HEX_RE.sub("<HEX>", text)
    text = _NUM_RE.sub("<N>", text)
    return _SPACE_RE.sub(" ", text).strip()


@dataclass(frozen=True)
class EventRule:
    rule_id: str
    source_type: str | None = None
    category: str | None = None
    min_severity: str | None = None

    def validate(self) -> "EventRule":
        object.__setattr__(self, "rule_id", _compact(self.rule_id, "rule_id", max_len=128))
        if self.source_type is not None:
            object.__setattr__(self, "source_type", _compact(self.source_type, "source_type", max_len=64))
        if self.category is not None:
            object.__setattr__(self, "category", _compact(self.category, "category", max_len=96))
        if self.min_severity not in {None, "info", "low", "medium", "high", "critical"}:
            raise MonitoringContractError("invalid min_severity")
        if self.source_type is None and self.category is None and self.min_severity is None:
            raise MonitoringContractError("rule must contain at least one predicate")
        return self


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class DeterministicEventRuleEngine:
    def __init__(self, rules: Iterable[EventRule]):
        validated = [rule.validate() for rule in rules]
        ids = [rule.rule_id for rule in validated]
        if len(ids) != len(set(ids)):
            raise MonitoringContractError("duplicate event rule_id")
        self.rules = tuple(validated)

    def match(self, event: CanonicalEvent) -> tuple[str, ...]:
        event.validate()
        matches: list[str] = []
        for rule in self.rules:
            if rule.source_type is not None and event.source_type != rule.source_type:
                continue
            if rule.category is not None and event.category != rule.category:
                continue
            if rule.min_severity is not None and _SEVERITY_RANK[event.severity] < _SEVERITY_RANK[rule.min_severity]:
                continue
            matches.append(rule.rule_id)
        return tuple(matches)


@dataclass(frozen=True)
class SourceFreshness:
    source_id: str
    expected_interval_seconds: int
    last_seen_at: str | None
    evaluated_at: str
    fresh: bool
    age_seconds: float | None
    reason_code: str | None


def evaluate_source_freshness(*, source_id: str, expected_interval_seconds: int, last_seen_at: str | None, evaluated_at: str) -> SourceFreshness:
    source = _compact(source_id, "source_id", max_len=128)
    if not 1 <= expected_interval_seconds <= 86400:
        raise ValueError("expected_interval_seconds must be within 1..86400")
    now = datetime.fromisoformat(evaluated_at.replace("Z", "+00:00"))
    if now.tzinfo is None:
        raise MonitoringContractError("evaluated_at must include timezone")
    if last_seen_at is None:
        return SourceFreshness(source, expected_interval_seconds, None, evaluated_at, False, None, "SOURCE_NEVER_SEEN")
    seen = datetime.fromisoformat(last_seen_at.replace("Z", "+00:00"))
    if seen.tzinfo is None:
        raise MonitoringContractError("last_seen_at must include timezone")
    age = (now - seen).total_seconds()
    if age < 0:
        return SourceFreshness(source, expected_interval_seconds, last_seen_at, evaluated_at, False, age, "SOURCE_TIMESTAMP_IN_FUTURE")
    fresh = age <= expected_interval_seconds * 2
    return SourceFreshness(source, expected_interval_seconds, last_seen_at, evaluated_at, fresh, age, None if fresh else "SOURCE_STALE")


@dataclass(frozen=True)
class RetentionResult:
    deleted: tuple[str, ...]
    remaining_candidates: int


class BoundedRetentionWorker:
    """Delete only explicitly matched evidence files older than cutoff, in bounded batches."""

    def __init__(self, root: str | Path, *, max_deletes_per_run: int = 64):
        self.root = Path(root)
        if not self.root.is_absolute():
            raise MonitoringContractError("retention root must be absolute")
        if not 1 <= max_deletes_per_run <= 1024:
            raise ValueError("max_deletes_per_run out of range")
        self.max_deletes_per_run = max_deletes_per_run

    def delete_older_than(self, *, cutoff_epoch: float) -> RetentionResult:
        if not self.root.exists():
            return RetentionResult((), 0)
        candidates = sorted(
            (
                path for path in self.root.glob("*.jsonl.gz")
                if path.is_file() and not path.is_symlink() and path.stat().st_mtime < cutoff_epoch
            ),
            key=lambda path: path.stat().st_mtime_ns,
        )
        selected = candidates[: self.max_deletes_per_run]
        deleted: list[str] = []
        for path in selected:
            path.unlink()
            deleted.append(path.name)
        return RetentionResult(tuple(deleted), max(0, len(candidates) - len(selected)))
