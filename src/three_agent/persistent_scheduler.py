from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .store import TaskStore

SCHEDULE_SCHEMA = "workspace-persistent-schedule/v1"
SCHEDULE_CLAIM_SCHEMA = "workspace-persistent-schedule-claim/v1"
SCHEDULE_EVENT_SCHEMA = "workspace-persistent-schedule-event/v1"

_MAX_SCHEDULE_ID = 128
_MAX_DUE_PER_TICK = 32
_MAX_INTERVAL_SECONDS = 366 * 24 * 60 * 60
_MIN_INTERVAL_SECONDS = 60
_MAX_CLAIM_LEASE_SECONDS = 24 * 60 * 60
_MAX_CRON_SEARCH_MINUTES = 370 * 24 * 60
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TERMINAL_CLAIM_STATUSES = frozenset({"SUCCEEDED", "FAILED", "CANCELLED"})
_UNRESOLVED_CLAIM_STATUSES = frozenset({"CLAIMED", "RECOVERY_REQUIRED"})


class PersistentSchedulerError(ValueError):
    """A persistent scheduler operation violates the fail-closed contract."""

    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code)
        super().__init__(self.reason_code)


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise PersistentSchedulerError("SCHEDULE_STATE_NOT_CANONICAL_JSON") from exc


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware_utc(value: datetime, *, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise PersistentSchedulerError(f"{field.upper()}_MUST_BE_TIMEZONE_AWARE")
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _aware_utc(value, field="timestamp").isoformat()


def _parse_iso(value: object, *, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise PersistentSchedulerError(f"INVALID_{field.upper()}") from exc
    return _aware_utc(parsed, field=field)


def _schedule_id(value: object) -> str:
    text = str(value or "").strip()
    if not _ID_RE.fullmatch(text) or len(text) > _MAX_SCHEDULE_ID:
        raise PersistentSchedulerError("SCHEDULE_ID_INVALID")
    return text


def _task_id(value: object) -> str:
    text = str(value or "").strip()
    if not _ID_RE.fullmatch(text):
        raise PersistentSchedulerError("SCHEDULE_TASK_ID_INVALID")
    return text


def _timezone(value: object) -> ZoneInfo:
    text = str(value or "").strip()
    if not text or len(text) > 128:
        raise PersistentSchedulerError("SCHEDULE_TIMEZONE_INVALID")
    try:
        return ZoneInfo(text)
    except ZoneInfoNotFoundError as exc:
        raise PersistentSchedulerError("SCHEDULE_TIMEZONE_INVALID") from exc


def _parse_cron_field(
    expression: str,
    *,
    minimum: int,
    maximum: int,
    sunday_alias: bool = False,
) -> frozenset[int]:
    text = str(expression or "").strip()
    if not text:
        raise PersistentSchedulerError("CRON_FIELD_EMPTY")
    values: set[int] = set()

    def normalize(number: int) -> int:
        if sunday_alias and number == 7:
            return 0
        if not minimum <= number <= maximum:
            raise PersistentSchedulerError("CRON_FIELD_OUT_OF_RANGE")
        return number

    for part in text.split(","):
        part = part.strip()
        if not part:
            raise PersistentSchedulerError("CRON_FIELD_INVALID")
        base, slash, step_text = part.partition("/")
        step = 1
        if slash:
            if not step_text.isdigit() or int(step_text) < 1:
                raise PersistentSchedulerError("CRON_STEP_INVALID")
            step = int(step_text)
            if step > (maximum - minimum + 1):
                raise PersistentSchedulerError("CRON_STEP_INVALID")

        if base == "*":
            raw_start, raw_end = minimum, maximum
        elif "-" in base:
            left, right = base.split("-", 1)
            if not left.isdigit() or not right.isdigit():
                raise PersistentSchedulerError("CRON_RANGE_INVALID")
            raw_start, raw_end = int(left), int(right)
            if raw_start > raw_end:
                raise PersistentSchedulerError("CRON_RANGE_INVALID")
            # Validate both endpoints before iteration. DOW alone accepts 7 as
            # the standard Sunday alias.
            normalize(raw_start)
            normalize(raw_end)
        else:
            if slash or not base.isdigit():
                raise PersistentSchedulerError("CRON_FIELD_INVALID")
            values.add(normalize(int(base)))
            continue

        for candidate in range(raw_start, raw_end + 1, step):
            values.add(normalize(candidate))

    if not values:
        raise PersistentSchedulerError("CRON_FIELD_EMPTY")
    return frozenset(values)


@dataclass(frozen=True)
class _CronMatcher:
    expression: str
    minutes: frozenset[int]
    hours: frozenset[int]
    days: frozenset[int]
    months: frozenset[int]
    weekdays: frozenset[int]
    day_any: bool
    weekday_any: bool

    @classmethod
    def parse(cls, expression: str) -> "_CronMatcher":
        canonical = " ".join(str(expression or "").strip().split())
        fields = canonical.split(" ") if canonical else []
        if len(fields) != 5:
            raise PersistentSchedulerError("CRON_EXPRESSION_REQUIRES_FIVE_FIELDS")
        minute, hour, day, month, weekday = fields
        return cls(
            expression=canonical,
            minutes=_parse_cron_field(minute, minimum=0, maximum=59),
            hours=_parse_cron_field(hour, minimum=0, maximum=23),
            days=_parse_cron_field(day, minimum=1, maximum=31),
            months=_parse_cron_field(month, minimum=1, maximum=12),
            weekdays=_parse_cron_field(
                weekday,
                minimum=0,
                maximum=6,
                sunday_alias=True,
            ),
            day_any=day == "*",
            weekday_any=weekday == "*",
        )

    def matches(self, local: datetime) -> bool:
        cron_weekday = (local.weekday() + 1) % 7  # Sunday=0, Monday=1.
        day_match = local.day in self.days
        weekday_match = cron_weekday in self.weekdays
        if self.day_any and self.weekday_any:
            calendar_day_match = True
        elif self.day_any:
            calendar_day_match = weekday_match
        elif self.weekday_any:
            calendar_day_match = day_match
        else:
            # Standard cron semantics: DOM and DOW are OR when both restricted.
            calendar_day_match = day_match or weekday_match
        return (
            local.minute in self.minutes
            and local.hour in self.hours
            and local.month in self.months
            and calendar_day_match
        )


def _next_cron(expression: str, tz_name: str, *, after: datetime) -> datetime:
    matcher = _CronMatcher.parse(expression)
    tz = _timezone(tz_name)
    cursor = _aware_utc(after, field="after").replace(second=0, microsecond=0) + timedelta(minutes=1)
    for _ in range(_MAX_CRON_SEARCH_MINUTES):
        if matcher.matches(cursor.astimezone(tz)):
            return cursor
        cursor += timedelta(minutes=1)
    raise PersistentSchedulerError("CRON_NEXT_RUN_OUTSIDE_SEARCH_HORIZON")


def _next_interval(interval_seconds: int, *, scheduled_for: datetime, now: datetime) -> datetime:
    scheduled = _aware_utc(scheduled_for, field="scheduled_for")
    current = _aware_utc(now, field="now")
    if scheduled > current:
        return scheduled
    elapsed = (current - scheduled).total_seconds()
    jumps = int(elapsed // interval_seconds) + 1
    return scheduled + timedelta(seconds=jumps * interval_seconds)


@dataclass(frozen=True)
class PersistentSchedule:
    schedule_id: str
    task_id: str
    kind: str
    schedule_value: str
    timezone_name: str
    contract_sha256: str
    next_run_at: str
    enabled: bool
    created_at: str
    updated_at: str
    last_error: str | None
    schema_version: str = SCHEDULE_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "schedule_id": self.schedule_id,
            "task_id": self.task_id,
            "kind": self.kind,
            "schedule_value": self.schedule_value,
            "timezone": self.timezone_name,
            "contract_sha256": self.contract_sha256,
            "next_run_at": self.next_run_at,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_error": self.last_error,
        }


@dataclass(frozen=True)
class ScheduleClaim:
    claim_id: str
    schedule_id: str
    task_id: str
    scheduled_for: str
    claimed_at: str
    lease_until: str
    contract_sha256: str
    status: str
    schema_version: str = SCHEDULE_CLAIM_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "claim_id": self.claim_id,
            "schedule_id": self.schedule_id,
            "task_id": self.task_id,
            "scheduled_for": self.scheduled_for,
            "claimed_at": self.claimed_at,
            "lease_until": self.lease_until,
            "contract_sha256": self.contract_sha256,
            "status": self.status,
        }


@dataclass(frozen=True)
class ScheduleEvent:
    sequence: int
    event_id: str
    prev_hash: str
    event_hash: str
    schedule_id: str
    action: str
    timestamp: str
    details: dict[str, Any]
    schema_version: str = SCHEDULE_EVENT_SCHEMA


class PersistentWallClockScheduler:
    """Persistent wall-clock admission layer over the canonical WorkSpace runtime.

    It never executes tools or widens capabilities. A claim only states that one
    pre-bound task occurrence is due; execution must still use the existing
    TaskContract/capability/budget/validator/ExecutionScheduler path.

    Missed occurrences are coalesced to one claim per schedule per tick and the
    next time is advanced beyond ``now``. Unresolved claims block later
    occurrences for the same schedule. Expired leases become
    ``RECOVERY_REQUIRED`` and are never automatically replayed.
    """

    def __init__(self, store: TaskStore):
        if not isinstance(store, TaskStore):
            raise PersistentSchedulerError("TASK_STORE_REQUIRED")
        self.store = store

    def initialize(self) -> None:
        self.store.initialize()
        with self.store.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scheduled_jobs (
                    schedule_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    schedule_value TEXT NOT NULL,
                    timezone_name TEXT NOT NULL,
                    contract_sha256 TEXT NOT NULL,
                    next_run_at TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_error TEXT,
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE INDEX IF NOT EXISTS idx_scheduled_jobs_due
                    ON scheduled_jobs(enabled, next_run_at, schedule_id);

                CREATE TABLE IF NOT EXISTS schedule_claims (
                    claim_id TEXT PRIMARY KEY,
                    schedule_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    scheduled_for TEXT NOT NULL,
                    claimed_at TEXT NOT NULL,
                    lease_until TEXT NOT NULL,
                    contract_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,
                    completed_at TEXT,
                    result_details TEXT NOT NULL DEFAULT '{}',
                    UNIQUE(schedule_id, scheduled_for),
                    FOREIGN KEY(schedule_id) REFERENCES scheduled_jobs(schedule_id),
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE INDEX IF NOT EXISTS idx_schedule_claims_status
                    ON schedule_claims(status, lease_until, claim_id);
                CREATE INDEX IF NOT EXISTS idx_schedule_claims_unresolved
                    ON schedule_claims(schedule_id, status, claim_id);

                CREATE TABLE IF NOT EXISTS schedule_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    schedule_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );
                """
            )

    @staticmethod
    def _contract_digest(conn: sqlite3.Connection, task_id: str) -> str:
        row = conn.execute(
            "SELECT contract_sha256 FROM task_contracts WHERE task_id=?",
            (task_id,),
        ).fetchone()
        if row is None:
            raise PersistentSchedulerError("SCHEDULE_TASK_CONTRACT_REQUIRED")
        digest = str(row["contract_sha256"] or "")
        if not _SHA256_RE.fullmatch(digest):
            raise PersistentSchedulerError("SCHEDULE_TASK_CONTRACT_DIGEST_INVALID")
        return digest

    @staticmethod
    def _task_exists(conn: sqlite3.Connection, task_id: str) -> None:
        if conn.execute("SELECT 1 FROM tasks WHERE task_id=?", (task_id,)).fetchone() is None:
            raise PersistentSchedulerError("SCHEDULE_TASK_NOT_FOUND")

    def _append_event(
        self,
        conn: sqlite3.Connection,
        *,
        schedule_id: str,
        action: str,
        timestamp: datetime,
        details: dict[str, Any],
    ) -> ScheduleEvent:
        last = conn.execute(
            "SELECT event_hash FROM schedule_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        prev_hash = str(last["event_hash"]) if last else "GENESIS"
        timestamp_text = _iso(timestamp)
        body = {
            "schedule_id": schedule_id,
            "action": action,
            "timestamp": timestamp_text,
            "details": details,
            "prev_hash": prev_hash,
        }
        event_hash = _digest(body)
        event_id = "sev_" + event_hash.split(":", 1)[1][:32]
        cursor = conn.execute(
            """
            INSERT INTO schedule_events(
                event_id,prev_hash,event_hash,schedule_id,action,timestamp,details_json
            ) VALUES(?,?,?,?,?,?,?)
            """,
            (
                event_id,
                prev_hash,
                event_hash,
                schedule_id,
                action,
                timestamp_text,
                _canonical_json(details),
            ),
        )
        return ScheduleEvent(
            sequence=int(cursor.lastrowid),
            event_id=event_id,
            prev_hash=prev_hash,
            event_hash=event_hash,
            schedule_id=schedule_id,
            action=action,
            timestamp=timestamp_text,
            details=details,
        )

    def register_interval(
        self,
        schedule_id: str,
        task_id: str,
        interval_seconds: int,
        *,
        start_at: datetime | None = None,
        now: datetime | None = None,
    ) -> PersistentSchedule:
        schedule_id = _schedule_id(schedule_id)
        task_id = _task_id(task_id)
        if (
            isinstance(interval_seconds, bool)
            or not isinstance(interval_seconds, int)
            or not _MIN_INTERVAL_SECONDS <= interval_seconds <= _MAX_INTERVAL_SECONDS
        ):
            raise PersistentSchedulerError("SCHEDULE_INTERVAL_INVALID")
        current = _aware_utc(now or _utc_now(), field="now")
        next_run = (
            _aware_utc(start_at, field="start_at")
            if start_at is not None
            else current + timedelta(seconds=interval_seconds)
        )
        if next_run < current:
            next_run = _next_interval(interval_seconds, scheduled_for=next_run, now=current)
        return self._register(
            schedule_id=schedule_id,
            task_id=task_id,
            kind="interval",
            schedule_value=str(interval_seconds),
            timezone_name="UTC",
            next_run_at=next_run,
            now=current,
        )

    def register_cron(
        self,
        schedule_id: str,
        task_id: str,
        expression: str,
        *,
        timezone_name: str = "UTC",
        now: datetime | None = None,
    ) -> PersistentSchedule:
        schedule_id = _schedule_id(schedule_id)
        task_id = _task_id(task_id)
        matcher = _CronMatcher.parse(expression)
        tz = _timezone(timezone_name)
        current = _aware_utc(now or _utc_now(), field="now")
        return self._register(
            schedule_id=schedule_id,
            task_id=task_id,
            kind="cron",
            schedule_value=matcher.expression,
            timezone_name=tz.key,
            next_run_at=_next_cron(matcher.expression, tz.key, after=current),
            now=current,
        )

    def _register(
        self,
        *,
        schedule_id: str,
        task_id: str,
        kind: str,
        schedule_value: str,
        timezone_name: str,
        next_run_at: datetime,
        now: datetime,
    ) -> PersistentSchedule:
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._task_exists(conn, task_id)
            contract_sha256 = self._contract_digest(conn, task_id)
            if conn.execute(
                "SELECT 1 FROM scheduled_jobs WHERE schedule_id=?",
                (schedule_id,),
            ).fetchone():
                raise PersistentSchedulerError("SCHEDULE_ALREADY_EXISTS")
            timestamp = _iso(now)
            conn.execute(
                """
                INSERT INTO scheduled_jobs(
                    schedule_id,task_id,kind,schedule_value,timezone_name,
                    contract_sha256,next_run_at,enabled,created_at,updated_at,last_error
                ) VALUES(?,?,?,?,?,?,?,?,?,?,NULL)
                """,
                (
                    schedule_id,
                    task_id,
                    kind,
                    schedule_value,
                    timezone_name,
                    contract_sha256,
                    _iso(next_run_at),
                    1,
                    timestamp,
                    timestamp,
                ),
            )
            self._append_event(
                conn,
                schedule_id=schedule_id,
                action="REGISTER",
                timestamp=now,
                details={
                    "task_id": task_id,
                    "kind": kind,
                    "schedule_value": schedule_value,
                    "timezone": timezone_name,
                    "contract_sha256": contract_sha256,
                    "next_run_at": _iso(next_run_at),
                },
            )
        return self.get(schedule_id)

    def get(self, schedule_id: str) -> PersistentSchedule:
        schedule_id = _schedule_id(schedule_id)
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM scheduled_jobs WHERE schedule_id=?",
                (schedule_id,),
            ).fetchone()
        if row is None:
            raise KeyError(schedule_id)
        return self._row_to_schedule(row)

    def list_schedules(self, *, enabled_only: bool = False) -> tuple[PersistentSchedule, ...]:
        with self.store.connect() as conn:
            sql = "SELECT * FROM scheduled_jobs"
            if enabled_only:
                sql += " WHERE enabled=1"
            sql += " ORDER BY schedule_id"
            rows = conn.execute(sql).fetchall()
        return tuple(self._row_to_schedule(row) for row in rows)

    def disable(self, schedule_id: str, *, now: datetime | None = None) -> PersistentSchedule:
        schedule_id = _schedule_id(schedule_id)
        current = _aware_utc(now or _utc_now(), field="now")
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                "UPDATE scheduled_jobs SET enabled=0,updated_at=? WHERE schedule_id=?",
                (_iso(current), schedule_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(schedule_id)
            self._append_event(
                conn,
                schedule_id=schedule_id,
                action="DISABLE",
                timestamp=current,
                details={},
            )
        return self.get(schedule_id)

    def enable(self, schedule_id: str, *, now: datetime | None = None) -> PersistentSchedule:
        schedule_id = _schedule_id(schedule_id)
        current = _aware_utc(now or _utc_now(), field="now")
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM scheduled_jobs WHERE schedule_id=?",
                (schedule_id,),
            ).fetchone()
            if row is None:
                raise KeyError(schedule_id)
            current_contract = self._contract_digest(conn, str(row["task_id"]))
            if current_contract != str(row["contract_sha256"]):
                raise PersistentSchedulerError("SCHEDULE_TASK_CONTRACT_CHANGED")
            next_run = self._next_after_row(row, current)
            conn.execute(
                """
                UPDATE scheduled_jobs
                SET enabled=1,next_run_at=?,updated_at=?,last_error=NULL
                WHERE schedule_id=?
                """,
                (_iso(next_run), _iso(current), schedule_id),
            )
            self._append_event(
                conn,
                schedule_id=schedule_id,
                action="ENABLE",
                timestamp=current,
                details={"next_run_at": _iso(next_run)},
            )
        return self.get(schedule_id)

    @staticmethod
    def _next_after_row(row: sqlite3.Row, now: datetime) -> datetime:
        kind = str(row["kind"])
        scheduled_for = _parse_iso(row["next_run_at"], field="next_run_at")
        if kind == "interval":
            try:
                interval = int(str(row["schedule_value"]))
            except ValueError as exc:
                raise PersistentSchedulerError("SCHEDULE_INTERVAL_CORRUPT") from exc
            if not _MIN_INTERVAL_SECONDS <= interval <= _MAX_INTERVAL_SECONDS:
                raise PersistentSchedulerError("SCHEDULE_INTERVAL_CORRUPT")
            return _next_interval(interval, scheduled_for=scheduled_for, now=now)
        if kind == "cron":
            return _next_cron(
                str(row["schedule_value"]),
                str(row["timezone_name"]),
                after=now,
            )
        raise PersistentSchedulerError("SCHEDULE_KIND_CORRUPT")

    @staticmethod
    def _has_unresolved_claim(conn: sqlite3.Connection, schedule_id: str) -> bool:
        placeholders = ",".join("?" for _ in _UNRESOLVED_CLAIM_STATUSES)
        params: tuple[object, ...] = (schedule_id, *tuple(sorted(_UNRESOLVED_CLAIM_STATUSES)))
        row = conn.execute(
            f"SELECT 1 FROM schedule_claims WHERE schedule_id=? AND status IN ({placeholders}) LIMIT 1",
            params,
        ).fetchone()
        return row is not None

    def claim_due(
        self,
        *,
        now: datetime | None = None,
        limit: int = 8,
        lease_seconds: int = 300,
    ) -> tuple[ScheduleClaim, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_DUE_PER_TICK:
            raise PersistentSchedulerError("SCHEDULE_DUE_LIMIT_INVALID")
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, int)
            or not 1 <= lease_seconds <= _MAX_CLAIM_LEASE_SECONDS
        ):
            raise PersistentSchedulerError("SCHEDULE_LEASE_INVALID")
        current = _aware_utc(now or _utc_now(), field="now")
        current_text = _iso(current)
        claims: list[ScheduleClaim] = []
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                """
                SELECT * FROM scheduled_jobs
                WHERE enabled=1 AND next_run_at<=?
                ORDER BY next_run_at,schedule_id
                LIMIT ?
                """,
                (current_text, _MAX_DUE_PER_TICK),
            ).fetchall()
            for row in rows:
                if len(claims) >= limit:
                    break
                schedule_id = str(row["schedule_id"])
                task_id = str(row["task_id"])

                # Never overlap occurrences while the previous execution outcome
                # is unresolved. This is checked inside the same IMMEDIATE
                # transaction that creates a claim.
                if self._has_unresolved_claim(conn, schedule_id):
                    continue

                try:
                    current_contract = self._contract_digest(conn, task_id)
                except PersistentSchedulerError as exc:
                    conn.execute(
                        """
                        UPDATE scheduled_jobs
                        SET enabled=0,updated_at=?,last_error=?
                        WHERE schedule_id=?
                        """,
                        (current_text, exc.reason_code, schedule_id),
                    )
                    self._append_event(
                        conn,
                        schedule_id=schedule_id,
                        action="AUTO_DISABLE",
                        timestamp=current,
                        details={"reason_code": exc.reason_code},
                    )
                    continue
                if current_contract != str(row["contract_sha256"]):
                    reason = "SCHEDULE_TASK_CONTRACT_CHANGED"
                    conn.execute(
                        """
                        UPDATE scheduled_jobs
                        SET enabled=0,updated_at=?,last_error=?
                        WHERE schedule_id=?
                        """,
                        (current_text, reason, schedule_id),
                    )
                    self._append_event(
                        conn,
                        schedule_id=schedule_id,
                        action="AUTO_DISABLE",
                        timestamp=current,
                        details={"reason_code": reason},
                    )
                    continue

                scheduled_for = _parse_iso(row["next_run_at"], field="next_run_at")
                next_run = self._next_after_row(row, current)
                identity = {
                    "schedule_id": schedule_id,
                    "task_id": task_id,
                    "scheduled_for": _iso(scheduled_for),
                    "contract_sha256": current_contract,
                }
                claim_id = "scl_" + _digest(identity).split(":", 1)[1][:32]
                lease_until = current + timedelta(seconds=lease_seconds)
                try:
                    conn.execute(
                        """
                        INSERT INTO schedule_claims(
                            claim_id,schedule_id,task_id,scheduled_for,claimed_at,
                            lease_until,contract_sha256,status
                        ) VALUES(?,?,?,?,?,?,?,?)
                        """,
                        (
                            claim_id,
                            schedule_id,
                            task_id,
                            _iso(scheduled_for),
                            current_text,
                            _iso(lease_until),
                            current_contract,
                            "CLAIMED",
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise PersistentSchedulerError("SCHEDULE_OCCURRENCE_ALREADY_CLAIMED") from exc
                conn.execute(
                    """
                    UPDATE scheduled_jobs
                    SET next_run_at=?,updated_at=?,last_error=NULL
                    WHERE schedule_id=?
                    """,
                    (_iso(next_run), current_text, schedule_id),
                )
                self._append_event(
                    conn,
                    schedule_id=schedule_id,
                    action="CLAIM",
                    timestamp=current,
                    details={
                        "claim_id": claim_id,
                        "scheduled_for": _iso(scheduled_for),
                        "lease_until": _iso(lease_until),
                        "next_run_at": _iso(next_run),
                        "contract_sha256": current_contract,
                    },
                )
                claims.append(
                    ScheduleClaim(
                        claim_id=claim_id,
                        schedule_id=schedule_id,
                        task_id=task_id,
                        scheduled_for=_iso(scheduled_for),
                        claimed_at=current_text,
                        lease_until=_iso(lease_until),
                        contract_sha256=current_contract,
                        status="CLAIMED",
                    )
                )
        return tuple(claims)

    def mark_expired_claims_recovery_required(
        self,
        *,
        now: datetime | None = None,
        limit: int = 32,
    ) -> tuple[ScheduleClaim, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 128:
            raise PersistentSchedulerError("SCHEDULE_RECOVERY_LIMIT_INVALID")
        current = _aware_utc(now or _utc_now(), field="now")
        current_text = _iso(current)
        recovered: list[ScheduleClaim] = []
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                """
                SELECT * FROM schedule_claims
                WHERE status='CLAIMED' AND lease_until<=?
                ORDER BY lease_until,claim_id
                LIMIT ?
                """,
                (current_text, limit),
            ).fetchall()
            for row in rows:
                conn.execute(
                    "UPDATE schedule_claims SET status='RECOVERY_REQUIRED' WHERE claim_id=?",
                    (str(row["claim_id"]),),
                )
                self._append_event(
                    conn,
                    schedule_id=str(row["schedule_id"]),
                    action="RECOVERY_REQUIRED",
                    timestamp=current,
                    details={"claim_id": str(row["claim_id"])},
                )
                recovered.append(self._row_to_claim(row, status_override="RECOVERY_REQUIRED"))
        return tuple(recovered)

    def complete_claim(
        self,
        claim_id: str,
        status: str,
        *,
        details: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> ScheduleClaim:
        claim_id = str(claim_id or "").strip()
        if not _ID_RE.fullmatch(claim_id):
            raise PersistentSchedulerError("SCHEDULE_CLAIM_ID_INVALID")
        status = str(status or "").strip().upper()
        if status not in _TERMINAL_CLAIM_STATUSES:
            raise PersistentSchedulerError("SCHEDULE_CLAIM_TERMINAL_STATUS_INVALID")
        result_details = details or {}
        _canonical_json(result_details)
        current = _aware_utc(now or _utc_now(), field="now")
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM schedule_claims WHERE claim_id=?",
                (claim_id,),
            ).fetchone()
            if row is None:
                raise KeyError(claim_id)
            current_status = str(row["status"])
            if current_status in _TERMINAL_CLAIM_STATUSES:
                if current_status != status:
                    raise PersistentSchedulerError("SCHEDULE_CLAIM_ALREADY_TERMINAL")
                return self._row_to_claim(row)
            if current_status not in _UNRESOLVED_CLAIM_STATUSES:
                raise PersistentSchedulerError("SCHEDULE_CLAIM_STATE_INVALID")
            conn.execute(
                """
                UPDATE schedule_claims
                SET status=?,completed_at=?,result_details=?
                WHERE claim_id=?
                """,
                (status, _iso(current), _canonical_json(result_details), claim_id),
            )
            self._append_event(
                conn,
                schedule_id=str(row["schedule_id"]),
                action="COMPLETE",
                timestamp=current,
                details={"claim_id": claim_id, "status": status, "result": result_details},
            )
            row = conn.execute(
                "SELECT * FROM schedule_claims WHERE claim_id=?",
                (claim_id,),
            ).fetchone()
        if row is None:
            raise PersistentSchedulerError("SCHEDULE_CLAIM_DISAPPEARED")
        return self._row_to_claim(row)

    def list_claims(
        self,
        *,
        statuses: Iterable[str] | None = None,
        limit: int = 100,
    ) -> tuple[ScheduleClaim, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise PersistentSchedulerError("SCHEDULE_CLAIM_LIST_LIMIT_INVALID")
        params: list[object] = []
        sql = "SELECT * FROM schedule_claims"
        if statuses is not None:
            normalized = tuple(sorted({str(value).strip().upper() for value in statuses}))
            allowed = _UNRESOLVED_CLAIM_STATUSES | _TERMINAL_CLAIM_STATUSES
            if not normalized or any(value not in allowed for value in normalized):
                raise PersistentSchedulerError("SCHEDULE_CLAIM_STATUS_FILTER_INVALID")
            placeholders = ",".join("?" for _ in normalized)
            sql += f" WHERE status IN ({placeholders})"
            params.extend(normalized)
        sql += " ORDER BY claimed_at DESC,claim_id LIMIT ?"
        params.append(limit)
        with self.store.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return tuple(self._row_to_claim(row) for row in rows)

    def verify_event_chain(self) -> bool:
        with self.store.connect() as conn:
            rows = conn.execute("SELECT * FROM schedule_events ORDER BY sequence").fetchall()
        previous = "GENESIS"
        for row in rows:
            details = json.loads(str(row["details_json"]))
            body = {
                "schedule_id": str(row["schedule_id"]),
                "action": str(row["action"]),
                "timestamp": str(row["timestamp"]),
                "details": details,
                "prev_hash": str(row["prev_hash"]),
            }
            expected = _digest(body)
            if str(row["prev_hash"]) != previous:
                return False
            if str(row["event_hash"]) != expected:
                return False
            if str(row["event_id"]) != "sev_" + expected.split(":", 1)[1][:32]:
                return False
            previous = expected
        return True

    @staticmethod
    def _row_to_schedule(row: sqlite3.Row) -> PersistentSchedule:
        return PersistentSchedule(
            schedule_id=str(row["schedule_id"]),
            task_id=str(row["task_id"]),
            kind=str(row["kind"]),
            schedule_value=str(row["schedule_value"]),
            timezone_name=str(row["timezone_name"]),
            contract_sha256=str(row["contract_sha256"]),
            next_run_at=str(row["next_run_at"]),
            enabled=bool(row["enabled"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            last_error=str(row["last_error"]) if row["last_error"] else None,
        )

    @staticmethod
    def _row_to_claim(row: sqlite3.Row, *, status_override: str | None = None) -> ScheduleClaim:
        return ScheduleClaim(
            claim_id=str(row["claim_id"]),
            schedule_id=str(row["schedule_id"]),
            task_id=str(row["task_id"]),
            scheduled_for=str(row["scheduled_for"]),
            claimed_at=str(row["claimed_at"]),
            lease_until=str(row["lease_until"]),
            contract_sha256=str(row["contract_sha256"]),
            status=status_override or str(row["status"]),
        )
