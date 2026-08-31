from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from .storage import MonitoringStore


HOURLY_LOCK_STALE_AFTER_SECONDS = 20 * 60


class MonitoringRunAlreadyLocked(RuntimeError):
    pass


@dataclass(frozen=True)
class HourlyRunLock:
    slot_key: str
    owner_id: str
    acquired_at: str


class HourlyRunLockManager:
    def __init__(self, store: MonitoringStore):
        self.store = store

    def initialize(self) -> None:
        with self.store.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS hourly_locks(
                    slot_key TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    acquired_at TEXT NOT NULL
                )
                """
            )

    @staticmethod
    def _age_seconds(*, acquired_at: str, now: str) -> float | None:
        try:
            acquired = datetime.fromisoformat(str(acquired_at).replace("Z", "+00:00"))
            current = datetime.fromisoformat(str(now).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
        if acquired.tzinfo is None or current.tzinfo is None:
            return None
        return (current - acquired).total_seconds()

    def acquire(self, *, slot_key: str, owner_id: str, acquired_at: str) -> HourlyRunLock:
        self.initialize()
        try:
            with self.store.connect() as conn:
                # Serialize stale-lock inspection/replacement so two restart attempts
                # cannot both reclaim the same slot.
                conn.execute("BEGIN IMMEDIATE")
                existing = conn.execute(
                    "SELECT owner_id,acquired_at FROM hourly_locks WHERE slot_key=?",
                    (slot_key,),
                ).fetchone()
                if existing is not None:
                    age = self._age_seconds(
                        acquired_at=str(existing["acquired_at"]),
                        now=acquired_at,
                    )
                    if age is None or age <= HOURLY_LOCK_STALE_AFTER_SECONDS:
                        raise MonitoringRunAlreadyLocked("HOURLY_SLOT_ALREADY_LOCKED")
                    conn.execute(
                        "DELETE FROM hourly_locks WHERE slot_key=? AND owner_id=? AND acquired_at=?",
                        (slot_key, existing["owner_id"], existing["acquired_at"]),
                    )
                conn.execute(
                    "INSERT INTO hourly_locks(slot_key,owner_id,acquired_at) VALUES(?,?,?)",
                    (slot_key, owner_id, acquired_at),
                )
        except sqlite3.IntegrityError as exc:
            raise MonitoringRunAlreadyLocked("HOURLY_SLOT_ALREADY_LOCKED") from exc
        return HourlyRunLock(slot_key, owner_id, acquired_at)

    def release(self, lock: HourlyRunLock) -> bool:
        with self.store.connect() as conn:
            cursor = conn.execute(
                "DELETE FROM hourly_locks WHERE slot_key=? AND owner_id=?",
                (lock.slot_key, lock.owner_id),
            )
            return cursor.rowcount == 1

    def is_locked(self, slot_key: str) -> bool:
        self.initialize()
        with self.store.connect() as conn:
            return conn.execute(
                "SELECT 1 FROM hourly_locks WHERE slot_key=?",
                (slot_key,),
            ).fetchone() is not None
