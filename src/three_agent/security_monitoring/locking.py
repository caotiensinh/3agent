from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from .storage import MonitoringStore


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

    def acquire(self, *, slot_key: str, owner_id: str, acquired_at: str) -> HourlyRunLock:
        self.initialize()
        try:
            with self.store.connect() as conn:
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
