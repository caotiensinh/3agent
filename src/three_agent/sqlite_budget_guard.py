from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, TypeVar

from .store import TaskStore

_T = TypeVar("_T")

# SQLite already waits for a bounded interval before raising a lock error.  These
# retries are deliberately few so cross-process contention cannot stall a task
# indefinitely, while transient writers still get a second chance.
SQLITE_BUDGET_LOCK_RETRY_ATTEMPTS = 2
SQLITE_BUDGET_LOCK_RETRY_DELAY_SECONDS = 0.05

_LOCK_REGISTRY_GUARD = threading.Lock()
_LOCK_REGISTRY: dict[str, threading.RLock] = {}


def _database_key(store: TaskStore) -> str:
    return str(Path(store.db_path).expanduser().resolve(strict=False))


def _database_lock(store: TaskStore) -> threading.RLock:
    key = _database_key(store)
    with _LOCK_REGISTRY_GUARD:
        lock = _LOCK_REGISTRY.get(key)
        if lock is None:
            lock = threading.RLock()
            _LOCK_REGISTRY[key] = lock
        return lock


@contextmanager
def budget_write_guard(store: TaskStore) -> Iterator[None]:
    """Serialize only execution-budget write transactions for one SQLite DB.

    The lock is shared by distinct ``TaskStore`` instances that point at the
    same database.  Model execution and the rest of Workflow V4 remain fully
    parallel; only the short budget bind/reserve transactions are serialized.
    """

    lock = _database_lock(store)
    with lock:
        yield


def run_budget_write(
    store: TaskStore,
    operation: Callable[[], _T],
    *,
    attempts: int = SQLITE_BUDGET_LOCK_RETRY_ATTEMPTS,
    retry_delay_seconds: float = SQLITE_BUDGET_LOCK_RETRY_DELAY_SECONDS,
) -> _T:
    """Run one budget write under a shared lock with bounded SQLite retry.

    ``database is locked``/``database is busy`` may still come from a different
    process, which the process-local lock cannot serialize.  Retry is therefore
    bounded and only applies to those SQLite contention errors.  All other
    exceptions preserve their original semantics.
    """

    if attempts < 1:
        raise ValueError("attempts must be >= 1")
    if retry_delay_seconds < 0:
        raise ValueError("retry_delay_seconds must be >= 0")

    with budget_write_guard(store):
        for attempt in range(attempts):
            try:
                return operation()
            except sqlite3.OperationalError as exc:
                message = str(exc).lower()
                locked = "database is locked" in message or "database is busy" in message
                if not locked or attempt + 1 >= attempts:
                    raise
                if retry_delay_seconds:
                    time.sleep(retry_delay_seconds * (attempt + 1))

    raise AssertionError("unreachable")
