from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .store import TaskStore

RUNTIME_WRITER_LEASE_SCHEMA = "workspace-runtime-writer-lease/v1"
ZERO_HASH = "sha256:" + "0" * 64
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_STATUSES = frozenset({"ACTIVE", "RELEASED"})


class RuntimeWriterLeaseError(RuntimeError):
    """Writer ownership state is missing, malformed, stale, or tampered."""


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise RuntimeWriterLeaseError("WRITER_LEASE_NOT_CANONICAL_JSON") from exc


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _compact_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not _ID_RE.fullmatch(value):
        raise RuntimeWriterLeaseError(f"INVALID_{field.upper()}")
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise RuntimeWriterLeaseError(f"INVALID_{field.upper()}")
    return value


def _timestamp(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise RuntimeWriterLeaseError(f"INVALID_{field.upper()}")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise RuntimeWriterLeaseError(f"INVALID_{field.upper()}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RuntimeWriterLeaseError(f"{field.upper()}_MUST_BE_TIMEZONE_AWARE")
    canonical = parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if canonical != value:
        raise RuntimeWriterLeaseError(f"{field.upper()}_MUST_BE_NORMALIZED_UTC")
    return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class RuntimeWriterLease:
    """Immutable proof that one run owns writes for one task/plan generation.

    A newer claim increments ``generation``. Any older lease becomes stale even if
    its worker is still alive. Persistence layers must validate the lease inside
    the same transaction that performs the protected write.
    """

    task_id: str
    plan_fingerprint: str
    run_id: str
    generation: int
    issued_at: str
    status: str = "ACTIVE"
    released_at: str | None = None
    schema_version: str = RUNTIME_WRITER_LEASE_SCHEMA

    def validate(self) -> "RuntimeWriterLease":
        if self.schema_version != RUNTIME_WRITER_LEASE_SCHEMA:
            raise RuntimeWriterLeaseError("WRITER_LEASE_SCHEMA_VERSION_MISMATCH")
        _compact_id(self.task_id, "task_id")
        _sha256(self.plan_fingerprint, "plan_fingerprint")
        _compact_id(self.run_id, "run_id")
        if isinstance(self.generation, bool) or not isinstance(self.generation, int):
            raise RuntimeWriterLeaseError("INVALID_WRITER_GENERATION")
        if self.generation < 1:
            raise RuntimeWriterLeaseError("INVALID_WRITER_GENERATION")
        if self.status not in _STATUSES:
            raise RuntimeWriterLeaseError("INVALID_WRITER_LEASE_STATUS")
        _timestamp(self.issued_at, "issued_at")
        if self.status == "ACTIVE":
            if self.released_at is not None:
                raise RuntimeWriterLeaseError("ACTIVE_WRITER_LEASE_HAS_RELEASE_TIME")
        else:
            if self.released_at is None:
                raise RuntimeWriterLeaseError("RELEASED_WRITER_LEASE_MISSING_RELEASE_TIME")
            released_at = _timestamp(self.released_at, "released_at")
            issued = datetime.fromisoformat(self.issued_at.replace("Z", "+00:00"))
            released = datetime.fromisoformat(released_at.replace("Z", "+00:00"))
            if released < issued:
                raise RuntimeWriterLeaseError("WRITER_LEASE_RELEASE_PRECEDES_ISSUE")
        return self

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "plan_fingerprint": self.plan_fingerprint,
            "run_id": self.run_id,
            "generation": self.generation,
            "issued_at": self.issued_at,
            "status": self.status,
            "released_at": self.released_at,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())


class RuntimeWriterLeaseRepository:
    """Durable, fail-closed writer-generation authority stored in TaskStore.

    This component does not schedule runs and does not authorize capabilities. It
    only answers one question: *is this exact run generation still the current
    writer for this task/plan?*

    ``require_current_in_transaction`` is the enforcement primitive. Callers that
    protect a dispatch, observation, transcript, artifact, or state write must
    invoke it after opening their write transaction and before mutating state.
    """

    def __init__(self, task_store: TaskStore):
        if not isinstance(task_store, TaskStore):
            raise TypeError("task_store must be TaskStore")
        self.task_store = task_store

    def initialize(self) -> None:
        with self.task_store.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS runtime_writer_leases (
                    task_id TEXT NOT NULL,
                    plan_fingerprint TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    lease_json TEXT NOT NULL,
                    lease_sha256 TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(task_id, plan_fingerprint),
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE INDEX IF NOT EXISTS idx_runtime_writer_leases_run
                    ON runtime_writer_leases(run_id, generation);

                CREATE TABLE IF NOT EXISTS runtime_writer_lease_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    plan_fingerprint TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE INDEX IF NOT EXISTS idx_runtime_writer_lease_events_scope
                    ON runtime_writer_lease_events(task_id, plan_fingerprint, sequence);
                """
            )

    @staticmethod
    def _require_task(conn, task_id: str) -> None:
        if conn.execute(
            "SELECT 1 FROM tasks WHERE task_id = ? LIMIT 1",
            (task_id,),
        ).fetchone() is None:
            raise RuntimeWriterLeaseError("WRITER_LEASE_TASK_NOT_FOUND")

    @staticmethod
    def _lease_from_row(row) -> RuntimeWriterLease:
        raw_json = str(row["lease_json"])
        stored_sha256 = str(row["lease_sha256"])
        try:
            payload = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            raise RuntimeWriterLeaseError("WRITER_LEASE_JSON_INVALID") from exc
        if not isinstance(payload, dict):
            raise RuntimeWriterLeaseError("WRITER_LEASE_RECORD_NOT_OBJECT")
        if _canonical_json(payload) != raw_json:
            raise RuntimeWriterLeaseError("WRITER_LEASE_RECORD_NOT_CANONICAL")
        if _digest(payload) != stored_sha256:
            raise RuntimeWriterLeaseError("WRITER_LEASE_DIGEST_MISMATCH")
        expected_keys = {
            "schema_version",
            "task_id",
            "plan_fingerprint",
            "run_id",
            "generation",
            "issued_at",
            "status",
            "released_at",
        }
        if set(payload) != expected_keys:
            raise RuntimeWriterLeaseError("WRITER_LEASE_RECORD_SHAPE_INVALID")
        try:
            lease = RuntimeWriterLease(
                task_id=payload["task_id"],
                plan_fingerprint=payload["plan_fingerprint"],
                run_id=payload["run_id"],
                generation=payload["generation"],
                issued_at=payload["issued_at"],
                status=payload["status"],
                released_at=payload["released_at"],
                schema_version=payload["schema_version"],
            ).validate()
        except (KeyError, TypeError, RuntimeWriterLeaseError) as exc:
            if isinstance(exc, RuntimeWriterLeaseError):
                raise
            raise RuntimeWriterLeaseError("WRITER_LEASE_RECORD_SHAPE_INVALID") from exc
        if lease.fingerprint != stored_sha256:
            raise RuntimeWriterLeaseError("WRITER_LEASE_FINGERPRINT_MISMATCH")
        if (
            str(row["task_id"]) != lease.task_id
            or str(row["plan_fingerprint"]) != lease.plan_fingerprint
            or str(row["run_id"]) != lease.run_id
            or int(row["generation"]) != lease.generation
            or str(row["status"]) != lease.status
        ):
            raise RuntimeWriterLeaseError("WRITER_LEASE_INDEX_MISMATCH")
        return lease

    @staticmethod
    def _event_hash(
        *,
        task_id: str,
        plan_fingerprint: str,
        event_type: str,
        run_id: str,
        generation: int,
        payload_json: str,
        payload_sha256: str,
        previous_hash: str,
        recorded_at: str,
    ) -> str:
        return _digest(
            {
                "task_id": task_id,
                "plan_fingerprint": plan_fingerprint,
                "event_type": event_type,
                "run_id": run_id,
                "generation": generation,
                "payload_json": payload_json,
                "payload_sha256": payload_sha256,
                "previous_hash": previous_hash,
                "recorded_at": recorded_at,
            }
        )

    def _append_event(
        self,
        conn,
        *,
        lease: RuntimeWriterLease,
        event_type: str,
        recorded_at: str,
    ) -> None:
        payload = {
            "lease_fingerprint": lease.fingerprint,
            "status": lease.status,
        }
        payload_json = _canonical_json(payload)
        payload_sha256 = _digest(payload)
        row = conn.execute(
            """
            SELECT event_hash
            FROM runtime_writer_lease_events
            WHERE task_id = ? AND plan_fingerprint = ?
            ORDER BY sequence DESC
            LIMIT 1
            """,
            (lease.task_id, lease.plan_fingerprint),
        ).fetchone()
        previous_hash = str(row["event_hash"]) if row else ZERO_HASH
        event_hash = self._event_hash(
            task_id=lease.task_id,
            plan_fingerprint=lease.plan_fingerprint,
            event_type=event_type,
            run_id=lease.run_id,
            generation=lease.generation,
            payload_json=payload_json,
            payload_sha256=payload_sha256,
            previous_hash=previous_hash,
            recorded_at=recorded_at,
        )
        conn.execute(
            """
            INSERT INTO runtime_writer_lease_events(
                task_id, plan_fingerprint, event_type, run_id, generation,
                payload_json, payload_sha256, previous_hash, event_hash, recorded_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (
                lease.task_id,
                lease.plan_fingerprint,
                event_type,
                lease.run_id,
                lease.generation,
                payload_json,
                payload_sha256,
                previous_hash,
                event_hash,
                recorded_at,
            ),
        )

    def claim(
        self,
        *,
        task_id: str,
        plan_fingerprint: str,
        run_id: str,
        issued_at: str | None = None,
    ) -> RuntimeWriterLease:
        task = _compact_id(task_id, "task_id")
        plan = _sha256(plan_fingerprint, "plan_fingerprint")
        run = _compact_id(run_id, "run_id")
        timestamp = _timestamp(issued_at, "issued_at") if issued_at is not None else _utc_now()

        with self.task_store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._require_task(conn, task)
            row = conn.execute(
                """
                SELECT * FROM runtime_writer_leases
                WHERE task_id = ? AND plan_fingerprint = ?
                """,
                (task, plan),
            ).fetchone()
            if row is not None:
                current = self._lease_from_row(row)
                if current.status == "ACTIVE" and current.run_id == run:
                    return current
                generation = current.generation + 1
            else:
                generation = 1

            lease = RuntimeWriterLease(
                task_id=task,
                plan_fingerprint=plan,
                run_id=run,
                generation=generation,
                issued_at=timestamp,
            ).validate()
            lease_json = _canonical_json(lease.canonical_dict())
            lease_sha256 = lease.fingerprint
            conn.execute(
                """
                INSERT INTO runtime_writer_leases(
                    task_id, plan_fingerprint, run_id, generation, status,
                    lease_json, lease_sha256, updated_at
                ) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(task_id, plan_fingerprint) DO UPDATE SET
                    run_id=excluded.run_id,
                    generation=excluded.generation,
                    status=excluded.status,
                    lease_json=excluded.lease_json,
                    lease_sha256=excluded.lease_sha256,
                    updated_at=excluded.updated_at
                """,
                (
                    lease.task_id,
                    lease.plan_fingerprint,
                    lease.run_id,
                    lease.generation,
                    lease.status,
                    lease_json,
                    lease_sha256,
                    timestamp,
                ),
            )
            self._append_event(
                conn,
                lease=lease,
                event_type="WRITER_CLAIMED",
                recorded_at=timestamp,
            )
        return lease

    def current(
        self,
        *,
        task_id: str,
        plan_fingerprint: str,
    ) -> RuntimeWriterLease | None:
        task = _compact_id(task_id, "task_id")
        plan = _sha256(plan_fingerprint, "plan_fingerprint")
        with self.task_store.connect() as conn:
            self._require_task(conn, task)
            row = conn.execute(
                """
                SELECT * FROM runtime_writer_leases
                WHERE task_id = ? AND plan_fingerprint = ?
                """,
                (task, plan),
            ).fetchone()
        return None if row is None else self._lease_from_row(row)

    def require_current_in_transaction(self, conn, lease: RuntimeWriterLease) -> RuntimeWriterLease:
        """Fail closed unless ``lease`` is the exact current ACTIVE writer.

        The caller must invoke this method from the same transaction as the state
        mutation it protects. This is intentionally exposed as an in-transaction
        primitive rather than a convenience pre-check, which would permit a
        check-then-use race.
        """

        if not isinstance(lease, RuntimeWriterLease):
            raise RuntimeWriterLeaseError("INVALID_WRITER_LEASE")
        lease.validate()
        if lease.status != "ACTIVE":
            raise RuntimeWriterLeaseError("WRITER_LEASE_NOT_ACTIVE")
        row = conn.execute(
            """
            SELECT * FROM runtime_writer_leases
            WHERE task_id = ? AND plan_fingerprint = ?
            """,
            (lease.task_id, lease.plan_fingerprint),
        ).fetchone()
        if row is None:
            raise RuntimeWriterLeaseError("WRITER_LEASE_NOT_FOUND")
        current = self._lease_from_row(row)
        if current.status != "ACTIVE":
            raise RuntimeWriterLeaseError("WRITER_LEASE_NOT_ACTIVE")
        if current.fingerprint != lease.fingerprint:
            raise RuntimeWriterLeaseError("WRITER_LEASE_STALE")
        return current

    def require_current(self, lease: RuntimeWriterLease) -> RuntimeWriterLease:
        with self.task_store.connect() as conn:
            return self.require_current_in_transaction(conn, lease)

    def release(
        self,
        lease: RuntimeWriterLease,
        *,
        released_at: str | None = None,
    ) -> RuntimeWriterLease:
        if not isinstance(lease, RuntimeWriterLease):
            raise RuntimeWriterLeaseError("INVALID_WRITER_LEASE")
        lease.validate()
        if lease.status != "ACTIVE":
            raise RuntimeWriterLeaseError("WRITER_LEASE_NOT_ACTIVE")
        timestamp = (
            _timestamp(released_at, "released_at")
            if released_at is not None
            else _utc_now()
        )
        with self.task_store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._require_task(conn, lease.task_id)
            row = conn.execute(
                """
                SELECT * FROM runtime_writer_leases
                WHERE task_id = ? AND plan_fingerprint = ?
                """,
                (lease.task_id, lease.plan_fingerprint),
            ).fetchone()
            if row is None:
                raise RuntimeWriterLeaseError("WRITER_LEASE_NOT_FOUND")
            current = self._lease_from_row(row)
            same_generation = (
                current.run_id == lease.run_id
                and current.generation == lease.generation
                and current.issued_at == lease.issued_at
            )
            if not same_generation:
                raise RuntimeWriterLeaseError("WRITER_LEASE_STALE")
            if current.status == "RELEASED":
                return current
            if current.fingerprint != lease.fingerprint:
                raise RuntimeWriterLeaseError("WRITER_LEASE_STALE")

            released = RuntimeWriterLease(
                task_id=current.task_id,
                plan_fingerprint=current.plan_fingerprint,
                run_id=current.run_id,
                generation=current.generation,
                issued_at=current.issued_at,
                status="RELEASED",
                released_at=timestamp,
            ).validate()
            lease_json = _canonical_json(released.canonical_dict())
            conn.execute(
                """
                UPDATE runtime_writer_leases
                SET status = ?, lease_json = ?, lease_sha256 = ?, updated_at = ?
                WHERE task_id = ? AND plan_fingerprint = ?
                """,
                (
                    released.status,
                    lease_json,
                    released.fingerprint,
                    timestamp,
                    released.task_id,
                    released.plan_fingerprint,
                ),
            )
            self._append_event(
                conn,
                lease=released,
                event_type="WRITER_RELEASED",
                recorded_at=timestamp,
            )
        return released

    def verify_event_chain(self, *, task_id: str, plan_fingerprint: str) -> bool:
        task = _compact_id(task_id, "task_id")
        plan = _sha256(plan_fingerprint, "plan_fingerprint")
        with self.task_store.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM runtime_writer_lease_events
                WHERE task_id = ? AND plan_fingerprint = ?
                ORDER BY sequence ASC
                """,
                (task, plan),
            ).fetchall()
        previous_hash = ZERO_HASH
        for row in rows:
            payload_json = str(row["payload_json"])
            try:
                payload = json.loads(payload_json)
            except json.JSONDecodeError:
                return False
            if not isinstance(payload, dict) or _canonical_json(payload) != payload_json:
                return False
            payload_sha256 = _digest(payload)
            if str(row["payload_sha256"]) != payload_sha256:
                return False
            if str(row["previous_hash"]) != previous_hash:
                return False
            expected = self._event_hash(
                task_id=str(row["task_id"]),
                plan_fingerprint=str(row["plan_fingerprint"]),
                event_type=str(row["event_type"]),
                run_id=str(row["run_id"]),
                generation=int(row["generation"]),
                payload_json=payload_json,
                payload_sha256=payload_sha256,
                previous_hash=previous_hash,
                recorded_at=str(row["recorded_at"]),
            )
            if str(row["event_hash"]) != expected:
                return False
            previous_hash = expected
        return True


__all__ = [
    "RUNTIME_WRITER_LEASE_SCHEMA",
    "RuntimeWriterLease",
    "RuntimeWriterLeaseError",
    "RuntimeWriterLeaseRepository",
]
