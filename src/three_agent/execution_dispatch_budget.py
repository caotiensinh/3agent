from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .execution_budget import ExecutionBudgetExceeded, TaskExecutionBudgetState
from .execution_checkpoint import (
    ExecutionCheckpointError,
    _canonical_json,
    _digest_payload,
    _dispatch_payload,
    _parse_canonical_payload,
    _utc_now,
)
from .execution_checkpoint_writer_fence import (
    WriterFencedExecutionCheckpointRepository,
)
from .execution_scheduler import DispatchTicket
from .runtime_writer_lease import RuntimeWriterLease
from .store import TaskStore

EXECUTION_DISPATCH_BUDGET_SCHEMA = "workspace-execution-dispatch-budget/v1"


class ExecutionDispatchBudgetError(ExecutionCheckpointError):
    """Dispatch budget persistence failed closed at the checkpoint boundary."""


def _reservation_payload(ticket: DispatchTicket) -> dict[str, Any]:
    ticket.validate()
    return {
        "schema_version": EXECUTION_DISPATCH_BUDGET_SCHEMA,
        "task_id": ticket.task_id,
        "plan_fingerprint": ticket.plan_fingerprint,
        "node_id": ticket.node_id,
        "node_fingerprint": ticket.node_fingerprint,
        "authority_fingerprint": ticket.authority_fingerprint,
        "steps": 1,
    }


def _reservation_id(payload: dict[str, Any]) -> str:
    text = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return "dispatch-budget:" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]


@dataclass(frozen=True)
class DispatchBudgetReservation:
    reservation_id: str
    task_id: str
    plan_fingerprint: str
    node_id: str
    node_fingerprint: str
    authority_fingerprint: str
    steps: int
    fingerprint: str
    reserved_at: str
    schema_version: str = EXECUTION_DISPATCH_BUDGET_SCHEMA


class DispatchBudgetController:
    """Bind one canonical task step to one plan node without widening budget authority.

    The controller reuses ``task_execution_budget_usage`` as the only budget source
    of truth.  The reservation table is an idempotency/audit index only; it does
    not contain another set of limits or counters.
    """

    def __init__(self, task_store: TaskStore, budget_state: TaskExecutionBudgetState):
        if not isinstance(task_store, TaskStore):
            raise TypeError("task_store must be TaskStore")
        if not isinstance(budget_state, TaskExecutionBudgetState):
            raise TypeError("budget_state must be TaskExecutionBudgetState")
        if task_store.db_path.resolve(strict=False) != budget_state.store.db_path.resolve(strict=False):
            raise ExecutionDispatchBudgetError("DISPATCH_BUDGET_STORE_MISMATCH")
        self.task_store = task_store
        self.budget_state = budget_state

    def initialize(self) -> None:
        with self.task_store.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_dispatch_budget_reservations (
                    reservation_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    plan_fingerprint TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    reservation_json TEXT NOT NULL,
                    reservation_sha256 TEXT NOT NULL,
                    reserved_at TEXT NOT NULL,
                    UNIQUE(task_id, plan_fingerprint, node_id),
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_execution_dispatch_budget_scope
                ON execution_dispatch_budget_reservations(task_id, plan_fingerprint, node_id)
                """
            )

    def assert_dispatch_step_available(self) -> None:
        """Cheap preflight only; the transaction-local reservation is authoritative."""
        self.budget_state.assert_active()
        snapshot = self.budget_state.snapshot()
        if int(snapshot["steps_used"]) + 1 > int(snapshot["max_steps"]):
            raise ExecutionBudgetExceeded("TASK_STEP_BUDGET_EXHAUSTED")

    @staticmethod
    def _deadline_expired(deadline_at: str) -> bool:
        try:
            deadline = datetime.fromisoformat(str(deadline_at))
        except ValueError as exc:
            raise ExecutionDispatchBudgetError("TASK_EXECUTION_BUDGET_DEADLINE_INVALID") from exc
        if deadline.tzinfo is None:
            raise ExecutionDispatchBudgetError("TASK_EXECUTION_BUDGET_DEADLINE_NAIVE")
        return datetime.now(deadline.tzinfo) >= deadline

    def _require_budget_scope(self, ticket: DispatchTicket) -> None:
        if ticket.task_id != self.budget_state.task_id:
            raise ExecutionDispatchBudgetError("DISPATCH_BUDGET_TASK_SCOPE_MISMATCH")

    def reserve_new_in_transaction(self, conn, ticket: DispatchTicket) -> DispatchBudgetReservation:
        """Reserve one dispatch step in the caller's existing SQLite transaction."""
        self._require_budget_scope(ticket)
        payload = _reservation_payload(ticket)
        payload_json = _canonical_json(payload)
        payload_sha256 = _digest_payload(payload)
        reservation_id = _reservation_id(payload)

        existing = conn.execute(
            """
            SELECT reservation_id, reservation_json, reservation_sha256
            FROM execution_dispatch_budget_reservations
            WHERE task_id = ? AND plan_fingerprint = ? AND node_id = ?
            """,
            (ticket.task_id, ticket.plan_fingerprint, ticket.node_id),
        ).fetchone()
        if existing is not None:
            existing_payload = _parse_canonical_payload(
                str(existing["reservation_json"]),
                str(existing["reservation_sha256"]),
                kind="DISPATCH_BUDGET_RESERVATION",
            )
            if _digest_payload(existing_payload) != payload_sha256:
                raise ExecutionDispatchBudgetError("DISPATCH_BUDGET_RESERVATION_CONFLICT")
            raise ExecutionDispatchBudgetError("DISPATCH_BUDGET_ORPHAN_RESERVATION")

        row = conn.execute(
            "SELECT * FROM task_execution_budget_usage WHERE task_id = ?",
            (ticket.task_id,),
        ).fetchone()
        if row is None:
            raise ExecutionDispatchBudgetError("TASK_EXECUTION_BUDGET_NOT_BOUND")
        if self._deadline_expired(str(row["deadline_at"])):
            raise ExecutionBudgetExceeded("TASK_WALL_TIME_BUDGET_EXHAUSTED")

        new_steps = int(row["steps_used"]) + 1
        if new_steps > int(row["max_steps"]):
            raise ExecutionBudgetExceeded("TASK_STEP_BUDGET_EXHAUSTED")

        now = _utc_now()
        conn.execute(
            """
            UPDATE task_execution_budget_usage
            SET steps_used = ?, updated_at = ?
            WHERE task_id = ?
            """,
            (new_steps, now, ticket.task_id),
        )
        conn.execute(
            """
            INSERT INTO execution_dispatch_budget_reservations(
                reservation_id, task_id, plan_fingerprint, node_id,
                reservation_json, reservation_sha256, reserved_at
            ) VALUES(?,?,?,?,?,?,?)
            """,
            (
                reservation_id,
                ticket.task_id,
                ticket.plan_fingerprint,
                ticket.node_id,
                payload_json,
                payload_sha256,
                now,
            ),
        )
        return DispatchBudgetReservation(
            reservation_id=reservation_id,
            task_id=ticket.task_id,
            plan_fingerprint=ticket.plan_fingerprint,
            node_id=ticket.node_id,
            node_fingerprint=ticket.node_fingerprint,
            authority_fingerprint=ticket.authority_fingerprint,
            steps=1,
            fingerprint=payload_sha256,
            reserved_at=now,
        )

    def require_existing_in_transaction(self, conn, ticket: DispatchTicket) -> DispatchBudgetReservation:
        """Verify an exact reservation for an already-persisted G6 dispatch."""
        self._require_budget_scope(ticket)
        payload = _reservation_payload(ticket)
        payload_sha256 = _digest_payload(payload)
        row = conn.execute(
            """
            SELECT reservation_id, reservation_json, reservation_sha256, reserved_at
            FROM execution_dispatch_budget_reservations
            WHERE task_id = ? AND plan_fingerprint = ? AND node_id = ?
            """,
            (ticket.task_id, ticket.plan_fingerprint, ticket.node_id),
        ).fetchone()
        if row is None:
            raise ExecutionDispatchBudgetError("DISPATCH_BUDGET_RESERVATION_MISSING")
        existing_payload = _parse_canonical_payload(
            str(row["reservation_json"]),
            str(row["reservation_sha256"]),
            kind="DISPATCH_BUDGET_RESERVATION",
        )
        if _digest_payload(existing_payload) != payload_sha256:
            raise ExecutionDispatchBudgetError("DISPATCH_BUDGET_RESERVATION_CONFLICT")
        return DispatchBudgetReservation(
            reservation_id=str(row["reservation_id"]),
            task_id=ticket.task_id,
            plan_fingerprint=ticket.plan_fingerprint,
            node_id=ticket.node_id,
            node_fingerprint=ticket.node_fingerprint,
            authority_fingerprint=ticket.authority_fingerprint,
            steps=1,
            fingerprint=payload_sha256,
            reserved_at=str(row["reserved_at"]),
        )


class DispatchBudgetPreflightGuard:
    """Scheduler-facing guard that defers the one step mutation to checkpoint commit."""

    def __init__(self, controller: DispatchBudgetController):
        if not isinstance(controller, DispatchBudgetController):
            raise TypeError("controller must be DispatchBudgetController")
        self.controller = controller

    def assert_active(self) -> None:
        self.controller.budget_state.assert_active()

    def reserve(
        self,
        *,
        steps: int = 0,
        tool_calls: int = 0,
        retries: int = 0,
        escalations: int = 0,
    ) -> None:
        if steps == 1 and tool_calls == 0 and retries == 0 and escalations == 0:
            self.controller.assert_dispatch_step_available()
            return
        if steps == 0 and tool_calls == 0 and retries == 0 and escalations == 0:
            self.controller.budget_state.assert_active()
            return
        raise ExecutionDispatchBudgetError("DISPATCH_BUDGET_PREFLIGHT_UNSUPPORTED_RESERVATION")


class AtomicBudgetWriterFencedExecutionCheckpointRepository(
    WriterFencedExecutionCheckpointRepository
):
    """Writer-fenced checkpoint adapter with atomic dispatch-step accounting.

    For a new dispatch, writer lease revalidation, one canonical task step, the
    dispatch checkpoint, the execution event, and the writer-fence event share one
    ``BEGIN IMMEDIATE`` transaction.  A failure at any later statement rolls all of
    them back together.
    """

    def __init__(
        self,
        task_store: TaskStore,
        writer_lease: RuntimeWriterLease,
        budget_state: TaskExecutionBudgetState,
    ):
        super().__init__(task_store, writer_lease)
        self.dispatch_budget_controller = DispatchBudgetController(task_store, budget_state)

    def initialize(self) -> None:
        super().initialize()
        self.dispatch_budget_controller.initialize()

    def record_dispatch(self, ticket: DispatchTicket) -> DispatchTicket:
        self._require_scope(
            task_id=ticket.task_id,
            plan_fingerprint=ticket.plan_fingerprint,
        )
        payload = _dispatch_payload(ticket)
        payload_json = _canonical_json(payload)
        payload_sha256 = _digest_payload(payload)
        now = _utc_now()
        with self.task_store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._require_task(conn, ticket.task_id)
            self._require_current_writer_in_transaction(conn)
            existing = conn.execute(
                """
                SELECT ticket_json, ticket_sha256
                FROM execution_dispatch_checkpoints
                WHERE ticket_id = ?
                """,
                (ticket.ticket_id,),
            ).fetchone()
            if existing is not None:
                existing_payload = _parse_canonical_payload(
                    str(existing["ticket_json"]),
                    str(existing["ticket_sha256"]),
                    kind="DISPATCH",
                )
                if _digest_payload(existing_payload) != payload_sha256:
                    raise ExecutionCheckpointError("DISPATCH_CHECKPOINT_IDENTITY_CONFLICT")
                self._require_binding_matches_current_writer(
                    conn,
                    protected_event_type="DISPATCH_RECORDED",
                    subject_id=ticket.ticket_id,
                )
                self.dispatch_budget_controller.require_existing_in_transaction(conn, ticket)
                return ticket

            node_row = conn.execute(
                """
                SELECT ticket_id
                FROM execution_dispatch_checkpoints
                WHERE task_id = ? AND plan_fingerprint = ? AND node_id = ?
                """,
                (ticket.task_id, ticket.plan_fingerprint, ticket.node_id),
            ).fetchone()
            if node_row is not None:
                raise ExecutionCheckpointError("DISPATCH_CHECKPOINT_NODE_CONFLICT")

            self.dispatch_budget_controller.reserve_new_in_transaction(conn, ticket)
            conn.execute(
                """
                INSERT INTO execution_dispatch_checkpoints(
                    ticket_id, task_id, plan_fingerprint, node_id, dispatch_sequence,
                    ticket_json, ticket_sha256, recorded_at
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    ticket.ticket_id,
                    ticket.task_id,
                    ticket.plan_fingerprint,
                    ticket.node_id,
                    ticket.dispatch_sequence,
                    payload_json,
                    payload_sha256,
                    now,
                ),
            )
            self._append_event(
                conn,
                task_id=ticket.task_id,
                plan_fingerprint=ticket.plan_fingerprint,
                event_type="DISPATCH_RECORDED",
                subject_id=ticket.ticket_id,
                payload_json=payload_json,
                payload_sha256=payload_sha256,
                recorded_at=now,
            )
            self._append_writer_fence_event(
                conn,
                subject_kind="DISPATCH",
                subject_id=ticket.ticket_id,
                recorded_at=now,
            )
        return ticket


__all__ = [
    "EXECUTION_DISPATCH_BUDGET_SCHEMA",
    "AtomicBudgetWriterFencedExecutionCheckpointRepository",
    "DispatchBudgetController",
    "DispatchBudgetPreflightGuard",
    "DispatchBudgetReservation",
    "ExecutionDispatchBudgetError",
]
