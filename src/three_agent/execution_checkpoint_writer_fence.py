from __future__ import annotations

from typing import Any

from .execution_checkpoint import (
    ExecutionCheckpointError,
    ExecutionCheckpointRepository,
    RecoveredExecutionState,
    _canonical_json,
    _digest_payload,
    _dispatch_from_payload,
    _dispatch_payload,
    _parse_canonical_payload,
    _require_sha256,
    _utc_now,
)
from .execution_observation import ExecutionObservation
from .execution_scheduler import DispatchTicket
from .runtime_writer_lease import (
    RuntimeWriterLease,
    RuntimeWriterLeaseError,
    RuntimeWriterLeaseRepository,
)
from .store import TaskStore

EXECUTION_WRITER_FENCE_SCHEMA = "workspace-execution-writer-fence/v1"
WRITER_FENCE_EVENT_TYPE = "WRITER_FENCE_BOUND"
_PROTECTED_EVENT_KINDS = {
    "DISPATCH_RECORDED": "DISPATCH",
    "OBSERVATION_RECORDED": "OBSERVATION",
    "CANCELLED": "CANCELLATION",
}


class ExecutionWriterFenceError(ExecutionCheckpointError):
    """Execution persistence was denied by writer-generation fencing."""


def _fence_payload(
    lease: RuntimeWriterLease,
    *,
    subject_kind: str,
) -> dict[str, Any]:
    lease.validate()
    if lease.status != "ACTIVE":
        raise ExecutionWriterFenceError("EXECUTION_WRITER_LEASE_NOT_ACTIVE")
    if subject_kind not in frozenset(_PROTECTED_EVENT_KINDS.values()):
        raise ExecutionWriterFenceError("INVALID_EXECUTION_WRITER_FENCE_SUBJECT_KIND")
    return {
        "schema_version": EXECUTION_WRITER_FENCE_SCHEMA,
        "subject_kind": subject_kind,
        "writer_run_id": lease.run_id,
        "writer_generation": lease.generation,
        "writer_lease_fingerprint": lease.fingerprint,
    }


class WriterFencedExecutionCheckpointRepository(ExecutionCheckpointRepository):
    """Strengthen the existing checkpoint repository with durable writer fencing.

    This is intentionally an adapter over the canonical ``ExecutionCheckpointRepository``:
    it reuses the same TaskStore, checkpoint tables, canonical payloads and
    tamper-evident execution event chain. It does not introduce a second scheduler,
    persistence model, or authority system.

    Every protected mutation validates the exact ACTIVE ``RuntimeWriterLease``
    *inside the same SQLite write transaction* before state is changed. The
    protected execution event is immediately followed by a ``WRITER_FENCE_BOUND``
    receipt in the existing execution event chain. Dispatch settlement additionally
    requires the observation to use the same writer generation that issued the
    dispatch, so a superseding run cannot silently finish work owned by an older run.
    """

    def __init__(self, task_store: TaskStore, writer_lease: RuntimeWriterLease):
        super().__init__(task_store)
        if not isinstance(writer_lease, RuntimeWriterLease):
            raise TypeError("writer_lease must be RuntimeWriterLease")
        writer_lease.validate()
        if writer_lease.status != "ACTIVE":
            raise ExecutionWriterFenceError("EXECUTION_WRITER_LEASE_NOT_ACTIVE")
        self.writer_lease = writer_lease
        self.writer_lease_repository = RuntimeWriterLeaseRepository(task_store)

    def initialize(self) -> None:
        super().initialize()
        self.writer_lease_repository.initialize()
        self._require_current_writer()

    def _require_scope(self, *, task_id: str, plan_fingerprint: str) -> None:
        if task_id != self.writer_lease.task_id:
            raise ExecutionWriterFenceError("EXECUTION_WRITER_TASK_SCOPE_MISMATCH")
        if plan_fingerprint != self.writer_lease.plan_fingerprint:
            raise ExecutionWriterFenceError("EXECUTION_WRITER_PLAN_SCOPE_MISMATCH")

    @staticmethod
    def _translate_writer_error(exc: RuntimeWriterLeaseError) -> ExecutionWriterFenceError:
        return ExecutionWriterFenceError(f"EXECUTION_WRITER_FENCE_DENIED:{exc}")

    def _require_current_writer(self) -> RuntimeWriterLease:
        try:
            return self.writer_lease_repository.require_current(self.writer_lease)
        except RuntimeWriterLeaseError as exc:
            raise self._translate_writer_error(exc) from exc

    def _require_current_writer_in_transaction(self, conn) -> RuntimeWriterLease:
        try:
            return self.writer_lease_repository.require_current_in_transaction(
                conn,
                self.writer_lease,
            )
        except RuntimeWriterLeaseError as exc:
            raise self._translate_writer_error(exc) from exc

    def _append_writer_fence_event(
        self,
        conn,
        *,
        subject_kind: str,
        subject_id: str,
        recorded_at: str,
    ) -> None:
        payload = _fence_payload(self.writer_lease, subject_kind=subject_kind)
        payload_json = _canonical_json(payload)
        self._append_event(
            conn,
            task_id=self.writer_lease.task_id,
            plan_fingerprint=self.writer_lease.plan_fingerprint,
            event_type=WRITER_FENCE_EVENT_TYPE,
            subject_id=subject_id,
            payload_json=payload_json,
            payload_sha256=_digest_payload(payload),
            recorded_at=recorded_at,
        )

    @staticmethod
    def _validate_fence_payload(payload: Any, *, subject_kind: str) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ExecutionWriterFenceError("EXECUTION_WRITER_FENCE_PAYLOAD_NOT_OBJECT")
        expected_keys = {
            "schema_version",
            "subject_kind",
            "writer_run_id",
            "writer_generation",
            "writer_lease_fingerprint",
        }
        if set(payload) != expected_keys:
            raise ExecutionWriterFenceError("EXECUTION_WRITER_FENCE_PAYLOAD_SHAPE_INVALID")
        if payload["schema_version"] != EXECUTION_WRITER_FENCE_SCHEMA:
            raise ExecutionWriterFenceError("EXECUTION_WRITER_FENCE_SCHEMA_MISMATCH")
        if payload["subject_kind"] != subject_kind:
            raise ExecutionWriterFenceError("EXECUTION_WRITER_FENCE_SUBJECT_KIND_MISMATCH")
        if not isinstance(payload["writer_run_id"], str) or not payload["writer_run_id"]:
            raise ExecutionWriterFenceError("EXECUTION_WRITER_FENCE_RUN_ID_INVALID")
        generation = payload["writer_generation"]
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise ExecutionWriterFenceError("EXECUTION_WRITER_FENCE_GENERATION_INVALID")
        fingerprint = payload["writer_lease_fingerprint"]
        if not isinstance(fingerprint, str):
            raise ExecutionWriterFenceError("EXECUTION_WRITER_FENCE_FINGERPRINT_INVALID")
        _require_sha256(fingerprint, "writer_lease_fingerprint")
        return payload

    def _binding_after_event(
        self,
        conn,
        *,
        protected_event_type: str,
        subject_id: str,
    ) -> dict[str, Any]:
        subject_kind = _PROTECTED_EVENT_KINDS.get(protected_event_type)
        if subject_kind is None:
            raise ExecutionWriterFenceError("UNKNOWN_PROTECTED_EXECUTION_EVENT")
        event = conn.execute(
            """
            SELECT sequence
            FROM execution_checkpoint_events
            WHERE task_id = ? AND plan_fingerprint = ?
              AND event_type = ? AND subject_id = ?
            ORDER BY sequence DESC
            LIMIT 1
            """,
            (
                self.writer_lease.task_id,
                self.writer_lease.plan_fingerprint,
                protected_event_type,
                subject_id,
            ),
        ).fetchone()
        if event is None:
            raise ExecutionWriterFenceError("EXECUTION_PROTECTED_EVENT_NOT_FOUND")
        binding = conn.execute(
            """
            SELECT event_type, subject_id, payload_json, payload_sha256
            FROM execution_checkpoint_events
            WHERE task_id = ? AND plan_fingerprint = ? AND sequence = ?
            """,
            (
                self.writer_lease.task_id,
                self.writer_lease.plan_fingerprint,
                int(event["sequence"]) + 1,
            ),
        ).fetchone()
        if binding is None:
            raise ExecutionWriterFenceError("EXECUTION_WRITER_FENCE_BINDING_MISSING")
        if str(binding["event_type"]) != WRITER_FENCE_EVENT_TYPE:
            raise ExecutionWriterFenceError("EXECUTION_WRITER_FENCE_NOT_ADJACENT")
        if str(binding["subject_id"]) != subject_id:
            raise ExecutionWriterFenceError("EXECUTION_WRITER_FENCE_SUBJECT_MISMATCH")
        payload = _parse_canonical_payload(
            str(binding["payload_json"]),
            str(binding["payload_sha256"]),
            kind="WRITER_FENCE",
        )
        return self._validate_fence_payload(payload, subject_kind=subject_kind)

    def _require_binding_matches_current_writer(
        self,
        conn,
        *,
        protected_event_type: str,
        subject_id: str,
    ) -> dict[str, Any]:
        payload = self._binding_after_event(
            conn,
            protected_event_type=protected_event_type,
            subject_id=subject_id,
        )
        if (
            payload["writer_run_id"] != self.writer_lease.run_id
            or payload["writer_generation"] != self.writer_lease.generation
            or payload["writer_lease_fingerprint"] != self.writer_lease.fingerprint
        ):
            raise ExecutionWriterFenceError(
                "EXECUTION_WRITER_GENERATION_BINDING_MISMATCH"
            )
        return payload

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

    def record_observation(self, observation: ExecutionObservation) -> ExecutionObservation:
        observation.validate()
        self._require_scope(
            task_id=observation.task_id,
            plan_fingerprint=observation.plan_fingerprint,
        )
        payload = observation.canonical_dict()
        payload_json = _canonical_json(payload)
        payload_sha256 = _digest_payload(payload)
        now = _utc_now()
        with self.task_store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._require_task(conn, observation.task_id)
            self._require_current_writer_in_transaction(conn)
            ticket = conn.execute(
                """
                SELECT ticket_id, ticket_json, ticket_sha256
                FROM execution_dispatch_checkpoints
                WHERE task_id = ? AND plan_fingerprint = ? AND node_id = ?
                """,
                (observation.task_id, observation.plan_fingerprint, observation.node_id),
            ).fetchone()
            if ticket is None:
                raise ExecutionCheckpointError("OBSERVATION_CHECKPOINT_REQUIRES_DISPATCH")
            dispatch_payload = _parse_canonical_payload(
                str(ticket["ticket_json"]),
                str(ticket["ticket_sha256"]),
                kind="DISPATCH",
            )
            dispatch = _dispatch_from_payload(dispatch_payload)
            if observation.node_fingerprint != dispatch.node_fingerprint:
                raise ExecutionCheckpointError("OBSERVATION_CHECKPOINT_NODE_MISMATCH")
            if observation.authority_fingerprint != dispatch.authority_fingerprint:
                raise ExecutionCheckpointError("OBSERVATION_CHECKPOINT_AUTHORITY_MISMATCH")
            self._require_binding_matches_current_writer(
                conn,
                protected_event_type="DISPATCH_RECORDED",
                subject_id=str(ticket["ticket_id"]),
            )

            existing = conn.execute(
                """
                SELECT observation_json, observation_sha256
                FROM execution_observation_checkpoints
                WHERE observation_id = ?
                """,
                (observation.observation_id,),
            ).fetchone()
            if existing is not None:
                existing_payload = _parse_canonical_payload(
                    str(existing["observation_json"]),
                    str(existing["observation_sha256"]),
                    kind="OBSERVATION",
                )
                if _digest_payload(existing_payload) != payload_sha256:
                    raise ExecutionCheckpointError("OBSERVATION_CHECKPOINT_IDENTITY_CONFLICT")
                self._require_binding_matches_current_writer(
                    conn,
                    protected_event_type="OBSERVATION_RECORDED",
                    subject_id=observation.observation_id,
                )
                return observation
            node_row = conn.execute(
                """
                SELECT observation_id
                FROM execution_observation_checkpoints
                WHERE task_id = ? AND plan_fingerprint = ? AND node_id = ?
                """,
                (observation.task_id, observation.plan_fingerprint, observation.node_id),
            ).fetchone()
            if node_row is not None:
                raise ExecutionCheckpointError("OBSERVATION_CHECKPOINT_NODE_CONFLICT")
            conn.execute(
                """
                INSERT INTO execution_observation_checkpoints(
                    observation_id, task_id, plan_fingerprint, node_id,
                    observation_json, observation_sha256, recorded_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    observation.observation_id,
                    observation.task_id,
                    observation.plan_fingerprint,
                    observation.node_id,
                    payload_json,
                    payload_sha256,
                    now,
                ),
            )
            self._append_event(
                conn,
                task_id=observation.task_id,
                plan_fingerprint=observation.plan_fingerprint,
                event_type="OBSERVATION_RECORDED",
                subject_id=observation.observation_id,
                payload_json=payload_json,
                payload_sha256=payload_sha256,
                recorded_at=now,
            )
            self._append_writer_fence_event(
                conn,
                subject_kind="OBSERVATION",
                subject_id=observation.observation_id,
                recorded_at=now,
            )
        return observation

    def record_cancellation(
        self,
        *,
        task_id: str,
        plan_fingerprint: str,
        reason_code: str,
    ) -> None:
        self._require_scope(task_id=task_id, plan_fingerprint=plan_fingerprint)
        _require_sha256(plan_fingerprint, "plan_fingerprint")
        if not isinstance(reason_code, str) or not reason_code.strip():
            raise ExecutionCheckpointError("INVALID_CANCELLATION_REASON")
        reason = reason_code.strip()
        payload = {"reason_code": reason}
        payload_json = _canonical_json(payload)
        payload_sha256 = _digest_payload(payload)
        now = _utc_now()
        with self.task_store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._require_task(conn, task_id)
            self._require_current_writer_in_transaction(conn)
            latest = conn.execute(
                """
                SELECT sequence, payload_json, payload_sha256
                FROM execution_checkpoint_events
                WHERE task_id = ? AND plan_fingerprint = ? AND event_type = 'CANCELLED'
                ORDER BY sequence DESC
                LIMIT 1
                """,
                (task_id, plan_fingerprint),
            ).fetchone()
            if latest is not None:
                latest_payload = _parse_canonical_payload(
                    str(latest["payload_json"]),
                    str(latest["payload_sha256"]),
                    kind="CANCELLATION",
                )
                if _canonical_json(latest_payload) == payload_json:
                    try:
                        existing_binding = self._binding_after_event(
                            conn,
                            protected_event_type="CANCELLED",
                            subject_id=task_id,
                        )
                    except ExecutionWriterFenceError:
                        existing_binding = None
                    if existing_binding is not None and (
                        existing_binding["writer_run_id"] == self.writer_lease.run_id
                        and existing_binding["writer_generation"] == self.writer_lease.generation
                        and existing_binding["writer_lease_fingerprint"]
                        == self.writer_lease.fingerprint
                    ):
                        return
            self._append_event(
                conn,
                task_id=task_id,
                plan_fingerprint=plan_fingerprint,
                event_type="CANCELLED",
                subject_id=task_id,
                payload_json=payload_json,
                payload_sha256=payload_sha256,
                recorded_at=now,
            )
            self._append_writer_fence_event(
                conn,
                subject_kind="CANCELLATION",
                subject_id=task_id,
                recorded_at=now,
            )

    def verify_writer_fence_bindings(self) -> bool:
        if not self.verify_event_chain(
            task_id=self.writer_lease.task_id,
            plan_fingerprint=self.writer_lease.plan_fingerprint,
        ):
            return False
        try:
            with self.task_store.connect() as conn:
                rows = conn.execute(
                    """
                    SELECT sequence, event_type, subject_id
                    FROM execution_checkpoint_events
                    WHERE task_id = ? AND plan_fingerprint = ?
                    ORDER BY sequence ASC
                    """,
                    (
                        self.writer_lease.task_id,
                        self.writer_lease.plan_fingerprint,
                    ),
                ).fetchall()
                for row in rows:
                    event_type = str(row["event_type"])
                    subject_kind = _PROTECTED_EVENT_KINDS.get(event_type)
                    if subject_kind is None:
                        continue
                    binding = conn.execute(
                        """
                        SELECT event_type, subject_id, payload_json, payload_sha256
                        FROM execution_checkpoint_events
                        WHERE task_id = ? AND plan_fingerprint = ? AND sequence = ?
                        """,
                        (
                            self.writer_lease.task_id,
                            self.writer_lease.plan_fingerprint,
                            int(row["sequence"]) + 1,
                        ),
                    ).fetchone()
                    if binding is None:
                        return False
                    if str(binding["event_type"]) != WRITER_FENCE_EVENT_TYPE:
                        return False
                    if str(binding["subject_id"]) != str(row["subject_id"]):
                        return False
                    payload = _parse_canonical_payload(
                        str(binding["payload_json"]),
                        str(binding["payload_sha256"]),
                        kind="WRITER_FENCE",
                    )
                    self._validate_fence_payload(payload, subject_kind=subject_kind)

                dispatch_rows = conn.execute(
                    """
                    SELECT ticket_id, node_id
                    FROM execution_dispatch_checkpoints
                    WHERE task_id = ? AND plan_fingerprint = ?
                    """,
                    (
                        self.writer_lease.task_id,
                        self.writer_lease.plan_fingerprint,
                    ),
                ).fetchall()
                dispatch_bindings: dict[str, dict[str, Any]] = {}
                for dispatch_row in dispatch_rows:
                    dispatch_bindings[str(dispatch_row["node_id"])] = self._binding_after_event(
                        conn,
                        protected_event_type="DISPATCH_RECORDED",
                        subject_id=str(dispatch_row["ticket_id"]),
                    )

                observation_rows = conn.execute(
                    """
                    SELECT observation_id, node_id
                    FROM execution_observation_checkpoints
                    WHERE task_id = ? AND plan_fingerprint = ?
                    """,
                    (
                        self.writer_lease.task_id,
                        self.writer_lease.plan_fingerprint,
                    ),
                ).fetchall()
                for observation_row in observation_rows:
                    node_id = str(observation_row["node_id"])
                    dispatch_binding = dispatch_bindings.get(node_id)
                    if dispatch_binding is None:
                        return False
                    observation_binding = self._binding_after_event(
                        conn,
                        protected_event_type="OBSERVATION_RECORDED",
                        subject_id=str(observation_row["observation_id"]),
                    )
                    for field in (
                        "writer_run_id",
                        "writer_generation",
                        "writer_lease_fingerprint",
                    ):
                        if observation_binding[field] != dispatch_binding[field]:
                            return False
        except (ExecutionCheckpointError, RuntimeWriterLeaseError, ValueError, TypeError):
            return False
        return True

    def load(self, *, task_id: str, plan_fingerprint: str) -> RecoveredExecutionState:
        self._require_scope(task_id=task_id, plan_fingerprint=plan_fingerprint)
        self._require_current_writer()
        state = super().load(task_id=task_id, plan_fingerprint=plan_fingerprint)
        if not self.verify_writer_fence_bindings():
            raise ExecutionWriterFenceError("EXECUTION_WRITER_FENCE_BINDINGS_INVALID")
        return state


__all__ = [
    "EXECUTION_WRITER_FENCE_SCHEMA",
    "WRITER_FENCE_EVENT_TYPE",
    "ExecutionWriterFenceError",
    "WriterFencedExecutionCheckpointRepository",
]
