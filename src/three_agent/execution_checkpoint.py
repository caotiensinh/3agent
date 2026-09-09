from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .execution_observation import (
    EXECUTION_EVIDENCE_BINDING_SCHEMA,
    EXECUTION_OBSERVATION_SCHEMA,
    ExecutionEvidenceBinding,
    ExecutionObservation,
    ObservationCost,
)
from .execution_scheduler import DISPATCH_TICKET_SCHEMA, DispatchTicket
from .store import TaskStore

EXECUTION_CHECKPOINT_SCHEMA = "workspace-execution-checkpoint/v1"
ZERO_HASH = "sha256:" + "0" * 64
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class ExecutionCheckpointError(RuntimeError):
    """Persistent execution checkpoint state is missing, malformed, or tampered."""


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
        raise ExecutionCheckpointError("CHECKPOINT_NOT_CANONICAL_JSON") from exc


def _digest_payload(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _require_sha256(value: str, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ExecutionCheckpointError(f"INVALID_{field.upper()}")
    return value


def _parse_canonical_payload(
    raw_json: str,
    stored_sha256: str,
    *,
    kind: str,
) -> Any:
    try:
        payload = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise ExecutionCheckpointError(f"{kind}_CHECKPOINT_JSON_INVALID") from exc
    if _canonical_json(payload) != raw_json:
        raise ExecutionCheckpointError(f"{kind}_CHECKPOINT_NOT_CANONICAL")
    if stored_sha256 != _digest_payload(payload):
        raise ExecutionCheckpointError(f"{kind}_CHECKPOINT_DIGEST_MISMATCH")
    return payload


def _validate_dispatch_fingerprints(ticket: DispatchTicket) -> None:
    _require_sha256(ticket.plan_fingerprint, "plan_fingerprint")
    _require_sha256(ticket.node_fingerprint, "node_fingerprint")
    _require_sha256(ticket.authority_fingerprint, "authority_fingerprint")
    for dependency in ticket.dependency_observation_fingerprints:
        _require_sha256(dependency, "dependency_observation_fingerprint")


def _dispatch_payload(ticket: DispatchTicket) -> dict[str, Any]:
    ticket.validate()
    _validate_dispatch_fingerprints(ticket)
    return {
        "ticket_id": ticket.ticket_id,
        "schema_version": ticket.schema_version,
        "task_id": ticket.task_id,
        "plan_fingerprint": ticket.plan_fingerprint,
        "node_id": ticket.node_id,
        "node_fingerprint": ticket.node_fingerprint,
        "authority_fingerprint": ticket.authority_fingerprint,
        "dependency_observation_fingerprints": list(
            ticket.dependency_observation_fingerprints
        ),
        "dispatch_sequence": ticket.dispatch_sequence,
        "execution_level": ticket.execution_level,
        "dispatch_authorized": ticket.dispatch_authorized,
    }


def _dispatch_from_payload(payload: Any) -> DispatchTicket:
    if not isinstance(payload, dict):
        raise ExecutionCheckpointError("DISPATCH_CHECKPOINT_MUST_BE_OBJECT")
    expected_keys = {
        "ticket_id",
        "schema_version",
        "task_id",
        "plan_fingerprint",
        "node_id",
        "node_fingerprint",
        "authority_fingerprint",
        "dependency_observation_fingerprints",
        "dispatch_sequence",
        "execution_level",
        "dispatch_authorized",
    }
    if set(payload) != expected_keys:
        raise ExecutionCheckpointError("DISPATCH_CHECKPOINT_FIELDS_MISMATCH")
    if payload["schema_version"] != DISPATCH_TICKET_SCHEMA:
        raise ExecutionCheckpointError("DISPATCH_CHECKPOINT_SCHEMA_VERSION_MISMATCH")
    if payload["dispatch_authorized"] is not True:
        raise ExecutionCheckpointError("DISPATCH_CHECKPOINT_NOT_AUTHORIZED")
    dependencies = payload["dependency_observation_fingerprints"]
    if not isinstance(dependencies, list) or not all(
        isinstance(item, str) and _SHA256_RE.fullmatch(item) for item in dependencies
    ):
        raise ExecutionCheckpointError("INVALID_DISPATCH_DEPENDENCY_FINGERPRINTS")
    try:
        ticket = DispatchTicket(
            ticket_id=str(payload["ticket_id"]),
            task_id=str(payload["task_id"]),
            plan_fingerprint=_require_sha256(
                str(payload["plan_fingerprint"]), "plan_fingerprint"
            ),
            node_id=str(payload["node_id"]),
            node_fingerprint=_require_sha256(
                str(payload["node_fingerprint"]), "node_fingerprint"
            ),
            authority_fingerprint=_require_sha256(
                str(payload["authority_fingerprint"]), "authority_fingerprint"
            ),
            dependency_observation_fingerprints=tuple(dependencies),
            dispatch_sequence=int(payload["dispatch_sequence"]),
            execution_level=int(payload["execution_level"]),
            schema_version=str(payload["schema_version"]),
        )
        ticket.validate()
        _validate_dispatch_fingerprints(ticket)
        return ticket
    except (TypeError, ValueError) as exc:
        raise ExecutionCheckpointError("INVALID_DISPATCH_CHECKPOINT") from exc


def _observation_from_payload(payload: Any) -> ExecutionObservation:
    if not isinstance(payload, dict):
        raise ExecutionCheckpointError("OBSERVATION_CHECKPOINT_MUST_BE_OBJECT")
    expected_keys = {
        "observation_id",
        "schema_version",
        "task_id",
        "task_context_fingerprint",
        "plan_fingerprint",
        "node_id",
        "node_fingerprint",
        "authority_fingerprint",
        "status",
        "started_at",
        "finished_at",
        "normalized_output",
        "normalized_output_sha256",
        "error_class",
        "evidence_bindings",
        "cost",
    }
    if set(payload) != expected_keys:
        raise ExecutionCheckpointError("OBSERVATION_CHECKPOINT_FIELDS_MISMATCH")
    if payload["schema_version"] != EXECUTION_OBSERVATION_SCHEMA:
        raise ExecutionCheckpointError("OBSERVATION_CHECKPOINT_SCHEMA_VERSION_MISMATCH")

    raw_bindings = payload["evidence_bindings"]
    if not isinstance(raw_bindings, list):
        raise ExecutionCheckpointError("INVALID_OBSERVATION_EVIDENCE_BINDINGS")
    bindings: list[ExecutionEvidenceBinding] = []
    for raw in raw_bindings:
        if not isinstance(raw, dict) or set(raw) != {
            "schema_version",
            "requirement",
            "evidence_ref",
            "evidence_fingerprint",
        }:
            raise ExecutionCheckpointError("INVALID_OBSERVATION_EVIDENCE_BINDING")
        if raw["schema_version"] != EXECUTION_EVIDENCE_BINDING_SCHEMA:
            raise ExecutionCheckpointError("EVIDENCE_BINDING_SCHEMA_VERSION_MISMATCH")
        binding = ExecutionEvidenceBinding(
            evidence_ref=str(raw["evidence_ref"]),
            evidence_fingerprint=str(raw["evidence_fingerprint"]),
            requirement=(
                None if raw["requirement"] is None else str(raw["requirement"])
            ),
            schema_version=str(raw["schema_version"]),
        )
        bindings.append(binding.validate())

    raw_cost = payload["cost"]
    cost = None
    if raw_cost is not None:
        if not isinstance(raw_cost, dict) or set(raw_cost) != {
            "wall_time_s",
            "model_tokens",
            "tool_calls",
            "cost_usd",
        }:
            raise ExecutionCheckpointError("INVALID_OBSERVATION_COST")
        cost = ObservationCost(
            wall_time_s=raw_cost["wall_time_s"],
            model_tokens=raw_cost["model_tokens"],
            tool_calls=raw_cost["tool_calls"],
            cost_usd=raw_cost["cost_usd"],
        ).validate()

    normalized_output = payload["normalized_output"]
    normalized_output_json = (
        None if normalized_output is None else _canonical_json(normalized_output)
    )
    observation = ExecutionObservation(
        observation_id=str(payload["observation_id"]),
        task_id=str(payload["task_id"]),
        task_context_fingerprint=str(payload["task_context_fingerprint"]),
        plan_fingerprint=str(payload["plan_fingerprint"]),
        node_id=str(payload["node_id"]),
        node_fingerprint=str(payload["node_fingerprint"]),
        authority_fingerprint=str(payload["authority_fingerprint"]),
        status=str(payload["status"]),
        started_at=str(payload["started_at"]),
        finished_at=str(payload["finished_at"]),
        normalized_output_json=normalized_output_json,
        error_class=(
            None if payload["error_class"] is None else str(payload["error_class"])
        ),
        evidence_bindings=tuple(bindings),
        cost=cost,
        schema_version=str(payload["schema_version"]),
    )
    try:
        observation.validate()
    except (TypeError, ValueError) as exc:
        raise ExecutionCheckpointError("INVALID_OBSERVATION_CHECKPOINT") from exc
    if payload["normalized_output_sha256"] != observation.normalized_output_sha256:
        raise ExecutionCheckpointError("OBSERVATION_OUTPUT_DIGEST_MISMATCH")
    return observation


@dataclass(frozen=True)
class RecoveredExecutionState:
    task_id: str
    plan_fingerprint: str
    dispatches: tuple[DispatchTicket, ...]
    observations: tuple[ExecutionObservation, ...]
    recovery_required_ticket_ids: tuple[str, ...]
    cancellation_reason: str | None
    schema_version: str = EXECUTION_CHECKPOINT_SCHEMA

    @property
    def max_dispatch_sequence(self) -> int:
        return max((ticket.dispatch_sequence for ticket in self.dispatches), default=0)


class ExecutionCheckpointRepository:
    """Persist canonical scheduler receipts in the existing TaskStore SQLite DB.

    This repository is deliberately not an execution runtime. It never issues a
    dispatch, replays work, widens authority, or compiles a new TaskContract. Its
    only job is to persist and verify immutable dispatch/observation receipts so a
    process restart can recover fail-closed.
    """

    def __init__(self, task_store: TaskStore):
        if not isinstance(task_store, TaskStore):
            raise TypeError("task_store must be TaskStore")
        self.task_store = task_store

    def initialize(self) -> None:
        with self.task_store.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS execution_dispatch_checkpoints (
                    ticket_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    plan_fingerprint TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    dispatch_sequence INTEGER NOT NULL,
                    ticket_json TEXT NOT NULL,
                    ticket_sha256 TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    UNIQUE(task_id, plan_fingerprint, node_id),
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE INDEX IF NOT EXISTS idx_execution_dispatch_task_plan
                    ON execution_dispatch_checkpoints(task_id, plan_fingerprint, dispatch_sequence);

                CREATE TABLE IF NOT EXISTS execution_observation_checkpoints (
                    observation_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    plan_fingerprint TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    observation_json TEXT NOT NULL,
                    observation_sha256 TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    UNIQUE(task_id, plan_fingerprint, node_id),
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE INDEX IF NOT EXISTS idx_execution_observation_task_plan
                    ON execution_observation_checkpoints(task_id, plan_fingerprint, node_id);

                CREATE TABLE IF NOT EXISTS execution_checkpoint_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    plan_fingerprint TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE INDEX IF NOT EXISTS idx_execution_checkpoint_events_task_plan
                    ON execution_checkpoint_events(task_id, plan_fingerprint, sequence);
                """
            )

    @staticmethod
    def _require_task(conn, task_id: str) -> None:
        if conn.execute(
            "SELECT 1 FROM tasks WHERE task_id = ? LIMIT 1",
            (task_id,),
        ).fetchone() is None:
            raise ExecutionCheckpointError("EXECUTION_CHECKPOINT_TASK_NOT_FOUND")

    @staticmethod
    def _event_hash(
        *,
        task_id: str,
        plan_fingerprint: str,
        event_type: str,
        subject_id: str,
        payload_json: str,
        payload_sha256: str,
        previous_hash: str,
        recorded_at: str,
    ) -> str:
        return _digest_payload(
            {
                "task_id": task_id,
                "plan_fingerprint": plan_fingerprint,
                "event_type": event_type,
                "subject_id": subject_id,
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
        task_id: str,
        plan_fingerprint: str,
        event_type: str,
        subject_id: str,
        payload_json: str,
        payload_sha256: str,
        recorded_at: str,
    ) -> None:
        row = conn.execute(
            """
            SELECT event_hash
            FROM execution_checkpoint_events
            WHERE task_id = ? AND plan_fingerprint = ?
            ORDER BY sequence DESC
            LIMIT 1
            """,
            (task_id, plan_fingerprint),
        ).fetchone()
        previous_hash = str(row["event_hash"]) if row else ZERO_HASH
        event_hash = self._event_hash(
            task_id=task_id,
            plan_fingerprint=plan_fingerprint,
            event_type=event_type,
            subject_id=subject_id,
            payload_json=payload_json,
            payload_sha256=payload_sha256,
            previous_hash=previous_hash,
            recorded_at=recorded_at,
        )
        conn.execute(
            """
            INSERT INTO execution_checkpoint_events(
                task_id, plan_fingerprint, event_type, subject_id,
                payload_json, payload_sha256, previous_hash, event_hash, recorded_at
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                task_id,
                plan_fingerprint,
                event_type,
                subject_id,
                payload_json,
                payload_sha256,
                previous_hash,
                event_hash,
                recorded_at,
            ),
        )

    def record_dispatch(self, ticket: DispatchTicket) -> DispatchTicket:
        payload = _dispatch_payload(ticket)
        payload_json = _canonical_json(payload)
        payload_sha256 = _digest_payload(payload)
        now = _utc_now()
        with self.task_store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._require_task(conn, ticket.task_id)
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
        return ticket

    def record_observation(self, observation: ExecutionObservation) -> ExecutionObservation:
        observation.validate()
        payload = observation.canonical_dict()
        payload_json = _canonical_json(payload)
        payload_sha256 = _digest_payload(payload)
        now = _utc_now()
        with self.task_store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._require_task(conn, observation.task_id)
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
        return observation

    def record_cancellation(
        self,
        *,
        task_id: str,
        plan_fingerprint: str,
        reason_code: str,
    ) -> None:
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
            latest = conn.execute(
                """
                SELECT payload_json, payload_sha256
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

    def verify_event_chain(self, *, task_id: str, plan_fingerprint: str) -> bool:
        with self.task_store.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM execution_checkpoint_events
                WHERE task_id = ? AND plan_fingerprint = ?
                ORDER BY sequence ASC
                """,
                (task_id, plan_fingerprint),
            ).fetchall()
        previous_hash = ZERO_HASH
        for row in rows:
            payload_json = str(row["payload_json"])
            try:
                payload = json.loads(payload_json)
            except json.JSONDecodeError:
                return False
            if _canonical_json(payload) != payload_json:
                return False
            payload_sha256 = _digest_payload(payload)
            if str(row["payload_sha256"]) != payload_sha256:
                return False
            if str(row["previous_hash"]) != previous_hash:
                return False
            expected = self._event_hash(
                task_id=str(row["task_id"]),
                plan_fingerprint=str(row["plan_fingerprint"]),
                event_type=str(row["event_type"]),
                subject_id=str(row["subject_id"]),
                payload_json=payload_json,
                payload_sha256=payload_sha256,
                previous_hash=previous_hash,
                recorded_at=str(row["recorded_at"]),
            )
            if str(row["event_hash"]) != expected:
                return False
            previous_hash = expected
        return True

    def load(self, *, task_id: str, plan_fingerprint: str) -> RecoveredExecutionState:
        _require_sha256(plan_fingerprint, "plan_fingerprint")
        if not self.verify_event_chain(task_id=task_id, plan_fingerprint=plan_fingerprint):
            raise ExecutionCheckpointError("EXECUTION_CHECKPOINT_EVENT_CHAIN_INVALID")

        with self.task_store.connect() as conn:
            self._require_task(conn, task_id)
            dispatch_rows = conn.execute(
                """
                SELECT *
                FROM execution_dispatch_checkpoints
                WHERE task_id = ? AND plan_fingerprint = ?
                ORDER BY dispatch_sequence ASC
                """,
                (task_id, plan_fingerprint),
            ).fetchall()
            observation_rows = conn.execute(
                """
                SELECT *
                FROM execution_observation_checkpoints
                WHERE task_id = ? AND plan_fingerprint = ?
                ORDER BY node_id ASC
                """,
                (task_id, plan_fingerprint),
            ).fetchall()
            cancellation = conn.execute(
                """
                SELECT payload_json, payload_sha256
                FROM execution_checkpoint_events
                WHERE task_id = ? AND plan_fingerprint = ? AND event_type = 'CANCELLED'
                ORDER BY sequence DESC
                LIMIT 1
                """,
                (task_id, plan_fingerprint),
            ).fetchone()

        dispatches: list[DispatchTicket] = []
        dispatch_by_node: dict[str, DispatchTicket] = {}
        for row in dispatch_rows:
            payload = _parse_canonical_payload(
                str(row["ticket_json"]),
                str(row["ticket_sha256"]),
                kind="DISPATCH",
            )
            ticket = _dispatch_from_payload(payload)
            if ticket.task_id != task_id or ticket.plan_fingerprint != plan_fingerprint:
                raise ExecutionCheckpointError("DISPATCH_CHECKPOINT_SCOPE_MISMATCH")
            if ticket.node_id in dispatch_by_node:
                raise ExecutionCheckpointError("DUPLICATE_DISPATCH_CHECKPOINT_NODE")
            dispatch_by_node[ticket.node_id] = ticket
            dispatches.append(ticket)

        observations: list[ExecutionObservation] = []
        observed_nodes: set[str] = set()
        for row in observation_rows:
            payload = _parse_canonical_payload(
                str(row["observation_json"]),
                str(row["observation_sha256"]),
                kind="OBSERVATION",
            )
            observation = _observation_from_payload(payload)
            if observation.task_id != task_id or observation.plan_fingerprint != plan_fingerprint:
                raise ExecutionCheckpointError("OBSERVATION_CHECKPOINT_SCOPE_MISMATCH")
            dispatch = dispatch_by_node.get(observation.node_id)
            if dispatch is None:
                raise ExecutionCheckpointError("OBSERVATION_CHECKPOINT_ORPHANED")
            if observation.node_fingerprint != dispatch.node_fingerprint:
                raise ExecutionCheckpointError("OBSERVATION_CHECKPOINT_NODE_MISMATCH")
            if observation.authority_fingerprint != dispatch.authority_fingerprint:
                raise ExecutionCheckpointError("OBSERVATION_CHECKPOINT_AUTHORITY_MISMATCH")
            observations.append(observation)
            observed_nodes.add(observation.node_id)

        cancellation_reason = None
        if cancellation is not None:
            cancellation_payload = _parse_canonical_payload(
                str(cancellation["payload_json"]),
                str(cancellation["payload_sha256"]),
                kind="CANCELLATION",
            )
            reason = cancellation_payload.get("reason_code")
            if not isinstance(reason, str) or not reason:
                raise ExecutionCheckpointError("CANCELLATION_CHECKPOINT_INVALID")
            cancellation_reason = reason

        recovery_required = tuple(
            ticket.ticket_id
            for ticket in dispatches
            if ticket.node_id not in observed_nodes
        )
        return RecoveredExecutionState(
            task_id=task_id,
            plan_fingerprint=plan_fingerprint,
            dispatches=tuple(dispatches),
            observations=tuple(observations),
            recovery_required_ticket_ids=recovery_required,
            cancellation_reason=cancellation_reason,
        )
