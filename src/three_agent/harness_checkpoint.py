from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .store import TaskStore

HARNESS_CHECKPOINT_SCHEMA = "workspace-harness-checkpoint/v1"

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class HarnessCheckpointError(ValueError):
    """Checkpoint input or persisted state violates a deterministic invariant."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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
        raise HarnessCheckpointError("CHECKPOINT_NOT_CANONICAL_JSON") from exc


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _compact_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise HarnessCheckpointError(f"INVALID_{field_name.upper()}")
    if not _ID_RE.fullmatch(value):
        raise HarnessCheckpointError(f"INVALID_{field_name.upper()}")
    return value


def _single_line(value: Any, field_name: str, *, max_len: int, required: bool = True) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise HarnessCheckpointError(f"INVALID_{field_name.upper()}")
    if required and not value:
        raise HarnessCheckpointError(f"INVALID_{field_name.upper()}")
    if len(value) > max_len or "\n" in value or "\r" in value:
        raise HarnessCheckpointError(f"INVALID_{field_name.upper()}")
    return value


def _timestamp(value: Any, field_name: str) -> str:
    text = _single_line(value, field_name, max_len=64)
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise HarnessCheckpointError(f"INVALID_{field_name.upper()}") from exc
    if parsed.tzinfo is None:
        raise HarnessCheckpointError(f"{field_name.upper()}_MUST_BE_TIMEZONE_AWARE")
    return text


def _as_datetime(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    return datetime.fromisoformat(normalized)


def _string_tuple(
    value: Any,
    field_name: str,
    *,
    max_items: int = 256,
    max_item_len: int = 1024,
) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise HarnessCheckpointError(f"{field_name.upper()}_MUST_BE_TUPLE")
    if len(value) > max_items:
        raise HarnessCheckpointError(f"{field_name.upper()}_TOO_MANY_ITEMS")
    result: list[str] = []
    for item in value:
        result.append(_single_line(item, field_name, max_len=max_item_len))
    if len(set(result)) != len(result):
        raise HarnessCheckpointError(f"DUPLICATE_{field_name.upper()}")
    return tuple(result)


@dataclass(frozen=True)
class HarnessCheckpoint:
    checkpoint_id: str
    project_id: str
    conversation_id: str
    task_id: str
    goal: str
    current_state: str
    completed: tuple[str, ...] = ()
    open_tasks: tuple[str, ...] = ()
    decisions: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()
    known_failures: tuple[str, ...] = ()
    important_entities: tuple[str, ...] = ()
    latest_evidence: tuple[str, ...] = ()
    next_action: str = ""
    source_refs: tuple[str, ...] = ()
    created_at: str = field(default_factory=_now)
    schema_version: str = HARNESS_CHECKPOINT_SCHEMA

    def validate(self) -> "HarnessCheckpoint":
        _compact_id(self.checkpoint_id, "checkpoint_id")
        _compact_id(self.project_id, "project_id")
        _compact_id(self.conversation_id, "conversation_id")
        _compact_id(self.task_id, "task_id")
        _single_line(self.goal, "goal", max_len=4096)
        _single_line(self.current_state, "current_state", max_len=8192)
        _string_tuple(self.completed, "completed")
        _string_tuple(self.open_tasks, "open_tasks")
        _string_tuple(self.decisions, "decisions")
        _string_tuple(self.constraints, "constraints")
        _string_tuple(self.known_failures, "known_failures")
        _string_tuple(self.important_entities, "important_entities")
        _string_tuple(self.latest_evidence, "latest_evidence")
        _single_line(self.next_action, "next_action", max_len=4096)
        refs = _string_tuple(
            self.source_refs,
            "source_refs",
            max_items=512,
            max_item_len=512,
        )
        if not refs:
            raise HarnessCheckpointError("CHECKPOINT_SOURCE_REFS_REQUIRED")
        _timestamp(self.created_at, "created_at")
        if self.schema_version != HARNESS_CHECKPOINT_SCHEMA:
            raise HarnessCheckpointError("CHECKPOINT_SCHEMA_VERSION_MISMATCH")
        return self

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "checkpoint_id": self.checkpoint_id,
            "project_id": self.project_id,
            "conversation_id": self.conversation_id,
            "task_id": self.task_id,
            "goal": self.goal,
            "current_state": self.current_state,
            "completed": list(self.completed),
            "open_tasks": list(self.open_tasks),
            "decisions": list(self.decisions),
            "constraints": list(self.constraints),
            "known_failures": list(self.known_failures),
            "important_entities": list(self.important_entities),
            "latest_evidence": list(self.latest_evidence),
            "next_action": self.next_action,
            "source_refs": list(self.source_refs),
            "created_at": self.created_at,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())


class HarnessCheckpointStore:
    """Immutable reconstruction anchors backed by the existing WorkSpace SQLite DB."""

    def __init__(self, task_store: TaskStore):
        if not isinstance(task_store, TaskStore):
            raise TypeError("task_store must be TaskStore")
        self.task_store = task_store
        self.initialize()

    def initialize(self) -> None:
        with self.task_store.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS harness_checkpoints (
                    checkpoint_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    conversation_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    checkpoint_json TEXT NOT NULL,
                    checkpoint_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE INDEX IF NOT EXISTS idx_harness_checkpoints_scope
                    ON harness_checkpoints(project_id, conversation_id, task_id, created_at);

                CREATE TRIGGER IF NOT EXISTS harness_checkpoints_no_update
                BEFORE UPDATE ON harness_checkpoints
                BEGIN
                    SELECT RAISE(ABORT, 'harness checkpoints are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS harness_checkpoints_no_delete
                BEFORE DELETE ON harness_checkpoints
                BEGIN
                    SELECT RAISE(ABORT, 'harness checkpoints are immutable');
                END;
                """
            )

    def _assert_task_exists(self, task_id: str) -> None:
        try:
            self.task_store.get_task(task_id)
        except KeyError as exc:
            raise HarnessCheckpointError("CHECKPOINT_TASK_SCOPE_UNKNOWN") from exc

    @staticmethod
    def _from_row(row: sqlite3.Row) -> HarnessCheckpoint:
        try:
            payload = json.loads(str(row["checkpoint_json"]))
        except (json.JSONDecodeError, TypeError) as exc:
            raise HarnessCheckpointError("CHECKPOINT_INTEGRITY_FAILED:JSON_INVALID") from exc
        if not isinstance(payload, dict):
            raise HarnessCheckpointError("CHECKPOINT_INTEGRITY_FAILED:NOT_OBJECT")

        def required_text(key: str) -> str:
            value = payload.get(key)
            if not isinstance(value, str):
                raise HarnessCheckpointError("CHECKPOINT_INTEGRITY_FAILED:SHAPE_INVALID")
            return value

        def required_string_list(key: str) -> tuple[str, ...]:
            value = payload.get(key)
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise HarnessCheckpointError("CHECKPOINT_INTEGRITY_FAILED:SHAPE_INVALID")
            return tuple(value)

        checkpoint = HarnessCheckpoint(
            checkpoint_id=required_text("checkpoint_id"),
            project_id=required_text("project_id"),
            conversation_id=required_text("conversation_id"),
            task_id=required_text("task_id"),
            goal=required_text("goal"),
            current_state=required_text("current_state"),
            completed=required_string_list("completed"),
            open_tasks=required_string_list("open_tasks"),
            decisions=required_string_list("decisions"),
            constraints=required_string_list("constraints"),
            known_failures=required_string_list("known_failures"),
            important_entities=required_string_list("important_entities"),
            latest_evidence=required_string_list("latest_evidence"),
            next_action=required_text("next_action"),
            source_refs=required_string_list("source_refs"),
            created_at=required_text("created_at"),
            schema_version=required_text("schema_version"),
        )
        try:
            checkpoint.validate()
        except HarnessCheckpointError as exc:
            raise HarnessCheckpointError("CHECKPOINT_INTEGRITY_FAILED:RECORD_INVALID") from exc
        if (
            checkpoint.checkpoint_id != str(row["checkpoint_id"])
            or checkpoint.project_id != str(row["project_id"])
            or checkpoint.conversation_id != str(row["conversation_id"])
            or checkpoint.task_id != str(row["task_id"])
            or checkpoint.schema_version != str(row["schema_version"])
            or checkpoint.created_at != str(row["created_at"])
        ):
            raise HarnessCheckpointError("CHECKPOINT_INTEGRITY_FAILED:SCOPE_MISMATCH")
        if checkpoint.fingerprint != str(row["checkpoint_sha256"]):
            raise HarnessCheckpointError("CHECKPOINT_INTEGRITY_FAILED:SHA256_MISMATCH")
        return checkpoint

    def save(self, checkpoint: HarnessCheckpoint) -> str:
        checkpoint.validate()
        if _as_datetime(checkpoint.created_at) > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise HarnessCheckpointError("CHECKPOINT_CREATED_AT_IN_FUTURE")
        self._assert_task_exists(checkpoint.task_id)
        payload = checkpoint.canonical_dict()
        fingerprint = checkpoint.fingerprint
        with self.task_store.connect() as conn:
            existing = conn.execute(
                "SELECT * FROM harness_checkpoints WHERE checkpoint_id = ?",
                (checkpoint.checkpoint_id,),
            ).fetchone()
            if existing is not None:
                stored = self._from_row(existing)
                if stored.fingerprint != fingerprint:
                    raise HarnessCheckpointError("CHECKPOINT_ID_CONFLICT")
                return fingerprint
            conn.execute(
                """
                INSERT INTO harness_checkpoints(
                    checkpoint_id,schema_version,project_id,conversation_id,task_id,
                    checkpoint_json,checkpoint_sha256,created_at
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    checkpoint.checkpoint_id,
                    checkpoint.schema_version,
                    checkpoint.project_id,
                    checkpoint.conversation_id,
                    checkpoint.task_id,
                    _canonical_json(payload),
                    fingerprint,
                    checkpoint.created_at,
                ),
            )
        return fingerprint

    def get(
        self,
        *,
        checkpoint_id: str,
        project_id: str,
    ) -> HarnessCheckpoint:
        checkpoint_key = _compact_id(checkpoint_id, "checkpoint_id")
        project = _compact_id(project_id, "project_id")
        with self.task_store.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM harness_checkpoints
                WHERE checkpoint_id = ? AND project_id = ?
                """,
                (checkpoint_key, project),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown harness checkpoint in project {project}: {checkpoint_key}")
        return self._from_row(row)

    def list_checkpoints(
        self,
        *,
        project_id: str,
        conversation_id: str | None = None,
        task_id: str | None = None,
    ) -> tuple[HarnessCheckpoint, ...]:
        project = _compact_id(project_id, "project_id")
        clauses = ["project_id = ?"]
        params: list[str] = [project]
        if conversation_id is not None:
            clauses.append("conversation_id = ?")
            params.append(_compact_id(conversation_id, "conversation_id"))
        if task_id is not None:
            clauses.append("task_id = ?")
            params.append(_compact_id(task_id, "task_id"))
        query = (
            "SELECT * FROM harness_checkpoints WHERE "
            + " AND ".join(clauses)
            + " ORDER BY created_at, checkpoint_id"
        )
        with self.task_store.connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return tuple(self._from_row(row) for row in rows)

    def latest(
        self,
        *,
        project_id: str,
        conversation_id: str,
        task_id: str,
    ) -> HarnessCheckpoint | None:
        project = _compact_id(project_id, "project_id")
        conversation = _compact_id(conversation_id, "conversation_id")
        task = _compact_id(task_id, "task_id")
        with self.task_store.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM harness_checkpoints
                WHERE project_id = ? AND conversation_id = ? AND task_id = ?
                ORDER BY created_at DESC, checkpoint_id DESC
                LIMIT 1
                """,
                (project, conversation, task),
            ).fetchone()
        return self._from_row(row) if row is not None else None

    def rehydration_anchor(
        self,
        *,
        project_id: str,
        conversation_id: str,
        task_id: str,
    ) -> dict[str, Any] | None:
        checkpoint = self.latest(
            project_id=project_id,
            conversation_id=conversation_id,
            task_id=task_id,
        )
        if checkpoint is None:
            return None
        return {
            "checkpoint": checkpoint.canonical_dict(),
            "integrity": {
                "content_hash": checkpoint.fingerprint,
                "source_ref_count": len(checkpoint.source_refs),
            },
        }
