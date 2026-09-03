from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .store import TaskStore

HARNESS_EVENT_SCHEMA = "workspace-harness-event/v1"
HARNESS_MEMORY_SCHEMA = "workspace-harness-memory/v1"

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_LAYERS = frozenset({"M1", "M2", "M3", "M4", "M5"})
_TRUST_DOMAINS = frozenset({"trusted", "derived", "untrusted"})


class HarnessMemoryError(ValueError):
    """Harness memory input or persisted state violates a deterministic invariant."""


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise HarnessMemoryError("PAYLOAD_NOT_CANONICAL_JSON") from exc


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _compact_id(value: Any, field_name: str) -> str:
    text = str(value or "").strip()
    if not _ID_RE.fullmatch(text):
        raise HarnessMemoryError(f"INVALID_{field_name.upper()}")
    return text


def _single_line(value: Any, field_name: str, *, max_len: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or "\n" in text or "\r" in text:
        raise HarnessMemoryError(f"INVALID_{field_name.upper()}")
    return text


def _timestamp(value: Any, field_name: str) -> str:
    text = _single_line(value, field_name, max_len=64)
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise HarnessMemoryError(f"INVALID_{field_name.upper()}") from exc
    if parsed.tzinfo is None:
        raise HarnessMemoryError(f"{field_name.upper()}_MUST_BE_TIMEZONE_AWARE")
    return text


def _as_datetime(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    return datetime.fromisoformat(normalized)


@dataclass(frozen=True)
class HarnessEvent:
    event_id: str
    project_id: str
    conversation_id: str
    event_type: str
    source_type: str
    source_ref: str
    trust_domain: str
    payload: dict[str, Any]
    task_id: str | None = None
    created_at: str = field(default_factory=_now)
    schema_version: str = HARNESS_EVENT_SCHEMA

    def validate(self) -> "HarnessEvent":
        _compact_id(self.event_id, "event_id")
        _compact_id(self.project_id, "project_id")
        _compact_id(self.conversation_id, "conversation_id")
        _compact_id(self.event_type, "event_type")
        _compact_id(self.source_type, "source_type")
        _single_line(self.source_ref, "source_ref", max_len=512)
        if self.trust_domain not in _TRUST_DOMAINS:
            raise HarnessMemoryError("INVALID_TRUST_DOMAIN")
        if self.task_id is not None:
            _compact_id(self.task_id, "task_id")
        if not isinstance(self.payload, dict):
            raise HarnessMemoryError("EVENT_PAYLOAD_MUST_BE_OBJECT")
        _canonical_json(self.payload)
        _timestamp(self.created_at, "created_at")
        if self.schema_version != HARNESS_EVENT_SCHEMA:
            raise HarnessMemoryError("EVENT_SCHEMA_VERSION_MISMATCH")
        return self

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "project_id": self.project_id,
            "conversation_id": self.conversation_id,
            "task_id": self.task_id,
            "event_type": self.event_type,
            "source_type": self.source_type,
            "source_ref": self.source_ref,
            "trust_domain": self.trust_domain,
            "payload": self.payload,
            "created_at": self.created_at,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())


@dataclass(frozen=True)
class MemoryRecord:
    revision_id: str
    memory_id: str
    project_id: str
    layer: str
    kind: str
    content: str
    provenance_event_ids: tuple[str, ...]
    trust_domain: str
    confidence: float
    valid_from: str
    conversation_id: str | None = None
    task_id: str | None = None
    valid_until: str | None = None
    supersedes_revision_id: str | None = None
    created_at: str = field(default_factory=_now)
    schema_version: str = HARNESS_MEMORY_SCHEMA

    def validate(self) -> "MemoryRecord":
        _compact_id(self.revision_id, "revision_id")
        _compact_id(self.memory_id, "memory_id")
        _compact_id(self.project_id, "project_id")
        if self.layer not in _LAYERS:
            raise HarnessMemoryError("INVALID_MEMORY_LAYER")
        _compact_id(self.kind, "memory_kind")
        if not isinstance(self.content, str) or not self.content.strip():
            raise HarnessMemoryError("MEMORY_CONTENT_REQUIRED")
        if self.trust_domain not in _TRUST_DOMAINS:
            raise HarnessMemoryError("INVALID_TRUST_DOMAIN")
        if not isinstance(self.confidence, (int, float)) or isinstance(self.confidence, bool):
            raise HarnessMemoryError("INVALID_MEMORY_CONFIDENCE")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise HarnessMemoryError("INVALID_MEMORY_CONFIDENCE")
        if not self.provenance_event_ids:
            raise HarnessMemoryError("MEMORY_PROVENANCE_REQUIRED")
        if len(set(self.provenance_event_ids)) != len(self.provenance_event_ids):
            raise HarnessMemoryError("DUPLICATE_MEMORY_PROVENANCE")
        for event_id in self.provenance_event_ids:
            _compact_id(event_id, "provenance_event_id")
        if self.conversation_id is not None:
            _compact_id(self.conversation_id, "conversation_id")
        if self.task_id is not None:
            _compact_id(self.task_id, "task_id")
        if self.supersedes_revision_id is not None:
            _compact_id(self.supersedes_revision_id, "supersedes_revision_id")
            if self.supersedes_revision_id == self.revision_id:
                raise HarnessMemoryError("MEMORY_CANNOT_SUPERSEDE_ITSELF")
        start = _timestamp(self.valid_from, "valid_from")
        _timestamp(self.created_at, "created_at")
        if self.valid_until is not None:
            end = _timestamp(self.valid_until, "valid_until")
            if _as_datetime(end) <= _as_datetime(start):
                raise HarnessMemoryError("MEMORY_VALID_UNTIL_NOT_AFTER_VALID_FROM")
        if self.schema_version != HARNESS_MEMORY_SCHEMA:
            raise HarnessMemoryError("MEMORY_SCHEMA_VERSION_MISMATCH")
        return self

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "revision_id": self.revision_id,
            "memory_id": self.memory_id,
            "project_id": self.project_id,
            "conversation_id": self.conversation_id,
            "task_id": self.task_id,
            "layer": self.layer,
            "kind": self.kind,
            "content": self.content,
            "provenance_event_ids": list(self.provenance_event_ids),
            "trust_domain": self.trust_domain,
            "confidence": float(self.confidence),
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "supersedes_revision_id": self.supersedes_revision_id,
            "created_at": self.created_at,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())


class HarnessMemoryStore:
    """Durable M0-M5 memory foundation backed by the existing WorkSpace SQLite DB.

    Raw events and memory revisions are immutable evidence. This store never
    grants capabilities; TaskContract and TaskCapabilityAuthority remain the
    only execution-authority path.
    """

    def __init__(self, task_store: TaskStore):
        if not isinstance(task_store, TaskStore):
            raise TypeError("task_store must be TaskStore")
        self.task_store = task_store
        self.initialize()

    def initialize(self) -> None:
        with self.task_store.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS harness_events (
                    event_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    conversation_id TEXT NOT NULL,
                    task_id TEXT,
                    event_type TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    source_ref TEXT NOT NULL,
                    trust_domain TEXT NOT NULL
                        CHECK(trust_domain IN ('trusted','derived','untrusted')),
                    payload_json TEXT NOT NULL,
                    event_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_harness_events_scope
                    ON harness_events(project_id, conversation_id, task_id, created_at);

                CREATE TABLE IF NOT EXISTS harness_memories (
                    revision_id TEXT PRIMARY KEY,
                    memory_id TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    conversation_id TEXT,
                    task_id TEXT,
                    layer TEXT NOT NULL CHECK(layer IN ('M1','M2','M3','M4','M5')),
                    kind TEXT NOT NULL,
                    content TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    provenance_json TEXT NOT NULL,
                    trust_domain TEXT NOT NULL
                        CHECK(trust_domain IN ('trusted','derived','untrusted')),
                    confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
                    valid_from TEXT NOT NULL,
                    valid_until TEXT,
                    supersedes_revision_id TEXT,
                    record_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(supersedes_revision_id) REFERENCES harness_memories(revision_id)
                );
                CREATE INDEX IF NOT EXISTS idx_harness_memories_scope
                    ON harness_memories(project_id, conversation_id, task_id, layer, memory_id);
                CREATE INDEX IF NOT EXISTS idx_harness_memories_chain
                    ON harness_memories(memory_id, supersedes_revision_id, valid_from);
                CREATE UNIQUE INDEX IF NOT EXISTS uq_harness_memories_predecessor
                    ON harness_memories(supersedes_revision_id)
                    WHERE supersedes_revision_id IS NOT NULL;

                CREATE TRIGGER IF NOT EXISTS harness_events_no_update
                BEFORE UPDATE ON harness_events
                BEGIN
                    SELECT RAISE(ABORT, 'harness events are append-only');
                END;
                CREATE TRIGGER IF NOT EXISTS harness_events_no_delete
                BEFORE DELETE ON harness_events
                BEGIN
                    SELECT RAISE(ABORT, 'harness events are append-only');
                END;
                CREATE TRIGGER IF NOT EXISTS harness_memories_no_update
                BEFORE UPDATE ON harness_memories
                BEGIN
                    SELECT RAISE(ABORT, 'harness memory revisions are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS harness_memories_no_delete
                BEFORE DELETE ON harness_memories
                BEGIN
                    SELECT RAISE(ABORT, 'harness memory revisions are immutable');
                END;
                """
            )

    def _assert_task_exists(self, task_id: str | None) -> None:
        if task_id is None:
            return
        try:
            self.task_store.get_task(task_id)
        except KeyError as exc:
            raise HarnessMemoryError("MEMORY_TASK_SCOPE_UNKNOWN") from exc

    @staticmethod
    def _event_from_row(row: sqlite3.Row) -> HarnessEvent:
        try:
            payload = json.loads(str(row["payload_json"]))
        except (json.JSONDecodeError, TypeError) as exc:
            raise HarnessMemoryError("EVENT_INTEGRITY_FAILED:PAYLOAD_JSON_INVALID") from exc
        event = HarnessEvent(
            event_id=str(row["event_id"]),
            project_id=str(row["project_id"]),
            conversation_id=str(row["conversation_id"]),
            task_id=str(row["task_id"]) if row["task_id"] is not None else None,
            event_type=str(row["event_type"]),
            source_type=str(row["source_type"]),
            source_ref=str(row["source_ref"]),
            trust_domain=str(row["trust_domain"]),
            payload=payload,
            created_at=str(row["created_at"]),
            schema_version=str(row["schema_version"]),
        )
        try:
            event.validate()
        except HarnessMemoryError as exc:
            raise HarnessMemoryError("EVENT_INTEGRITY_FAILED:INVALID_RECORD") from exc
        if event.fingerprint != str(row["event_sha256"]):
            raise HarnessMemoryError("EVENT_INTEGRITY_FAILED:SHA256_MISMATCH")
        return event

    @staticmethod
    def _memory_from_row(row: sqlite3.Row) -> MemoryRecord:
        try:
            provenance = json.loads(str(row["provenance_json"]))
        except (json.JSONDecodeError, TypeError) as exc:
            raise HarnessMemoryError("MEMORY_INTEGRITY_FAILED:PROVENANCE_JSON_INVALID") from exc
        if not isinstance(provenance, list):
            raise HarnessMemoryError("MEMORY_INTEGRITY_FAILED:PROVENANCE_NOT_LIST")
        record = MemoryRecord(
            revision_id=str(row["revision_id"]),
            memory_id=str(row["memory_id"]),
            project_id=str(row["project_id"]),
            conversation_id=(
                str(row["conversation_id"]) if row["conversation_id"] is not None else None
            ),
            task_id=str(row["task_id"]) if row["task_id"] is not None else None,
            layer=str(row["layer"]),
            kind=str(row["kind"]),
            content=str(row["content"]),
            provenance_event_ids=tuple(str(item) for item in provenance),
            trust_domain=str(row["trust_domain"]),
            confidence=float(row["confidence"]),
            valid_from=str(row["valid_from"]),
            valid_until=str(row["valid_until"]) if row["valid_until"] is not None else None,
            supersedes_revision_id=(
                str(row["supersedes_revision_id"])
                if row["supersedes_revision_id"] is not None
                else None
            ),
            created_at=str(row["created_at"]),
            schema_version=str(row["schema_version"]),
        )
        try:
            record.validate()
        except HarnessMemoryError as exc:
            raise HarnessMemoryError("MEMORY_INTEGRITY_FAILED:INVALID_RECORD") from exc
        content_sha = "sha256:" + hashlib.sha256(record.content.encode("utf-8")).hexdigest()
        if content_sha != str(row["content_sha256"]):
            raise HarnessMemoryError("MEMORY_INTEGRITY_FAILED:CONTENT_SHA256_MISMATCH")
        if record.fingerprint != str(row["record_sha256"]):
            raise HarnessMemoryError("MEMORY_INTEGRITY_FAILED:RECORD_SHA256_MISMATCH")
        return record

    def append_event(self, event: HarnessEvent) -> str:
        event.validate()
        self._assert_task_exists(event.task_id)
        fingerprint = event.fingerprint
        with self.task_store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT * FROM harness_events WHERE event_id = ?",
                (event.event_id,),
            ).fetchone()
            if existing is not None:
                stored = self._event_from_row(existing)
                if stored.fingerprint != fingerprint:
                    raise HarnessMemoryError("EVENT_ID_CONFLICT")
                return fingerprint
            conn.execute(
                """
                INSERT INTO harness_events(
                    event_id,schema_version,project_id,conversation_id,task_id,
                    event_type,source_type,source_ref,trust_domain,payload_json,
                    event_sha256,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    event.event_id,
                    event.schema_version,
                    event.project_id,
                    event.conversation_id,
                    event.task_id,
                    event.event_type,
                    event.source_type,
                    event.source_ref,
                    event.trust_domain,
                    _canonical_json(event.payload),
                    fingerprint,
                    event.created_at,
                ),
            )
        return fingerprint

    def get_event(self, event_id: str) -> HarnessEvent:
        event_key = _compact_id(event_id, "event_id")
        with self.task_store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM harness_events WHERE event_id = ?",
                (event_key,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown harness event: {event_key}")
        return self._event_from_row(row)

    def list_events(
        self,
        *,
        project_id: str,
        conversation_id: str | None = None,
        task_id: str | None = None,
    ) -> tuple[HarnessEvent, ...]:
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
            "SELECT * FROM harness_events WHERE "
            + " AND ".join(clauses)
            + " ORDER BY created_at, event_id"
        )
        with self.task_store.connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return tuple(self._event_from_row(row) for row in rows)

    def _provenance_events(self, record: MemoryRecord) -> tuple[HarnessEvent, ...]:
        events: list[HarnessEvent] = []
        for event_id in record.provenance_event_ids:
            try:
                event = self.get_event(event_id)
            except KeyError as exc:
                raise HarnessMemoryError("MEMORY_PROVENANCE_EVENT_MISSING") from exc
            if event.project_id != record.project_id:
                raise HarnessMemoryError("MEMORY_PROVENANCE_PROJECT_SCOPE_MISMATCH")
            if record.conversation_id is not None and event.conversation_id != record.conversation_id:
                raise HarnessMemoryError("MEMORY_PROVENANCE_CONVERSATION_SCOPE_MISMATCH")
            if record.task_id is not None and event.task_id != record.task_id:
                raise HarnessMemoryError("MEMORY_PROVENANCE_TASK_SCOPE_MISMATCH")
            events.append(event)
        return tuple(events)

    def _validate_memory_admission(self, record: MemoryRecord) -> None:
        record.validate()
        self._assert_task_exists(record.task_id)
        events = self._provenance_events(record)
        if record.trust_domain == "trusted" and any(
            event.trust_domain != "trusted" for event in events
        ):
            raise HarnessMemoryError("MEMORY_TRUST_ESCALATION_FORBIDDEN")
        if record.layer == "M4" or record.kind.lower() == "procedure":
            if record.trust_domain != "trusted":
                raise HarnessMemoryError("PROCEDURAL_MEMORY_REQUIRES_TRUSTED_DOMAIN")
            if any(event.trust_domain != "trusted" for event in events):
                raise HarnessMemoryError("PROCEDURAL_MEMORY_REQUIRES_TRUSTED_PROVENANCE")

    def remember(self, record: MemoryRecord) -> str:
        self._validate_memory_admission(record)
        fingerprint = record.fingerprint
        with self.task_store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT * FROM harness_memories WHERE revision_id = ?",
                (record.revision_id,),
            ).fetchone()
            if existing is not None:
                stored = self._memory_from_row(existing)
                if stored.fingerprint != fingerprint:
                    raise HarnessMemoryError("MEMORY_REVISION_ID_CONFLICT")
                return fingerprint

            history = conn.execute(
                """
                SELECT * FROM harness_memories
                WHERE memory_id = ? AND project_id = ?
                ORDER BY valid_from, created_at, revision_id
                """,
                (record.memory_id, record.project_id),
            ).fetchall()
            if record.supersedes_revision_id is None:
                if history:
                    raise HarnessMemoryError("MEMORY_REVISION_REQUIRES_SUPERSEDES")
            else:
                predecessor = conn.execute(
                    "SELECT * FROM harness_memories WHERE revision_id = ?",
                    (record.supersedes_revision_id,),
                ).fetchone()
                if predecessor is None:
                    raise HarnessMemoryError("SUPERSEDED_MEMORY_REVISION_MISSING")
                previous = self._memory_from_row(predecessor)
                if previous.memory_id != record.memory_id:
                    raise HarnessMemoryError("MEMORY_SUPERSESSION_ID_MISMATCH")
                if previous.project_id != record.project_id:
                    raise HarnessMemoryError("MEMORY_SUPERSESSION_PROJECT_SCOPE_MISMATCH")
                if (
                    previous.layer != record.layer
                    or previous.kind != record.kind
                    or previous.conversation_id != record.conversation_id
                    or previous.task_id != record.task_id
                ):
                    raise HarnessMemoryError("MEMORY_SUPERSESSION_SCOPE_MISMATCH")
                if _as_datetime(record.valid_from) <= _as_datetime(previous.valid_from):
                    raise HarnessMemoryError("MEMORY_SUPERSESSION_TIME_NOT_FORWARD")
                child = conn.execute(
                    """
                    SELECT revision_id FROM harness_memories
                    WHERE supersedes_revision_id = ?
                    LIMIT 1
                    """,
                    (record.supersedes_revision_id,),
                ).fetchone()
                if child is not None:
                    raise HarnessMemoryError("MEMORY_SUPERSESSION_FORK_FORBIDDEN")

            content_sha = "sha256:" + hashlib.sha256(record.content.encode("utf-8")).hexdigest()
            try:
                conn.execute(
                    """
                    INSERT INTO harness_memories(
                        revision_id,memory_id,schema_version,project_id,conversation_id,
                        task_id,layer,kind,content,content_sha256,provenance_json,
                        trust_domain,confidence,valid_from,valid_until,
                        supersedes_revision_id,record_sha256,created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record.revision_id,
                        record.memory_id,
                        record.schema_version,
                        record.project_id,
                        record.conversation_id,
                        record.task_id,
                        record.layer,
                        record.kind,
                        record.content,
                        content_sha,
                        _canonical_json(list(record.provenance_event_ids)),
                        record.trust_domain,
                        float(record.confidence),
                        record.valid_from,
                        record.valid_until,
                        record.supersedes_revision_id,
                        fingerprint,
                        record.created_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                if record.supersedes_revision_id is not None:
                    raise HarnessMemoryError("MEMORY_SUPERSESSION_FORK_FORBIDDEN") from exc
                raise
        return fingerprint

    def get_revision(self, revision_id: str) -> MemoryRecord:
        revision_key = _compact_id(revision_id, "revision_id")
        with self.task_store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM harness_memories WHERE revision_id = ?",
                (revision_key,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown harness memory revision: {revision_key}")
        return self._memory_from_row(row)

    def memory_history(self, *, memory_id: str, project_id: str) -> tuple[MemoryRecord, ...]:
        memory_key = _compact_id(memory_id, "memory_id")
        project = _compact_id(project_id, "project_id")
        with self.task_store.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM harness_memories
                WHERE memory_id = ? AND project_id = ?
                ORDER BY valid_from, created_at, revision_id
                """,
                (memory_key, project),
            ).fetchall()
        return tuple(self._memory_from_row(row) for row in rows)

    def effective_valid_until(self, revision_id: str) -> str | None:
        record = self.get_revision(revision_id)
        with self.task_store.connect() as conn:
            child_row = conn.execute(
                """
                SELECT * FROM harness_memories
                WHERE supersedes_revision_id = ?
                ORDER BY valid_from, revision_id
                LIMIT 1
                """,
                (record.revision_id,),
            ).fetchone()
        child_start = None
        if child_row is not None:
            child = self._memory_from_row(child_row)
            child_start = child.valid_from
        if record.valid_until is None:
            return child_start
        if child_start is None:
            return record.valid_until
        return (
            record.valid_until
            if _as_datetime(record.valid_until) <= _as_datetime(child_start)
            else child_start
        )

    def memory_at(
        self,
        *,
        memory_id: str,
        project_id: str,
        at: str,
    ) -> MemoryRecord | None:
        point = _as_datetime(_timestamp(at, "at"))
        history = self.memory_history(memory_id=memory_id, project_id=project_id)
        matches: list[MemoryRecord] = []
        for record in history:
            start = _as_datetime(record.valid_from)
            end_text = self.effective_valid_until(record.revision_id)
            end = _as_datetime(end_text) if end_text is not None else None
            if start <= point and (end is None or point < end):
                matches.append(record)
        if len(matches) > 1:
            raise HarnessMemoryError("MEMORY_TEMPORAL_OVERLAP")
        return matches[0] if matches else None

    def current_memory(self, *, memory_id: str, project_id: str) -> MemoryRecord | None:
        return self.memory_at(memory_id=memory_id, project_id=project_id, at=_now())

    def list_current(
        self,
        *,
        project_id: str,
        conversation_id: str | None = None,
        layer: str | None = None,
    ) -> tuple[MemoryRecord, ...]:
        project = _compact_id(project_id, "project_id")
        conversation = (
            _compact_id(conversation_id, "conversation_id")
            if conversation_id is not None
            else None
        )
        if layer is not None and layer not in _LAYERS:
            raise HarnessMemoryError("INVALID_MEMORY_LAYER")
        with self.task_store.connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT memory_id FROM harness_memories WHERE project_id = ?",
                (project,),
            ).fetchall()
        result: list[MemoryRecord] = []
        for row in rows:
            current = self.current_memory(memory_id=str(row["memory_id"]), project_id=project)
            if current is None:
                continue
            if conversation is not None and current.conversation_id != conversation:
                continue
            if layer is not None and current.layer != layer:
                continue
            result.append(current)
        result.sort(key=lambda item: (item.layer, item.memory_id, item.revision_id))
        return tuple(result)
