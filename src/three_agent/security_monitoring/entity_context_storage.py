from __future__ import annotations

import sqlite3

from .contracts import MonitoringContractError
from .entity_context import ENTITY_CONTEXT_SCHEMA, EventEntityContext, EventEntityReference
from .storage import MonitoringStore

ENTITY_CONTEXT_STORAGE_VERSION = 1

_ENTITY_SCHEMA = """
CREATE TABLE IF NOT EXISTS event_entities (
    event_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    role TEXT NOT NULL,
    entity_ref TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    PRIMARY KEY(event_id, kind, role, entity_ref),
    FOREIGN KEY(event_id) REFERENCES canonical_events(event_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_event_entities_ref ON event_entities(entity_ref, event_id);
CREATE INDEX IF NOT EXISTS idx_event_entities_event ON event_entities(event_id, role);
"""


class EventEntityContextStore:
    """Additive metadata extension over the existing MonitoringStore database."""

    def __init__(self, store: MonitoringStore):
        self.store = store

    def initialize(self) -> None:
        self.store.initialize()
        with self.store.connect() as conn:
            conn.executescript(_ENTITY_SCHEMA)
            conn.execute(
                "INSERT INTO schema_meta(key,value) VALUES('entity_context_schema_version',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(ENTITY_CONTEXT_STORAGE_VERSION),),
            )

    def schema_version(self) -> int:
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT value FROM schema_meta WHERE key='entity_context_schema_version'"
            ).fetchone()
        if row is None:
            raise RuntimeError("event entity context storage is not initialized")
        return int(row["value"])

    def put(self, context: EventEntityContext) -> None:
        validated = context.validate()
        with self.store.connect() as conn:
            event = conn.execute(
                "SELECT event_id FROM canonical_events WHERE event_id=?",
                (validated.event_id,),
            ).fetchone()
            if event is None:
                raise MonitoringContractError("entity context requires an existing canonical event")
            existing_rows = conn.execute(
                "SELECT kind,role,entity_ref,schema_version FROM event_entities WHERE event_id=? "
                "ORDER BY kind,role,entity_ref",
                (validated.event_id,),
            ).fetchall()
            existing = tuple(
                EventEntityReference(
                    kind=row["kind"], role=row["role"], entity_ref=row["entity_ref"]
                ).validate()
                for row in existing_rows
            )
            if existing and existing != validated.references:
                raise MonitoringContractError("event entity context mutation is forbidden")
            if existing:
                return
            try:
                conn.executemany(
                    "INSERT INTO event_entities(event_id,kind,role,entity_ref,schema_version) "
                    "VALUES(?,?,?,?,?)",
                    (
                        (
                            validated.event_id,
                            reference.kind,
                            reference.role,
                            reference.entity_ref,
                            ENTITY_CONTEXT_SCHEMA,
                        )
                        for reference in validated.references
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise MonitoringContractError("event entity context persistence failed") from exc

    def get(self, event_id: str) -> EventEntityContext | None:
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT kind,role,entity_ref,schema_version FROM event_entities WHERE event_id=? "
                "ORDER BY kind,role,entity_ref",
                (str(event_id),),
            ).fetchall()
        if not rows:
            return None
        schema_versions = {row["schema_version"] for row in rows}
        if schema_versions != {ENTITY_CONTEXT_SCHEMA}:
            raise MonitoringContractError("stored entity context schema is invalid")
        references = tuple(
            EventEntityReference(
                kind=row["kind"], role=row["role"], entity_ref=row["entity_ref"]
            ).validate()
            for row in rows
        )
        return EventEntityContext(event_id=str(event_id), references=references).validate()

    def event_ids_for_entity(self, entity_ref: str, *, limit: int = 1000) -> tuple[str, ...]:
        if not 1 <= int(limit) <= 10000:
            raise MonitoringContractError("entity lookup limit must be within 1..10000")
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT event_id FROM event_entities WHERE entity_ref=? "
                "ORDER BY event_id LIMIT ?",
                (str(entity_ref), int(limit)),
            ).fetchall()
        return tuple(row["event_id"] for row in rows)
