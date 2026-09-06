from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from .contracts import CanonicalEvent, MonitoringContractError
from .correlation_graph import CorrelationEvent
from .entity_context import ENTITY_CONTEXT_SCHEMA, EventEntityContext, EventEntityReference
from .operator_posture import (
    OPERATOR_POSTURE_ENTITY_LIMIT,
    OPERATOR_POSTURE_EVENT_LIMIT,
    reduce_operator_posture,
)
from .runtime_config import MonitoringRuntimeConfig
from .ui_read_model import SecurityMonitoringUIReadModel


def _read_correlation_events_query_only(
    config: MonitoringRuntimeConfig,
) -> tuple[CorrelationEvent, ...]:
    """Read a fixed recent correlation sample without schema initialization or writes."""

    path = config.database_path
    if path.is_symlink() or not path.is_file():
        return ()
    uri = path.resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=1.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    conn.execute("PRAGMA busy_timeout=1000")
    try:
        event_rows = conn.execute(
            """
            SELECT ce.event_id,ce.source_id,ce.source_type,ce.observed_at,
                   ce.category,ce.severity,ce.message_sha256,ce.parser_version,ce.evidence_ref
            FROM canonical_events ce
            WHERE EXISTS (
                SELECT 1 FROM event_entities ee WHERE ee.event_id=ce.event_id
            )
            ORDER BY julianday(ce.observed_at) DESC,ce.event_id DESC
            LIMIT ?
            """,
            (OPERATOR_POSTURE_EVENT_LIMIT,),
        ).fetchall()
        if not event_rows:
            return ()

        event_ids = tuple(str(row["event_id"]) for row in event_rows)
        placeholders = ",".join("?" for _ in event_ids)
        entity_rows = conn.execute(
            f"""
            SELECT event_id,kind,role,entity_ref,schema_version
            FROM event_entities
            WHERE event_id IN ({placeholders})
            ORDER BY event_id,kind,role,entity_ref
            LIMIT ?
            """,
            (*event_ids, OPERATOR_POSTURE_ENTITY_LIMIT + 1),
        ).fetchall()
    finally:
        conn.close()

    if len(entity_rows) > OPERATOR_POSTURE_ENTITY_LIMIT:
        raise MonitoringContractError("operator posture entity bound exceeded")

    grouped: dict[str, list[EventEntityReference]] = {event_id: [] for event_id in event_ids}
    for row in entity_rows:
        event_id = str(row["event_id"])
        if event_id not in grouped:
            continue
        if row["schema_version"] != ENTITY_CONTEXT_SCHEMA:
            raise MonitoringContractError("operator posture stored entity schema is invalid")
        grouped[event_id].append(
            EventEntityReference(
                kind=row["kind"],
                role=row["role"],
                entity_ref=row["entity_ref"],
            ).validate()
        )

    result: list[CorrelationEvent] = []
    for row in event_rows:
        event_id = str(row["event_id"])
        references = tuple(grouped.get(event_id, ()))
        if not references:
            raise MonitoringContractError("operator posture event lost entity context")
        event = CanonicalEvent(
            event_id=event_id,
            source_id=row["source_id"],
            source_type=row["source_type"],
            observed_at=row["observed_at"],
            category=row["category"],
            severity=row["severity"],
            message_sha256=row["message_sha256"],
            parser_version=row["parser_version"],
            evidence_ref=row["evidence_ref"],
        ).validate()
        context = EventEntityContext(event_id=event_id, references=references).validate()
        result.append(CorrelationEvent(event=event, context=context).validate())

    return tuple(sorted(result, key=lambda item: (item.observed, item.event.event_id)))


def safe_operator_posture_summary(
    config: MonitoringRuntimeConfig,
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    """Build final operator posture through bounded query-only reads and pure reducers."""

    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    read_model = SecurityMonitoringUIReadModel(config, config_state="configured")
    database_available = config.database_path.is_file() and not config.database_path.is_symlink()

    soc: dict[str, object] = {}
    assets: dict[str, object] = {"items": []}
    correlation_events: tuple[CorrelationEvent, ...] = ()
    data_state = "unavailable"
    if database_available:
        try:
            soc = read_model.soc(cutoff_at=current.isoformat())
            assets = read_model.assets()
            correlation_events = _read_correlation_events_query_only(config)
            data_state = "available"
        except sqlite3.OperationalError:
            # Missing/incomplete durable storage is a read-side data gap, not a reason
            # to initialize or mutate the database from a browser request.
            soc = {}
            assets = {"items": []}
            correlation_events = ()
            data_state = "data_gap"

    payload = reduce_operator_posture(
        soc=soc,
        assets=assets,
        correlation_events=correlation_events,
        now=current,
    )
    payload["database_available"] = bool(database_available)
    payload["data_state"] = data_state
    return payload
