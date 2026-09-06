from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from .asset_dependency import MAX_IMPACT_SEEDS
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

_DEPENDENCY_FINDING_LIMIT = 100
_UNRESOLVED_FINDING_STATUSES = ("open", "correlated", "investigating", "reopened")


def _read_correlation_events_query_only(
    config: MonitoringRuntimeConfig,
) -> tuple[CorrelationEvent, ...]:
    """Read a fixed evidence-bound sample without schema initialization or writes."""

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
            WHERE ce.evidence_ref IS NOT NULL
              AND EXISTS (
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


def _read_dependency_seeds_query_only(
    config: MonitoringRuntimeConfig,
) -> dict[str, object]:
    """Derive bounded impact seeds from unresolved findings without exposing identifiers."""

    path = config.database_path
    if path.is_symlink() or not path.is_file():
        return {
            "seed_asset_ids": (),
            "source_finding_count": 0,
            "ignored_seed_ref_count": 0,
            "seed_input_truncated": False,
        }

    enabled_ids = {asset.asset_id for asset in config.assets if asset.enabled}
    uri = path.resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=1.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    conn.execute("PRAGMA busy_timeout=1000")
    try:
        rows = conn.execute(
            """
            SELECT asset_refs_json
            FROM findings
            WHERE status IN ('open','correlated','investigating','reopened')
            ORDER BY CASE severity
                WHEN 'critical' THEN 4
                WHEN 'high' THEN 3
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 1
                ELSE 0
            END DESC,
            julianday(last_seen) DESC,
            finding_id DESC
            LIMIT ?
            """,
            (_DEPENDENCY_FINDING_LIMIT,),
        ).fetchall()
    finally:
        conn.close()

    selected: list[str] = []
    selected_set: set[str] = set()
    ignored = 0
    truncated = False
    for row in rows:
        try:
            raw_refs = json.loads(str(row["asset_refs_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MonitoringContractError("dependency seed asset references are invalid") from exc
        if not isinstance(raw_refs, list) or any(not isinstance(value, str) for value in raw_refs):
            raise MonitoringContractError("dependency seed asset references must be a string array")
        for asset_id in sorted(set(raw_refs)):
            if asset_id not in enabled_ids:
                ignored += 1
                continue
            if asset_id in selected_set:
                continue
            if len(selected) >= MAX_IMPACT_SEEDS:
                truncated = True
                continue
            selected.append(asset_id)
            selected_set.add(asset_id)

    return {
        "seed_asset_ids": tuple(selected),
        "source_finding_count": len(rows),
        "ignored_seed_ref_count": ignored,
        "seed_input_truncated": truncated,
    }


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
    dependency_seeds: dict[str, object] = {
        "seed_asset_ids": (),
        "source_finding_count": 0,
        "ignored_seed_ref_count": 0,
        "seed_input_truncated": False,
    }
    dependency_seed_data_state = "unavailable"
    data_state = "unavailable"
    if database_available:
        try:
            soc = read_model.soc(cutoff_at=current.isoformat())
            assets = read_model.assets()
            correlation_events = _read_correlation_events_query_only(config)
            dependency_seeds = _read_dependency_seeds_query_only(config)
            dependency_seed_data_state = "available"
            data_state = "available"
        except sqlite3.OperationalError:
            # Missing/incomplete durable storage is a read-side data gap, not a reason
            # to initialize or mutate the database from a browser request.
            soc = {}
            assets = {"items": []}
            correlation_events = ()
            dependency_seeds = {
                "seed_asset_ids": (),
                "source_finding_count": 0,
                "ignored_seed_ref_count": 0,
                "seed_input_truncated": False,
            }
            dependency_seed_data_state = "data_gap"
            data_state = "data_gap"

    payload = reduce_operator_posture(
        soc=soc,
        assets=assets,
        correlation_events=correlation_events,
        now=current,
        dependency_inventory=config.assets,
        dependencies=config.dependencies,
        dependency_seed_asset_ids=dependency_seeds["seed_asset_ids"],  # type: ignore[arg-type]
        dependency_seed_data_state=dependency_seed_data_state,
        dependency_source_finding_count=int(dependency_seeds["source_finding_count"]),
        dependency_ignored_seed_ref_count=int(dependency_seeds["ignored_seed_ref_count"]),
        dependency_seed_input_truncated=bool(dependency_seeds["seed_input_truncated"]),
    )
    payload["database_available"] = bool(database_available)
    payload["data_state"] = data_state
    return payload
