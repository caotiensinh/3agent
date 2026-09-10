from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .contracts import CanonicalEvent, MonitoringContractError
from .correlation_graph import (
    CorrelationEvent,
    CorrelationGraphConfig,
    DeterministicIncidentCorrelator,
    IncidentGraph,
)
from .correlation_support import (
    CorrelationSupportConfig,
    IncidentSupportingEvidence,
    attach_supporting_evidence,
)
from .entity_context import ENTITY_CONTEXT_SCHEMA, EventEntityContext, EventEntityReference
from .entity_context_storage import EventEntityContextStore
from .storage import MonitoringStore


@dataclass(frozen=True)
class CorrelationWindow:
    starts_at: str
    ends_at: str

    def validate(self) -> "CorrelationWindow":
        try:
            start = datetime.fromisoformat(str(self.starts_at or "").replace("Z", "+00:00"))
            end = datetime.fromisoformat(str(self.ends_at or "").replace("Z", "+00:00"))
        except ValueError as exc:
            raise MonitoringContractError("correlation window timestamps must be ISO-8601") from exc
        if start.tzinfo is None or end.tzinfo is None:
            raise MonitoringContractError("correlation window timestamps require timezone")
        if end < start:
            raise MonitoringContractError("correlation window ends_at precedes starts_at")
        object.__setattr__(self, "starts_at", start.isoformat())
        object.__setattr__(self, "ends_at", end.isoformat())
        return self


@dataclass(frozen=True)
class CorrelatedIncidentBundle:
    graph: IncidentGraph
    support: IncidentSupportingEvidence | None

    def public_dict(self) -> dict[str, object]:
        return {
            "graph": self.graph.public_dict(),
            "support": self.support.public_dict() if self.support is not None else None,
        }


class CorrelationStoreReader:
    """Read-only bounded bridge from MonitoringStore to the pure correlator."""

    def __init__(
        self,
        *,
        store: MonitoringStore,
        entity_store: EventEntityContextStore,
        config: CorrelationGraphConfig | None = None,
    ):
        self.store = store
        self.entity_store = entity_store
        self.config = (config or CorrelationGraphConfig()).validate()

    def read_window(self, window: CorrelationWindow) -> tuple[CorrelationEvent, ...]:
        bound = window.validate()
        starts_at = datetime.fromisoformat(bound.starts_at)
        ends_at = datetime.fromisoformat(bound.ends_at)
        if (ends_at - starts_at).total_seconds() > self.config.window_seconds:
            raise MonitoringContractError("correlation store query window exceeds configured time bound")
        self.entity_store.initialize()
        with self.store.connect() as conn:
            event_rows = conn.execute(
                """
                SELECT ce.event_id,ce.source_id,ce.source_type,ce.observed_at,
                       ce.category,ce.severity,ce.message_sha256,ce.parser_version,ce.evidence_ref
                FROM canonical_events ce
                WHERE julianday(ce.observed_at) >= julianday(?)
                  AND julianday(ce.observed_at) <= julianday(?)
                  AND EXISTS (
                      SELECT 1 FROM event_entities ee WHERE ee.event_id=ce.event_id
                  )
                ORDER BY julianday(ce.observed_at),ce.event_id
                LIMIT ?
                """,
                (bound.starts_at, bound.ends_at, self.config.max_events + 1),
            ).fetchall()
            if len(event_rows) > self.config.max_events:
                raise MonitoringContractError("correlation event bound exceeded while reading store")
            if not event_rows:
                return ()

            # Query by the same validated time window instead of constructing a
            # large unbounded IN clause. LIMIT+1 lets the reader fail closed if
            # the persisted entity set exceeds the configured graph budget.
            entity_rows = conn.execute(
                """
                SELECT ee.event_id,ee.kind,ee.role,ee.entity_ref,ee.schema_version
                FROM event_entities ee
                JOIN canonical_events ce ON ce.event_id=ee.event_id
                WHERE julianday(ce.observed_at) >= julianday(?)
                  AND julianday(ce.observed_at) <= julianday(?)
                ORDER BY julianday(ce.observed_at),ee.event_id,ee.kind,ee.role,ee.entity_ref
                LIMIT ?
                """,
                (bound.starts_at, bound.ends_at, self.config.max_entities + 1),
            ).fetchall()
        if len(entity_rows) > self.config.max_entities:
            raise MonitoringContractError("correlation entity bound exceeded while reading store")

        event_ids = {row["event_id"] for row in event_rows}
        grouped: dict[str, list[EventEntityReference]] = {event_id: [] for event_id in event_ids}
        for row in entity_rows:
            event_id = row["event_id"]
            if event_id not in grouped:
                continue
            if row["schema_version"] != ENTITY_CONTEXT_SCHEMA:
                raise MonitoringContractError("stored correlation entity schema is invalid")
            grouped[event_id].append(
                EventEntityReference(
                    kind=row["kind"],
                    role=row["role"],
                    entity_ref=row["entity_ref"],
                ).validate()
            )

        result: list[CorrelationEvent] = []
        for row in event_rows:
            event_id = row["event_id"]
            references = tuple(grouped.get(event_id, ()))
            if not references:
                raise MonitoringContractError("correlation event lost its persisted entity context")
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
        return tuple(result)

    def correlate_window(self, window: CorrelationWindow) -> tuple[IncidentGraph, ...]:
        events = self.read_window(window)
        return DeterministicIncidentCorrelator(self.config).correlate(events)

    def correlate_window_with_support(
        self,
        window: CorrelationWindow,
        *,
        support_config: CorrelationSupportConfig | None = None,
    ) -> tuple[CorrelatedIncidentBundle, ...]:
        """Return causal graphs plus separate fact-only operational support."""

        events = self.read_window(window)
        graphs = DeterministicIncidentCorrelator(self.config).correlate(events)
        if not graphs:
            return ()
        attachments = {
            item.graph_id: item
            for item in attach_supporting_evidence(
                graphs,
                events,
                config=support_config
                or CorrelationSupportConfig(window_seconds=self.config.window_seconds),
            )
        }
        return tuple(
            CorrelatedIncidentBundle(graph=graph, support=attachments.get(graph.graph_id))
            for graph in graphs
        )
