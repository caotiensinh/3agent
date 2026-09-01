from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from .behavior_intelligence import (
    BehaviorAssessment,
    BehaviorBaselineConfig,
    DeterministicBehaviorAnalyzer,
)
from .contracts import CanonicalEvent, MonitoringContractError
from .correlation_graph import CorrelationEvent
from .dns_behavior import (
    DNS_BEHAVIOR_PARSER_VERSION,
    DNS_BEHAVIOR_SCHEMA,
    DNSBehaviorFeatures,
)
from .dns_behavior_storage import DNSBehaviorFeatureStore
from .entity_context import ENTITY_CONTEXT_SCHEMA, EventEntityContext, EventEntityReference
from .entity_context_storage import EventEntityContextStore
from .storage import MonitoringStore

MAX_BEHAVIOR_LOOKBACK_SECONDS = 30 * 24 * 3600
MAX_BEHAVIOR_CURRENT_WINDOW_SECONDS = 3600


@dataclass(frozen=True)
class BehaviorAnalysisWindow:
    starts_at: str
    ends_at: str

    def validate(self) -> "BehaviorAnalysisWindow":
        try:
            start = datetime.fromisoformat(str(self.starts_at or "").replace("Z", "+00:00"))
            end = datetime.fromisoformat(str(self.ends_at or "").replace("Z", "+00:00"))
        except ValueError as exc:
            raise MonitoringContractError("behavior window timestamps must be ISO-8601") from exc
        if start.tzinfo is None or end.tzinfo is None:
            raise MonitoringContractError("behavior window timestamps require timezone")
        if end <= start:
            raise MonitoringContractError("behavior window must have positive duration")
        if (end - start).total_seconds() > MAX_BEHAVIOR_CURRENT_WINDOW_SECONDS:
            raise MonitoringContractError("behavior current window exceeds one-hour bound")
        object.__setattr__(self, "starts_at", start.isoformat())
        object.__setattr__(self, "ends_at", end.isoformat())
        return self


@dataclass(frozen=True)
class BehaviorStoreConfig:
    lookback_seconds: int = 7 * 24 * 3600
    max_entity_rows: int = 100000

    def validate(self) -> "BehaviorStoreConfig":
        if not 3600 <= int(self.lookback_seconds) <= MAX_BEHAVIOR_LOOKBACK_SECONDS:
            raise MonitoringContractError("behavior lookback must be within 1 hour..30 days")
        if not 1 <= int(self.max_entity_rows) <= 500000:
            raise MonitoringContractError("behavior entity row bound is invalid")
        return self


class BehaviorStoreReader:
    """Bounded read-only bridge from MonitoringStore to behavior intelligence."""

    def __init__(
        self,
        *,
        store: MonitoringStore,
        entity_store: EventEntityContextStore,
        dns_store: DNSBehaviorFeatureStore,
        analyzer_config: BehaviorBaselineConfig | None = None,
        store_config: BehaviorStoreConfig | None = None,
    ):
        self.store = store
        self.entity_store = entity_store
        self.dns_store = dns_store
        self.analyzer_config = (analyzer_config or BehaviorBaselineConfig()).validate()
        self.store_config = (store_config or BehaviorStoreConfig()).validate()

    def _read_events(
        self,
        *,
        starts_at: str,
        ends_at: str,
        include_end: bool,
    ) -> tuple[CorrelationEvent, ...]:
        end_operator = "<=" if include_end else "<"
        with self.store.connect() as conn:
            event_rows = conn.execute(
                f"""
                SELECT ce.event_id,ce.source_id,ce.source_type,ce.observed_at,
                       ce.category,ce.severity,ce.message_sha256,ce.parser_version,ce.evidence_ref
                FROM canonical_events ce
                WHERE julianday(ce.observed_at) >= julianday(?)
                  AND julianday(ce.observed_at) {end_operator} julianday(?)
                  AND EXISTS (SELECT 1 FROM event_entities ee WHERE ee.event_id=ce.event_id)
                ORDER BY julianday(ce.observed_at),ce.event_id
                LIMIT ?
                """,
                (starts_at, ends_at, self.analyzer_config.max_events + 1),
            ).fetchall()
            if len(event_rows) > self.analyzer_config.max_events:
                raise MonitoringContractError("behavior store event bound exceeded")
            if not event_rows:
                return ()
            entity_rows = conn.execute(
                f"""
                SELECT ee.event_id,ee.kind,ee.role,ee.entity_ref,ee.schema_version
                FROM event_entities ee
                JOIN canonical_events ce ON ce.event_id=ee.event_id
                WHERE julianday(ce.observed_at) >= julianday(?)
                  AND julianday(ce.observed_at) {end_operator} julianday(?)
                ORDER BY julianday(ce.observed_at),ee.event_id,ee.kind,ee.role,ee.entity_ref
                LIMIT ?
                """,
                (starts_at, ends_at, self.store_config.max_entity_rows + 1),
            ).fetchall()
        if len(entity_rows) > self.store_config.max_entity_rows:
            raise MonitoringContractError("behavior store entity row bound exceeded")

        event_ids = {row["event_id"] for row in event_rows}
        grouped: dict[str, list[EventEntityReference]] = {event_id: [] for event_id in event_ids}
        for row in entity_rows:
            if row["event_id"] not in grouped:
                continue
            if row["schema_version"] != ENTITY_CONTEXT_SCHEMA:
                raise MonitoringContractError("stored behavior entity schema is invalid")
            grouped[row["event_id"]].append(
                EventEntityReference(
                    kind=row["kind"],
                    role=row["role"],
                    entity_ref=row["entity_ref"],
                ).validate()
            )

        result: list[CorrelationEvent] = []
        for row in event_rows:
            references = tuple(grouped.get(row["event_id"], ()))
            if not references:
                raise MonitoringContractError("behavior event lost persisted entity context")
            event = CanonicalEvent(
                event_id=row["event_id"],
                source_id=row["source_id"],
                source_type=row["source_type"],
                observed_at=row["observed_at"],
                category=row["category"],
                severity=row["severity"],
                message_sha256=row["message_sha256"],
                parser_version=row["parser_version"],
                evidence_ref=row["evidence_ref"],
            ).validate()
            context = EventEntityContext(
                event_id=event.event_id,
                references=references,
            ).validate()
            result.append(CorrelationEvent(event=event, context=context).validate())
        return tuple(result)

    def _read_current_dns_features(
        self,
        *,
        starts_at: str,
        ends_at: str,
    ) -> tuple[DNSBehaviorFeatures, ...]:
        with self.store.connect() as conn:
            rows = conn.execute(
                """
                SELECT dbf.*
                FROM dns_behavior_features dbf
                JOIN canonical_events ce ON ce.event_id=dbf.event_id
                WHERE julianday(ce.observed_at) >= julianday(?)
                  AND julianday(ce.observed_at) <= julianday(?)
                ORDER BY julianday(ce.observed_at),dbf.event_id
                LIMIT ?
                """,
                (starts_at, ends_at, self.analyzer_config.max_dns_features + 1),
            ).fetchall()
        if len(rows) > self.analyzer_config.max_dns_features:
            raise MonitoringContractError("behavior DNS feature row bound exceeded")
        result: list[DNSBehaviorFeatures] = []
        for row in rows:
            if row["schema_version"] != DNS_BEHAVIOR_SCHEMA:
                raise MonitoringContractError("stored behavior DNS schema is invalid")
            if row["parser_version"] != DNS_BEHAVIOR_PARSER_VERSION:
                raise MonitoringContractError("stored behavior DNS parser version is invalid")
            result.append(
                DNSBehaviorFeatures(
                    event_id=row["event_id"],
                    source_type=row["source_type"],
                    query_entity_ref=row["query_entity_ref"],
                    query_length=int(row["query_length"]),
                    label_count=int(row["label_count"]),
                    max_label_length=int(row["max_label_length"]),
                    shannon_entropy=float(row["shannon_entropy"]),
                    normalized_entropy=float(row["normalized_entropy"]),
                    digit_count=int(row["digit_count"]),
                    hyphen_count=int(row["hyphen_count"]),
                    answer_count=int(row["answer_count"]),
                    response_code=row["response_code"],
                    query_type=row["query_type"],
                    schema_version=row["schema_version"],
                    parser_version=row["parser_version"],
                ).validate()
            )
        return tuple(result)

    def read_inputs(
        self,
        window: BehaviorAnalysisWindow,
    ) -> tuple[tuple[CorrelationEvent, ...], tuple[CorrelationEvent, ...], tuple[DNSBehaviorFeatures, ...]]:
        bound = window.validate()
        self.entity_store.initialize()
        self.dns_store.initialize()
        start = datetime.fromisoformat(bound.starts_at)
        history_start = (start - timedelta(seconds=self.store_config.lookback_seconds)).isoformat()
        history = self._read_events(
            starts_at=history_start,
            ends_at=bound.starts_at,
            include_end=False,
        )
        current = self._read_events(
            starts_at=bound.starts_at,
            ends_at=bound.ends_at,
            include_end=True,
        )
        features = self._read_current_dns_features(
            starts_at=bound.starts_at,
            ends_at=bound.ends_at,
        )
        return current, history, features

    def analyze_window(self, window: BehaviorAnalysisWindow) -> tuple[BehaviorAssessment, ...]:
        current, history, features = self.read_inputs(window)
        return DeterministicBehaviorAnalyzer(self.analyzer_config).analyze(
            current_events=current,
            history_events=history,
            current_dns_features=features,
        )
