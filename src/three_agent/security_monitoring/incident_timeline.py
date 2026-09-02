from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .contracts import MonitoringContractError, SEVERITIES, sha256_fingerprint
from .correlation_graph import (
    CorrelationEvent,
    CorrelationGraphConfig,
    DeterministicIncidentCorrelator,
    IncidentGraph,
    STAGE_ORDER,
)

INCIDENT_TIMELINE_SCHEMA = "workspace-security-monitoring/incident-timeline-v1"
INCIDENT_TIMELINE_ENTRY_SCHEMA = "workspace-security-monitoring/incident-timeline-entry-v1"
MAX_INCIDENT_TIMELINE_EVENTS = 256
MAX_INCIDENT_TIMELINE_ENTITIES = 4096
MAX_INCIDENT_TIMELINE_EDGES = 2048
INCIDENT_TIMELINE_WINDOW_SECONDS = 900


@dataclass(frozen=True)
class IncidentTimelineEntry:
    event_id: str
    graph_ids: tuple[str, ...]
    observed_at: str
    stage: str
    source_type: str
    category: str
    severity: str
    evidence_ref: str
    entity_refs: tuple[str, ...]
    schema_version: str = INCIDENT_TIMELINE_ENTRY_SCHEMA

    def validate(self) -> "IncidentTimelineEntry":
        if self.schema_version != INCIDENT_TIMELINE_ENTRY_SCHEMA:
            raise MonitoringContractError("unsupported incident timeline entry schema")
        if not self.event_id:
            raise MonitoringContractError("incident timeline entry requires event_id")
        if not self.graph_ids or tuple(sorted(set(self.graph_ids))) != self.graph_ids:
            raise MonitoringContractError("incident timeline entry graph_ids must be sorted and unique")
        if self.stage not in STAGE_ORDER:
            raise MonitoringContractError("incident timeline entry stage is invalid")
        if self.severity not in SEVERITIES:
            raise MonitoringContractError("incident timeline entry severity is invalid")
        if not self.evidence_ref:
            raise MonitoringContractError("incident timeline entry requires evidence_ref")
        if tuple(sorted(set(self.entity_refs))) != self.entity_refs:
            raise MonitoringContractError("incident timeline entry entity_refs must be sorted and unique")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "graph_ids": list(self.graph_ids),
            "observed_at": self.observed_at,
            "stage": self.stage,
            "source_type": self.source_type,
            "category": self.category,
            "severity": self.severity,
            "evidence_ref": self.evidence_ref,
            "entity_refs": list(self.entity_refs),
        }


@dataclass(frozen=True)
class IncidentTimeline:
    entry_count: int
    graph_count: int
    entries: tuple[IncidentTimelineEntry, ...]
    incident_graphs: tuple[IncidentGraph, ...]
    graph_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    entity_refs: tuple[str, ...]
    stage_types: tuple[str, ...]
    first_seen: str
    last_seen: str
    reason_codes: tuple[str, ...]
    authority: str = "advisory"
    schema_version: str = INCIDENT_TIMELINE_SCHEMA

    def validate(self) -> "IncidentTimeline":
        if self.schema_version != INCIDENT_TIMELINE_SCHEMA:
            raise MonitoringContractError("unsupported incident timeline schema")
        if self.authority != "advisory":
            raise MonitoringContractError("incident timeline must remain advisory")
        if not 1 <= self.entry_count <= MAX_INCIDENT_TIMELINE_EVENTS:
            raise MonitoringContractError("incident timeline entry_count is out of bounds")
        if self.entry_count != len(self.entries):
            raise MonitoringContractError("incident timeline entry_count mismatch")
        if not 1 <= self.graph_count <= MAX_INCIDENT_TIMELINE_EVENTS:
            raise MonitoringContractError("incident timeline graph_count is out of bounds")
        if self.graph_count != len(self.incident_graphs) or self.graph_count != len(self.graph_ids):
            raise MonitoringContractError("incident timeline graph_count mismatch")
        if tuple(graph.graph_id for graph in self.incident_graphs) != self.graph_ids:
            raise MonitoringContractError("incident timeline graph_ids do not match graph order")
        if len(set(self.graph_ids)) != len(self.graph_ids):
            raise MonitoringContractError("incident timeline graph_ids must be unique")
        if tuple(sorted(set(self.evidence_refs))) != self.evidence_refs or not self.evidence_refs:
            raise MonitoringContractError("incident timeline evidence_refs must be sorted, unique and non-empty")
        if tuple(sorted(set(self.entity_refs))) != self.entity_refs:
            raise MonitoringContractError("incident timeline entity_refs must be sorted and unique")
        if len(self.entity_refs) > MAX_INCIDENT_TIMELINE_ENTITIES:
            raise MonitoringContractError("incident timeline entity bound exceeded")
        if not self.stage_types or any(stage not in STAGE_ORDER for stage in self.stage_types):
            raise MonitoringContractError("incident timeline stage_types are invalid")
        if self.stage_types != tuple(stage for stage in STAGE_ORDER if stage in set(self.stage_types)):
            raise MonitoringContractError("incident timeline stage_types must use canonical order")
        if not self.first_seen or not self.last_seen or self.first_seen > self.last_seen:
            raise MonitoringContractError("incident timeline time range is invalid")
        if not self.reason_codes:
            raise MonitoringContractError("incident timeline requires reason codes")

        previous_key: tuple[str, str] | None = None
        graph_ids = set(self.graph_ids)
        event_ids: set[str] = set()
        for entry in self.entries:
            entry.validate()
            key = (entry.observed_at, entry.event_id)
            if previous_key is not None and key < previous_key:
                raise MonitoringContractError("incident timeline entries must be chronologically ordered")
            previous_key = key
            if entry.event_id in event_ids:
                raise MonitoringContractError("incident timeline event_ids must be unique")
            event_ids.add(entry.event_id)
            if not set(entry.graph_ids) <= graph_ids:
                raise MonitoringContractError("incident timeline entry references unknown graph")
            if entry.evidence_ref not in self.evidence_refs:
                raise MonitoringContractError("incident timeline entry evidence is outside timeline evidence set")

        correlated_ids = {event_id for graph in self.incident_graphs for event_id in graph.event_ids}
        if event_ids != correlated_ids:
            raise MonitoringContractError("incident timeline entries must exactly cover correlated events")
        if self.entries[0].observed_at != self.first_seen or self.entries[-1].observed_at != self.last_seen:
            raise MonitoringContractError("incident timeline time bounds must match ordered entries")
        for graph in self.incident_graphs:
            if graph.authority != "advisory":
                raise MonitoringContractError("incident timeline graph authority must remain advisory")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "entry_count": self.entry_count,
            "graph_count": self.graph_count,
            "entries": [entry.public_dict() for entry in self.entries],
            "incident_graphs": [graph.public_dict() for graph in self.incident_graphs],
            "graph_ids": list(self.graph_ids),
            "evidence_refs": list(self.evidence_refs),
            "entity_refs": list(self.entity_refs),
            "stage_types": list(self.stage_types),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "reason_codes": list(self.reason_codes),
            "authority": self.authority,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


def _event_identity(item: CorrelationEvent) -> tuple[object, ...]:
    return (
        item.event.event_id,
        item.event.source_id,
        item.event.source_type,
        item.event.observed_at,
        item.event.category,
        item.event.severity,
        item.event.message_sha256,
        item.event.parser_version,
        item.event.evidence_ref,
        tuple(item.context.references),
    )


def build_incident_timeline(events: Iterable[CorrelationEvent]) -> IncidentTimeline:
    """Build a bounded timeline only from events with deterministic incident linkage.

    The function is local, pure and evidence-bound. It never acquires new evidence,
    invokes a model, opens a network connection or manufactures an incident from
    uncorrelated events. Sensitive identities remain typed hashed entity references.
    """

    unique: dict[str, CorrelationEvent] = {}
    for raw in events:
        if not isinstance(raw, CorrelationEvent):
            raise MonitoringContractError("incident timeline accepts CorrelationEvent only")
        item = raw.validate()
        if item.stage is None:
            raise MonitoringContractError("incident timeline rejects unclassified correlation stages")
        if item.event.evidence_ref is None:
            raise MonitoringContractError("incident timeline requires evidence_ref on every event")
        previous = unique.get(item.event.event_id)
        if previous is not None:
            if _event_identity(previous) != _event_identity(item):
                raise MonitoringContractError("duplicate event_id has conflicting timeline evidence")
            continue
        unique[item.event.event_id] = item
        if len(unique) > MAX_INCIDENT_TIMELINE_EVENTS:
            raise MonitoringContractError("incident timeline event bound exceeded")

    if not unique:
        raise MonitoringContractError("incident timeline requires normalized evidence")

    ordered = tuple(sorted(unique.values(), key=lambda item: (item.observed, item.event.event_id)))
    total_entities = sum(len(item.context.references) for item in ordered)
    if total_entities > MAX_INCIDENT_TIMELINE_ENTITIES:
        raise MonitoringContractError("incident timeline entity bound exceeded")

    config = CorrelationGraphConfig(
        window_seconds=INCIDENT_TIMELINE_WINDOW_SECONDS,
        max_events=MAX_INCIDENT_TIMELINE_EVENTS,
        max_entities=MAX_INCIDENT_TIMELINE_ENTITIES,
        max_edges=MAX_INCIDENT_TIMELINE_EDGES,
    )
    graphs = DeterministicIncidentCorrelator(config).correlate(ordered)
    if not graphs:
        raise MonitoringContractError("incident timeline requires deterministically correlated incident evidence")

    graph_ids_by_event: dict[str, list[str]] = {}
    correlated_event_ids: set[str] = set()
    for graph in graphs:
        for event_id in graph.event_ids:
            correlated_event_ids.add(event_id)
            graph_ids_by_event.setdefault(event_id, []).append(graph.graph_id)

    correlated = tuple(item for item in ordered if item.event.event_id in correlated_event_ids)
    entries = tuple(
        IncidentTimelineEntry(
            event_id=item.event.event_id,
            graph_ids=tuple(sorted(graph_ids_by_event[item.event.event_id])),
            observed_at=item.event.observed_at,
            stage=str(item.stage),
            source_type=item.event.source_type,
            category=item.event.category,
            severity=item.event.severity,
            evidence_ref=str(item.event.evidence_ref),
            entity_refs=tuple(sorted({reference.entity_ref for reference in item.context.references})),
        ).validate()
        for item in correlated
    )
    evidence_refs = tuple(sorted({entry.evidence_ref for entry in entries}))
    entity_refs = tuple(sorted({ref for entry in entries for ref in entry.entity_refs}))
    stages_present = {entry.stage for entry in entries}
    stage_types = tuple(stage for stage in STAGE_ORDER if stage in stages_present)

    return IncidentTimeline(
        entry_count=len(entries),
        graph_count=len(graphs),
        entries=entries,
        incident_graphs=graphs,
        graph_ids=tuple(graph.graph_id for graph in graphs),
        evidence_refs=evidence_refs,
        entity_refs=entity_refs,
        stage_types=stage_types,
        first_seen=entries[0].observed_at,
        last_seen=entries[-1].observed_at,
        reason_codes=(
            "INCIDENT_TIMELINE_BUILT_DETERMINISTICALLY",
            "INCIDENT_TIMELINE_REQUIRES_EXACT_CORRELATION",
        ),
    ).validate()
