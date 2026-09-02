from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .contracts import MonitoringContractError, SEVERITIES, sha256_fingerprint
from .correlation_graph import (
    CorrelationEvent,
    CorrelationGraphConfig,
    DeterministicIncidentCorrelator,
    IncidentGraph,
    STAGE_FLOW,
    STAGE_ORDER,
)

FLOW_ANALYSIS_SCHEMA = "workspace-security-monitoring/flow-evidence-analysis-v1"
MAX_FLOW_ANALYSIS_EVENTS = 256
MAX_FLOW_ANALYSIS_ENTITIES = 4096
MAX_FLOW_ANALYSIS_EDGES = 2048
FLOW_ANALYSIS_WINDOW_SECONDS = 900

_FLOW_SOURCES = frozenset({"suricata_eve", "zeek_json"})
_FLOW_CATEGORIES = frozenset({"suricata.flow", "zeek.conn"})


@dataclass(frozen=True)
class FlowEvidenceAnalysis:
    event_count: int
    flow_event_count: int
    event_ids: tuple[str, ...]
    flow_event_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    entity_refs: tuple[str, ...]
    source_types: tuple[str, ...]
    stage_types: tuple[str, ...]
    first_seen: str
    last_seen: str
    severity_counts: tuple[tuple[str, int], ...]
    incident_graphs: tuple[IncidentGraph, ...]
    reason_codes: tuple[str, ...]
    authority: str = "advisory"
    schema_version: str = FLOW_ANALYSIS_SCHEMA

    def validate(self) -> "FlowEvidenceAnalysis":
        if self.schema_version != FLOW_ANALYSIS_SCHEMA:
            raise MonitoringContractError("unsupported flow analysis schema")
        if self.authority != "advisory":
            raise MonitoringContractError("flow analysis must remain advisory")
        if not 1 <= self.event_count <= MAX_FLOW_ANALYSIS_EVENTS:
            raise MonitoringContractError("flow analysis event_count is out of bounds")
        if not 1 <= self.flow_event_count <= self.event_count:
            raise MonitoringContractError("flow analysis requires at least one flow event")
        if len(self.event_ids) != self.event_count or len(set(self.event_ids)) != self.event_count:
            raise MonitoringContractError("flow analysis event_ids are inconsistent")
        if len(self.flow_event_ids) != self.flow_event_count or not set(self.flow_event_ids) <= set(self.event_ids):
            raise MonitoringContractError("flow analysis flow_event_ids are inconsistent")
        if not self.evidence_refs:
            raise MonitoringContractError("flow analysis requires evidence refs")
        if tuple(sorted(set(self.evidence_refs))) != self.evidence_refs:
            raise MonitoringContractError("flow analysis evidence refs must be sorted and unique")
        if tuple(sorted(set(self.entity_refs))) != self.entity_refs:
            raise MonitoringContractError("flow analysis entity refs must be sorted and unique")
        if len(self.entity_refs) > MAX_FLOW_ANALYSIS_ENTITIES:
            raise MonitoringContractError("flow analysis entity bound exceeded")
        if tuple(sorted(set(self.source_types))) != self.source_types:
            raise MonitoringContractError("flow analysis source_types must be sorted and unique")
        if not self.stage_types or any(stage not in STAGE_ORDER for stage in self.stage_types):
            raise MonitoringContractError("flow analysis stage_types are invalid")
        if STAGE_FLOW not in self.stage_types:
            raise MonitoringContractError("flow analysis stage_types must include FLOW")
        if not self.first_seen or not self.last_seen or self.first_seen > self.last_seen:
            raise MonitoringContractError("flow analysis time range is invalid")
        severity_rows = dict(self.severity_counts)
        if set(severity_rows) - SEVERITIES:
            raise MonitoringContractError("flow analysis severity_counts contain unsupported severity")
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in severity_rows.values()):
            raise MonitoringContractError("flow analysis severity counts are invalid")
        if sum(severity_rows.values()) != self.event_count:
            raise MonitoringContractError("flow analysis severity counts do not match event_count")
        if tuple(sorted(severity_rows.items())) != self.severity_counts:
            raise MonitoringContractError("flow analysis severity_counts must be sorted and unique")
        if not self.reason_codes:
            raise MonitoringContractError("flow analysis requires reason codes")
        if len(self.incident_graphs) > MAX_FLOW_ANALYSIS_EVENTS:
            raise MonitoringContractError("flow analysis graph bound exceeded")
        for graph in self.incident_graphs:
            if graph.authority != "advisory":
                raise MonitoringContractError("flow analysis graph authority must remain advisory")
            if not set(graph.event_ids) <= set(self.event_ids):
                raise MonitoringContractError("flow analysis graph references an event outside the request")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "event_count": self.event_count,
            "flow_event_count": self.flow_event_count,
            "event_ids": list(self.event_ids),
            "flow_event_ids": list(self.flow_event_ids),
            "evidence_refs": list(self.evidence_refs),
            "entity_refs": list(self.entity_refs),
            "source_types": list(self.source_types),
            "stage_types": list(self.stage_types),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "severity_counts": {key: value for key, value in self.severity_counts},
            "incident_graphs": [graph.public_dict() for graph in self.incident_graphs],
            "reason_codes": list(self.reason_codes),
            "authority": self.authority,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


def _identity(item: CorrelationEvent) -> tuple[object, ...]:
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


def analyze_flow_evidence(events: Iterable[CorrelationEvent]) -> FlowEvidenceAnalysis:
    """Analyze already-normalized flow evidence without collection or model authority.

    Input is deliberately downstream of the strict sensor parsers. Raw log lines,
    packet bytes, host targets, paths, credentials, shell commands and model output do
    not cross this boundary. Related DNS/AUTH/PROCESS/IDS events may be included only
    when they are already normalized CorrelationEvent objects with evidence anchors.
    """

    unique: dict[str, CorrelationEvent] = {}
    for raw in events:
        if not isinstance(raw, CorrelationEvent):
            raise MonitoringContractError("flow analysis accepts CorrelationEvent only")
        item = raw.validate()
        if item.stage is None:
            raise MonitoringContractError("flow analysis rejects unclassified correlation stages")
        if item.event.evidence_ref is None:
            raise MonitoringContractError("flow analysis requires evidence_ref on every event")
        previous = unique.get(item.event.event_id)
        if previous is not None:
            if _identity(previous) != _identity(item):
                raise MonitoringContractError("duplicate event_id has conflicting flow evidence")
            continue
        unique[item.event.event_id] = item
        if len(unique) > MAX_FLOW_ANALYSIS_EVENTS:
            raise MonitoringContractError("flow analysis event bound exceeded")

    if not unique:
        raise MonitoringContractError("flow analysis requires normalized evidence")

    ordered = tuple(sorted(unique.values(), key=lambda item: (item.observed, item.event.event_id)))
    flow_events = tuple(item for item in ordered if item.stage == STAGE_FLOW)
    if not flow_events:
        raise MonitoringContractError("flow analysis requires at least one FLOW event")
    for item in flow_events:
        if item.event.source_type not in _FLOW_SOURCES or item.event.category not in _FLOW_CATEGORIES:
            raise MonitoringContractError("flow event source/category is not admitted")

    entity_refs = tuple(
        sorted({reference.entity_ref for item in ordered for reference in item.context.references})
    )
    if len(entity_refs) > MAX_FLOW_ANALYSIS_ENTITIES:
        raise MonitoringContractError("flow analysis entity bound exceeded")

    config = CorrelationGraphConfig(
        window_seconds=FLOW_ANALYSIS_WINDOW_SECONDS,
        max_events=MAX_FLOW_ANALYSIS_EVENTS,
        max_entities=MAX_FLOW_ANALYSIS_ENTITIES,
        max_edges=MAX_FLOW_ANALYSIS_EDGES,
    )
    graphs = DeterministicIncidentCorrelator(config).correlate(ordered)
    evidence_refs = tuple(sorted({item.event.evidence_ref for item in ordered if item.event.evidence_ref}))
    stages_present = {item.stage for item in ordered if item.stage is not None}
    stage_types = tuple(stage for stage in STAGE_ORDER if stage in stages_present)
    severity_counts = tuple(
        sorted((severity, sum(item.event.severity == severity for item in ordered)) for severity in SEVERITIES if any(item.event.severity == severity for item in ordered))
    )
    reason_codes = ["FLOW_EVIDENCE_ANALYZED_DETERMINISTICALLY"]
    if graphs:
        reason_codes.append("FLOW_CROSS_STAGE_CORRELATION_OBSERVED")
    else:
        reason_codes.append("FLOW_CROSS_STAGE_CORRELATION_NOT_OBSERVED")

    result = FlowEvidenceAnalysis(
        event_count=len(ordered),
        flow_event_count=len(flow_events),
        event_ids=tuple(item.event.event_id for item in ordered),
        flow_event_ids=tuple(item.event.event_id for item in flow_events),
        evidence_refs=evidence_refs,
        entity_refs=entity_refs,
        source_types=tuple(sorted({item.event.source_type for item in ordered})),
        stage_types=stage_types,
        first_seen=ordered[0].event.observed_at,
        last_seen=ordered[-1].event.observed_at,
        severity_counts=severity_counts,
        incident_graphs=graphs,
        reason_codes=tuple(reason_codes),
    )
    return result.validate()
