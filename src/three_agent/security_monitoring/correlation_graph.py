from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from .contracts import CanonicalEvent, MonitoringContractError, SEVERITIES, sha256_fingerprint
from .entity_context import EventEntityContext

STAGE_DNS = "DNS"
STAGE_FLOW = "FLOW"
STAGE_AUTH = "AUTH"
STAGE_PROCESS = "PROCESS"
STAGE_IDS = "IDS"
STAGE_ORDER = (STAGE_DNS, STAGE_FLOW, STAGE_AUTH, STAGE_PROCESS, STAGE_IDS)
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

RULE_DNS_FLOW = "DNS_FLOW_EXACT_V1"
RULE_FLOW_AUTH = "FLOW_AUTH_EXACT_V1"
RULE_AUTH_PROCESS = "AUTH_PROCESS_EXACT_V1"
RULE_IDS_CORROBORATION = "IDS_CORROBORATION_EXACT_V1"


@dataclass(frozen=True)
class CorrelationEvent:
    event: CanonicalEvent
    context: EventEntityContext

    def validate(self) -> "CorrelationEvent":
        self.event.validate()
        self.context.validate()
        if self.context.event_id != self.event.event_id:
            raise MonitoringContractError("correlation context must bind exact event_id")
        return self

    @property
    def stage(self) -> str | None:
        category = self.event.category
        source_type = self.event.source_type
        if source_type == "workspace_audit":
            if category in {"workspace_audit.auth_success", "workspace_audit.auth_failure"}:
                return STAGE_AUTH
            if category == "workspace_audit.process_start":
                return STAGE_PROCESS
            return None
        if source_type == "suricata_eve":
            if category == "suricata.dns":
                return STAGE_DNS
            if category == "suricata.flow":
                return STAGE_FLOW
            if category == "suricata.alert":
                return STAGE_IDS
            return None
        if source_type == "zeek_json":
            if category == "zeek.dns":
                return STAGE_DNS
            if category == "zeek.conn":
                return STAGE_FLOW
            if category in {"zeek.notice", "zeek.weird"}:
                return STAGE_IDS
        return None

    @property
    def observed(self) -> datetime:
        return datetime.fromisoformat(self.event.observed_at.replace("Z", "+00:00"))


@dataclass(frozen=True, order=True)
class CorrelationEdge:
    from_event_id: str
    to_event_id: str
    rule_id: str
    shared_entity_refs: tuple[str, ...]
    edge_id: str

    @classmethod
    def build(
        cls,
        *,
        left: CorrelationEvent,
        right: CorrelationEvent,
        rule_id: str,
        shared_entity_refs: Iterable[str],
    ) -> "CorrelationEdge":
        refs = tuple(sorted(set(str(value) for value in shared_entity_refs)))
        if not refs:
            raise MonitoringContractError("correlation edge requires exact shared entity evidence")
        identity = {
            "from_event_id": left.event.event_id,
            "to_event_id": right.event.event_id,
            "rule_id": rule_id,
            "shared_entity_refs": list(refs),
        }
        edge_id = "edge-" + sha256_fingerprint(identity).split(":", 1)[1][:24]
        return cls(
            from_event_id=left.event.event_id,
            to_event_id=right.event.event_id,
            rule_id=rule_id,
            shared_entity_refs=refs,
            edge_id=edge_id,
        )


@dataclass(frozen=True)
class IncidentGraph:
    graph_id: str
    event_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    entity_refs: tuple[str, ...]
    source_types: tuple[str, ...]
    stage_types: tuple[str, ...]
    first_seen: str
    last_seen: str
    severity: str
    priority: str
    rule_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    authority: str = "advisory"
    schema_version: str = "workspace-security-monitoring/incident-graph-v1"

    def public_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "graph_id": self.graph_id,
            "event_ids": list(self.event_ids),
            "evidence_refs": list(self.evidence_refs),
            "entity_refs": list(self.entity_refs),
            "source_types": list(self.source_types),
            "stage_types": list(self.stage_types),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "severity": self.severity,
            "priority": self.priority,
            "rule_ids": list(self.rule_ids),
            "edge_ids": list(self.edge_ids),
            "authority": self.authority,
        }


@dataclass(frozen=True)
class CorrelationGraphConfig:
    window_seconds: int = 900
    max_events: int = 2000
    max_entities: int = 16000
    max_edges: int = 5000

    def validate(self) -> "CorrelationGraphConfig":
        if not 30 <= int(self.window_seconds) <= 3600:
            raise MonitoringContractError("correlation window must be within 30..3600 seconds")
        if not 1 <= int(self.max_events) <= 10000:
            raise MonitoringContractError("max_events must be within 1..10000")
        if not 1 <= int(self.max_entities) <= 100000:
            raise MonitoringContractError("max_entities must be within 1..100000")
        if not 1 <= int(self.max_edges) <= 50000:
            raise MonitoringContractError("max_edges must be within 1..50000")
        return self


def _refs(item: CorrelationEvent, role: str) -> set[str]:
    return set(item.context.refs_for_role(role))


def _shared_initiator(left: CorrelationEvent, right: CorrelationEvent) -> set[str]:
    shared_assets = _refs(left, "asset") & _refs(right, "asset")
    shared_sources = _refs(left, "source_ip") & _refs(right, "source_ip")
    return shared_assets | shared_sources


def _rule_for(left: CorrelationEvent, right: CorrelationEvent) -> tuple[str, set[str]] | None:
    left_stage = left.stage
    right_stage = right.stage
    if left_stage == STAGE_DNS and right_stage == STAGE_FLOW:
        initiator = _shared_initiator(left, right)
        resolved = _refs(left, "dns_answer") & _refs(right, "destination_ip")
        if initiator and resolved:
            return RULE_DNS_FLOW, initiator | resolved
        return None

    if left_stage == STAGE_FLOW and right_stage == STAGE_AUTH:
        source = _refs(left, "source_ip") & _refs(right, "source_ip")
        destination = _refs(left, "destination_ip") & _refs(right, "destination_ip")
        service = _refs(left, "service") & _refs(right, "service")
        if source and destination and service:
            return RULE_FLOW_AUTH, source | destination | service
        return None

    if left_stage == STAGE_AUTH and right_stage == STAGE_PROCESS:
        asset = _refs(left, "asset") & _refs(right, "asset")
        user = _refs(left, "auth_user") & _refs(right, "auth_user")
        if asset and user:
            return RULE_AUTH_PROCESS, asset | user
        return None

    if STAGE_IDS in {left_stage, right_stage} and left_stage != right_stage:
        shared = set()
        for role in ("asset", "source_ip", "destination_ip"):
            shared |= _refs(left, role) & _refs(right, role)
        if shared:
            return RULE_IDS_CORROBORATION, shared
    return None


def _event_identity(item: CorrelationEvent) -> tuple[object, ...]:
    item.validate()
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


def _graph_severity(items: tuple[CorrelationEvent, ...], stage_count: int) -> tuple[str, str]:
    severities = [item.event.severity for item in items]
    if any(value not in SEVERITIES for value in severities):
        raise MonitoringContractError("graph contains unsupported severity")
    severity = max(severities, key=lambda value: SEVERITY_ORDER[value])
    priority = "normal"
    if stage_count >= 3:
        priority = "high"
        # Multi-stage linkage increases investigation priority but must never
        # manufacture CRITICAL without critical source evidence.
        if SEVERITY_ORDER[severity] < SEVERITY_ORDER["high"]:
            severity = "high"
    return severity, priority


class DeterministicIncidentCorrelator:
    """Pure local exact-entity correlator with no model/network/write authority."""

    def __init__(self, config: CorrelationGraphConfig | None = None):
        self.config = (config or CorrelationGraphConfig()).validate()

    def correlate(self, events: Iterable[CorrelationEvent]) -> tuple[IncidentGraph, ...]:
        unique: dict[str, CorrelationEvent] = {}
        total_entities = 0
        for raw in events:
            item = raw.validate()
            previous = unique.get(item.event.event_id)
            if previous is not None:
                if _event_identity(previous) != _event_identity(item):
                    raise MonitoringContractError("duplicate event_id has conflicting correlation context")
                continue
            unique[item.event.event_id] = item
            total_entities += len(item.context.references)
            if len(unique) > self.config.max_events:
                raise MonitoringContractError("correlation event bound exceeded")
            if total_entities > self.config.max_entities:
                raise MonitoringContractError("correlation entity bound exceeded")

        relevant = sorted(
            (item for item in unique.values() if item.stage is not None),
            key=lambda item: (item.observed, item.event.event_id),
        )
        edges: list[CorrelationEdge] = []
        for index, left in enumerate(relevant):
            for right in relevant[index + 1 :]:
                delta = (right.observed - left.observed).total_seconds()
                if delta > self.config.window_seconds:
                    break
                if delta < 0:
                    continue
                rule = _rule_for(left, right)
                if rule is None:
                    continue
                rule_id, shared = rule
                edges.append(
                    CorrelationEdge.build(
                        left=left,
                        right=right,
                        rule_id=rule_id,
                        shared_entity_refs=shared,
                    )
                )
                if len(edges) > self.config.max_edges:
                    raise MonitoringContractError("correlation edge bound exceeded")

        if not edges:
            return ()
        edge_by_id = {edge.edge_id: edge for edge in edges}
        edges = sorted(edge_by_id.values())
        by_event = {item.event.event_id: item for item in relevant}
        adjacency: dict[str, set[str]] = {}
        for edge in edges:
            adjacency.setdefault(edge.from_event_id, set()).add(edge.to_event_id)
            adjacency.setdefault(edge.to_event_id, set()).add(edge.from_event_id)

        graphs: list[IncidentGraph] = []
        visited: set[str] = set()
        for root in sorted(adjacency):
            if root in visited:
                continue
            stack = [root]
            component: set[str] = set()
            while stack:
                event_id = stack.pop()
                if event_id in component:
                    continue
                component.add(event_id)
                stack.extend(sorted(adjacency.get(event_id, ()), reverse=True))
            visited |= component
            component_items = tuple(sorted((by_event[event_id] for event_id in component), key=lambda item: (item.observed, item.event.event_id)))
            component_edges = tuple(
                edge for edge in edges
                if edge.from_event_id in component and edge.to_event_id in component
            )
            stages_present = {item.stage for item in component_items if item.stage is not None}
            stage_types = tuple(stage for stage in STAGE_ORDER if stage in stages_present)
            severity, priority = _graph_severity(component_items, len(stage_types))
            evidence_refs = tuple(sorted({item.event.evidence_ref for item in component_items if item.event.evidence_ref}))
            entity_refs = tuple(sorted({ref for edge in component_edges for ref in edge.shared_entity_refs}))
            source_types = tuple(sorted({item.event.source_type for item in component_items}))
            rule_ids = tuple(sorted({edge.rule_id for edge in component_edges}))
            edge_ids = tuple(sorted(edge.edge_id for edge in component_edges))
            first_seen = component_items[0].event.observed_at
            last_seen = component_items[-1].event.observed_at
            event_ids = tuple(item.event.event_id for item in component_items)
            identity = {
                "event_ids": list(event_ids),
                "evidence_refs": list(evidence_refs),
                "entity_refs": list(entity_refs),
                "source_types": list(source_types),
                "stage_types": list(stage_types),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "severity": severity,
                "priority": priority,
                "rule_ids": list(rule_ids),
                "edge_ids": list(edge_ids),
                "authority": "advisory",
            }
            graph_id = "incident-" + sha256_fingerprint(identity).split(":", 1)[1][:24]
            graphs.append(
                IncidentGraph(
                    graph_id=graph_id,
                    event_ids=event_ids,
                    evidence_refs=evidence_refs,
                    entity_refs=entity_refs,
                    source_types=source_types,
                    stage_types=stage_types,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    severity=severity,
                    priority=priority,
                    rule_ids=rule_ids,
                    edge_ids=edge_ids,
                )
            )
        return tuple(sorted(graphs, key=lambda graph: (graph.first_seen, graph.graph_id)))
