from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable

from .contracts import MonitoringContractError
from .correlation_graph import CorrelationEvent, IncidentGraph

SUPPORT_SOURCE_TYPES = frozenset({"monitoring_observation", "syslog"})


@dataclass(frozen=True)
class CorrelationSupportConfig:
    window_seconds: int = 900
    max_support_events: int = 1000
    max_support_entity_refs: int = 8000

    def validate(self) -> "CorrelationSupportConfig":
        if not 30 <= int(self.window_seconds) <= 3600:
            raise MonitoringContractError("support window must be within 30..3600 seconds")
        if not 1 <= int(self.max_support_events) <= 10000:
            raise MonitoringContractError("max_support_events must be within 1..10000")
        if not 1 <= int(self.max_support_entity_refs) <= 100000:
            raise MonitoringContractError("max_support_entity_refs must be within 1..100000")
        return self


@dataclass(frozen=True)
class IncidentSupportingEvidence:
    graph_id: str
    event_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    shared_entity_refs: tuple[str, ...]
    source_types: tuple[str, ...]
    relation: str = "supporting_context_only"
    authority: str = "advisory"
    schema_version: str = "workspace-security-monitoring/incident-support-v1"

    def public_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "graph_id": self.graph_id,
            "event_ids": list(self.event_ids),
            "evidence_refs": list(self.evidence_refs),
            "shared_entity_refs": list(self.shared_entity_refs),
            "source_types": list(self.source_types),
            "relation": self.relation,
            "authority": self.authority,
        }


def _refs(item: CorrelationEvent, role: str) -> set[str]:
    return set(item.context.refs_for_role(role))


def attach_supporting_evidence(
    graphs: Iterable[IncidentGraph],
    events: Iterable[CorrelationEvent],
    *,
    config: CorrelationSupportConfig | None = None,
) -> tuple[IncidentSupportingEvidence, ...]:
    """Attach fact-only operational context without creating or changing incident edges.

    Only stage-less syslog/monitoring observations are eligible. Attachment requires
    an exact shared approved asset reference with an event already inside the incident
    graph and a bounded timestamp window. Interface references may further corroborate
    that already asset-bound relationship, but an interface name/hash alone is never
    authoritative because interface labels are not globally unique across devices.
    The returned object is separate from IncidentGraph, so it cannot alter severity,
    priority, stages, rules, or edges.
    """

    cfg = (config or CorrelationSupportConfig()).validate()
    unique: dict[str, CorrelationEvent] = {}
    for raw in events:
        item = raw.validate()
        previous = unique.get(item.event.event_id)
        if previous is not None:
            if previous != item:
                raise MonitoringContractError("duplicate support event_id has conflicting context")
            continue
        unique[item.event.event_id] = item

    attachments: list[IncidentSupportingEvidence] = []
    support_events_seen = 0
    support_refs_seen = 0

    for graph in graphs:
        graph_event_ids = set(graph.event_ids)
        missing = graph_event_ids - set(unique)
        if missing:
            raise MonitoringContractError("support attachment requires all graph events")

        core = tuple(unique[event_id] for event_id in graph.event_ids)
        core_assets: set[str] = set()
        core_interfaces: set[str] = set()
        for item in core:
            core_assets |= _refs(item, "asset")
            core_interfaces |= _refs(item, "interface")

        # Monitoring/syslog support originates from approved inventory identity.
        # Fail closed when the incident has no exact approved asset reference to bind.
        if not core_assets:
            continue

        first_seen = min(item.observed for item in core)
        last_seen = max(item.observed for item in core)
        lower = first_seen - timedelta(seconds=cfg.window_seconds)
        upper = last_seen + timedelta(seconds=cfg.window_seconds)

        matched: list[tuple[CorrelationEvent, set[str]]] = []
        for candidate in unique.values():
            if candidate.event.event_id in graph_event_ids:
                continue
            if candidate.stage is not None:
                continue
            if candidate.event.source_type not in SUPPORT_SOURCE_TYPES:
                continue
            if candidate.observed < lower or candidate.observed > upper:
                continue

            shared_assets = _refs(candidate, "asset") & core_assets
            if not shared_assets:
                continue

            # Interface hashes are only supporting detail inside an already
            # exact asset match. Same-named interfaces on different devices
            # must never attach unrelated operational evidence.
            shared_interfaces = _refs(candidate, "interface") & core_interfaces
            shared = shared_assets | shared_interfaces

            support_events_seen += 1
            support_refs_seen += len(shared)
            if support_events_seen > cfg.max_support_events:
                raise MonitoringContractError("support event bound exceeded")
            if support_refs_seen > cfg.max_support_entity_refs:
                raise MonitoringContractError("support entity bound exceeded")
            matched.append((candidate, shared))

        if not matched:
            continue

        matched.sort(key=lambda pair: (pair[0].observed, pair[0].event.event_id))
        attachments.append(
            IncidentSupportingEvidence(
                graph_id=graph.graph_id,
                event_ids=tuple(item.event.event_id for item, _ in matched),
                evidence_refs=tuple(
                    sorted(
                        {
                            item.event.evidence_ref
                            for item, _ in matched
                            if item.event.evidence_ref
                        }
                    )
                ),
                shared_entity_refs=tuple(
                    sorted({ref for _, shared in matched for ref in shared})
                ),
                source_types=tuple(
                    sorted({item.event.source_type for item, _ in matched})
                ),
            )
        )

    return tuple(sorted(attachments, key=lambda item: item.graph_id))
