from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from .behavior_intelligence import (
    BehaviorAssessment,
    RULE_DNS_CARDINALITY,
    RULE_DNS_ENTROPY,
    RULE_DNS_NXDOMAIN,
    RULE_RARE_DNS,
    RULE_RARE_PEER,
    RULE_RARE_SERVICE,
)
from .contracts import MonitoringContractError, SEVERITIES, sha256_fingerprint
from .correlation_graph import IncidentGraph, STAGE_ORDER

_RULE_WEIGHTS = {
    RULE_RARE_DNS: 10,
    RULE_RARE_PEER: 10,
    RULE_RARE_SERVICE: 8,
    RULE_DNS_ENTROPY: 25,
    RULE_DNS_CARDINALITY: 20,
    RULE_DNS_NXDOMAIN: 20,
}
_ENTITY_REF_RE = re.compile(r"^entity:[a-z]+:sha256:[0-9a-f]{64}$")
_ASSET_REF_RE = re.compile(r"^asset:[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,127}$")
_INCIDENT_SCHEMA = "workspace-security-monitoring/incident-graph-v1"
_MAX_RECEIPT_EVIDENCE_REFS = 512
_MAX_RECEIPT_ENTITY_REFS = 256
_MAX_RECEIPT_RULE_REFS = 64


@dataclass(frozen=True)
class BehaviorRiskConfig:
    max_assessments: int = 2000
    max_graphs: int = 200
    max_components: int = 32
    graph_two_stage_points: int = 20
    graph_multi_stage_points: int = 35
    high_threshold: int = 60

    def validate(self) -> "BehaviorRiskConfig":
        if not 1 <= int(self.max_assessments) <= 2000:
            raise MonitoringContractError("risk assessment bound is invalid")
        if not 1 <= int(self.max_graphs) <= 200:
            raise MonitoringContractError("risk graph bound is invalid")
        if not 1 <= int(self.max_components) <= 128:
            raise MonitoringContractError("risk component bound is invalid")
        for value in (self.graph_two_stage_points, self.graph_multi_stage_points, self.high_threshold):
            if not 1 <= int(value) <= 100:
                raise MonitoringContractError("risk score threshold/weight is invalid")
        if self.graph_multi_stage_points < self.graph_two_stage_points:
            raise MonitoringContractError("multi-stage graph weight must not be lower than two-stage")
        return self


@dataclass(frozen=True, order=True)
class RiskComponent:
    component_id: str
    rule_id: str
    points: int
    source_refs: tuple[str, ...]


@dataclass(frozen=True)
class BehaviorRiskReceipt:
    receipt_id: str
    score: int
    level: str
    corroborated: bool
    assessment_ids: tuple[str, ...]
    graph_ids: tuple[str, ...]
    rule_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    entity_refs: tuple[str, ...]
    components: tuple[RiskComponent, ...]
    scope_entity_ref: str | None = None
    authority: str = "advisory"
    schema_version: str = "workspace-security-monitoring/behavior-risk-v1"

    def validate(self) -> "BehaviorRiskReceipt":
        if not 0 <= int(self.score) <= 100:
            raise MonitoringContractError("risk score must be within 0..100")
        if self.level not in {"info", "low", "medium", "high"}:
            raise MonitoringContractError("unsupported risk level")
        if self.authority != "advisory":
            raise MonitoringContractError("risk authority must remain advisory")
        if self.scope_entity_ref is not None:
            scope = str(self.scope_entity_ref)
            if not (_ENTITY_REF_RE.fullmatch(scope) or _ASSET_REF_RE.fullmatch(scope)):
                raise MonitoringContractError("risk receipt scope is not an opaque/approved entity ref")
            if scope not in self.entity_refs:
                raise MonitoringContractError("risk receipt scope must be present in entity refs")
        if len(self.assessment_ids) > 2000 or len(self.graph_ids) > 200:
            raise MonitoringContractError("risk receipt source reference bound exceeded")
        if len(self.rule_ids) > _MAX_RECEIPT_RULE_REFS:
            raise MonitoringContractError("risk receipt rule reference bound exceeded")
        if len(self.evidence_refs) > _MAX_RECEIPT_EVIDENCE_REFS:
            raise MonitoringContractError("risk receipt evidence reference bound exceeded")
        if len(self.entity_refs) > _MAX_RECEIPT_ENTITY_REFS:
            raise MonitoringContractError("risk receipt entity reference bound exceeded")
        if len(self.components) > 128:
            raise MonitoringContractError("risk receipt component bound exceeded")
        for ref in self.entity_refs:
            if not (_ENTITY_REF_RE.fullmatch(ref) or _ASSET_REF_RE.fullmatch(ref)):
                raise MonitoringContractError("risk receipt contains non-opaque entity reference")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "score": self.score,
            "level": self.level,
            "corroborated": self.corroborated,
            "scope_entity_ref": self.scope_entity_ref,
            "assessment_ids": list(self.assessment_ids),
            "graph_ids": list(self.graph_ids),
            "rule_ids": list(self.rule_ids),
            "evidence_refs": list(self.evidence_refs),
            "entity_refs": list(self.entity_refs),
            "components": [
                {
                    "component_id": component.component_id,
                    "rule_id": component.rule_id,
                    "points": component.points,
                    "source_refs": list(component.source_refs),
                }
                for component in self.components
            ],
            "authority": self.authority,
        }


def _safe_entities(refs: Iterable[str]) -> tuple[str, ...]:
    result = tuple(sorted(set(str(ref) for ref in refs)))
    for ref in result:
        if not (_ENTITY_REF_RE.fullmatch(ref) or _ASSET_REF_RE.fullmatch(ref)):
            raise MonitoringContractError("risk input contains raw/invalid entity reference")
    return result


def _validate_graph(graph: IncidentGraph) -> IncidentGraph:
    if graph.schema_version != _INCIDENT_SCHEMA:
        raise MonitoringContractError("unsupported incident graph schema")
    if graph.authority != "advisory":
        raise MonitoringContractError("incident graph authority must remain advisory")
    if not graph.event_ids or len(graph.event_ids) > 10000:
        raise MonitoringContractError("incident graph event reference bound is invalid")
    if len(graph.evidence_refs) > 10000 or len(graph.entity_refs) > 100000:
        raise MonitoringContractError("incident graph reference bound exceeded")
    if not 2 <= len(graph.stage_types) <= len(STAGE_ORDER):
        raise MonitoringContractError("incident graph must contain at least two supported stages")
    if any(stage not in STAGE_ORDER for stage in graph.stage_types):
        raise MonitoringContractError("incident graph contains unsupported stage")
    if graph.severity not in SEVERITIES or graph.priority not in {"normal", "high"}:
        raise MonitoringContractError("incident graph severity/priority is invalid")
    if not graph.rule_ids or not graph.edge_ids:
        raise MonitoringContractError("incident graph requires deterministic rule/edge evidence")
    try:
        first = datetime.fromisoformat(graph.first_seen.replace("Z", "+00:00"))
        last = datetime.fromisoformat(graph.last_seen.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError("incident graph timestamps must be ISO-8601") from exc
    if first.tzinfo is None or last.tzinfo is None or last < first:
        raise MonitoringContractError("incident graph timestamps are invalid")
    _safe_entities(graph.entity_refs)
    return graph


def _component(*, rule_id: str, points: int, source_refs: Iterable[str]) -> RiskComponent:
    refs = tuple(sorted(set(str(ref) for ref in source_refs)))
    identity = {"rule_id": rule_id, "points": int(points), "source_refs": list(refs)}
    component_id = "risk-component-" + sha256_fingerprint(identity).split(":", 1)[1][:24]
    return RiskComponent(
        component_id=component_id,
        rule_id=rule_id,
        points=int(points),
        source_refs=refs,
    )


class DeterministicBehaviorRiskScorer:
    """Metadata-only advisory scorer isolated to one exact initiator scope."""

    def __init__(self, config: BehaviorRiskConfig | None = None):
        self.config = (config or BehaviorRiskConfig()).validate()

    def score(
        self,
        *,
        assessments: Iterable[BehaviorAssessment],
        incident_graphs: Iterable[IncidentGraph] = (),
    ) -> BehaviorRiskReceipt:
        unique_assessments: dict[str, BehaviorAssessment] = {}
        for raw in assessments:
            item = raw.validate()
            if item.status == "signal" and item.scope_entity_ref is None:
                raise MonitoringContractError("risk signal requires exact initiator scope")
            previous = unique_assessments.get(item.assessment_id)
            if previous is not None and previous != item:
                raise MonitoringContractError("conflicting behavior assessment replay")
            unique_assessments[item.assessment_id] = item
            if len(unique_assessments) > self.config.max_assessments:
                raise MonitoringContractError("risk assessment input bound exceeded")

        scopes = {
            item.scope_entity_ref
            for item in unique_assessments.values()
            if item.scope_entity_ref is not None
        }
        if len(scopes) > 1:
            raise MonitoringContractError(
                "risk score accepts one exact scope; use score_by_scope for multiple initiators"
            )
        scope_entity_ref = next(iter(scopes), None)
        if scope_entity_ref is not None:
            _safe_entities((scope_entity_ref,))
            selected_assessments = {
                key: item
                for key, item in unique_assessments.items()
                if item.scope_entity_ref == scope_entity_ref
            }
        else:
            selected_assessments = unique_assessments

        unique_graphs: dict[str, IncidentGraph] = {}
        for raw_graph in incident_graphs:
            graph = _validate_graph(raw_graph)
            previous = unique_graphs.get(graph.graph_id)
            if previous is not None and previous != graph:
                raise MonitoringContractError("conflicting incident graph replay")
            unique_graphs[graph.graph_id] = graph
            if len(unique_graphs) > self.config.max_graphs:
                raise MonitoringContractError("risk graph input bound exceeded")

        selected_event_ids = {
            event_id
            for item in selected_assessments.values()
            for event_id in item.event_ids
        }
        if scope_entity_ref is None:
            related_graphs = unique_graphs
        else:
            related_graphs = {
                key: graph
                for key, graph in unique_graphs.items()
                if scope_entity_ref in graph.entity_refs
                or bool(selected_event_ids.intersection(graph.event_ids))
            }

        signals = tuple(
            sorted(
                (item for item in selected_assessments.values() if item.status == "signal"),
                key=lambda item: item.assessment_id,
            )
        )
        all_entities = _safe_entities(
            ref for item in selected_assessments.values() for ref in item.entity_refs
        )
        all_entities = _safe_entities(
            (*all_entities, *(ref for graph in related_graphs.values() for ref in graph.entity_refs))
        )
        if scope_entity_ref is not None and scope_entity_ref not in all_entities:
            all_entities = _safe_entities((*all_entities, scope_entity_ref))

        components: list[RiskComponent] = []
        seen_signal_rules: set[str] = set()
        for item in signals:
            if item.rule_id in seen_signal_rules:
                continue
            points = _RULE_WEIGHTS.get(item.rule_id)
            if points is None:
                continue
            seen_signal_rules.add(item.rule_id)
            components.append(
                _component(
                    rule_id=item.rule_id,
                    points=points,
                    source_refs=(item.assessment_id,),
                )
            )

        graph_component_added: set[str] = set()
        for graph in sorted(related_graphs.values(), key=lambda value: value.graph_id):
            rule_id = (
                "MULTI_STAGE_INCIDENT_GRAPH_V1"
                if len(graph.stage_types) >= 3
                else "TWO_STAGE_INCIDENT_GRAPH_V1"
            )
            if rule_id in graph_component_added:
                continue
            graph_component_added.add(rule_id)
            points = (
                self.config.graph_multi_stage_points
                if len(graph.stage_types) >= 3
                else self.config.graph_two_stage_points
            )
            components.append(
                _component(rule_id=rule_id, points=points, source_refs=(graph.graph_id,))
            )

        if len(components) > self.config.max_components:
            raise MonitoringContractError("risk component bound exceeded")

        corroborated = False
        for item in signals:
            item_events = set(item.event_ids)
            item_entities = set(item.entity_refs)
            for graph in related_graphs.values():
                # Exact event/entity overlap only. Time proximity is not an input
                # to this scorer and can never establish corroboration.
                if item_events.intersection(graph.event_ids) or item_entities.intersection(graph.entity_refs):
                    corroborated = True
                    break
            if corroborated:
                break

        score = min(100, sum(component.points for component in components))
        if score == 0:
            level = "info"
        elif score < 20:
            level = "low"
        elif score < self.config.high_threshold:
            level = "medium"
        else:
            strong_independent = len(seen_signal_rules) >= 3
            level = "high" if corroborated or strong_independent else "medium"

        all_assessment_ids = tuple(sorted(selected_assessments))
        all_graph_ids = tuple(sorted(related_graphs))
        all_rule_ids = tuple(sorted({component.rule_id for component in components}))
        all_evidence_refs = tuple(
            sorted(
                {ref for item in selected_assessments.values() for ref in item.evidence_refs}
                | {ref for graph in related_graphs.values() for ref in graph.evidence_refs}
            )
        )
        components_tuple = tuple(sorted(components))
        identity = {
            "scope_entity_ref": scope_entity_ref,
            "score": score,
            "level": level,
            "corroborated": corroborated,
            "assessment_ids": list(all_assessment_ids),
            "graph_ids": list(all_graph_ids),
            "rule_ids": list(all_rule_ids),
            "evidence_refs": list(all_evidence_refs),
            "entity_refs": list(all_entities),
            "components": [
                {
                    "component_id": item.component_id,
                    "rule_id": item.rule_id,
                    "points": item.points,
                    "source_refs": list(item.source_refs),
                }
                for item in components_tuple
            ],
            "authority": "advisory",
        }
        receipt_id = "risk-" + sha256_fingerprint(identity).split(":", 1)[1][:24]
        return BehaviorRiskReceipt(
            receipt_id=receipt_id,
            score=score,
            level=level,
            corroborated=corroborated,
            assessment_ids=all_assessment_ids,
            graph_ids=all_graph_ids,
            rule_ids=all_rule_ids[:_MAX_RECEIPT_RULE_REFS],
            evidence_refs=all_evidence_refs[:_MAX_RECEIPT_EVIDENCE_REFS],
            entity_refs=all_entities[:_MAX_RECEIPT_ENTITY_REFS],
            components=components_tuple,
            scope_entity_ref=scope_entity_ref,
        ).validate()

    def score_by_scope(
        self,
        *,
        assessments: Iterable[BehaviorAssessment],
        incident_graphs: Iterable[IncidentGraph] = (),
    ) -> tuple[BehaviorRiskReceipt, ...]:
        assessment_items = tuple(item.validate() for item in assessments)
        graph_items = tuple(_validate_graph(graph) for graph in incident_graphs)
        groups: dict[str, list[BehaviorAssessment]] = {}
        for item in assessment_items:
            if item.status == "signal" and item.scope_entity_ref is None:
                raise MonitoringContractError("risk signal requires exact initiator scope")
            if item.scope_entity_ref is None:
                continue
            groups.setdefault(item.scope_entity_ref, []).append(item)
        receipts = [
            self.score(assessments=tuple(groups[scope]), incident_graphs=graph_items)
            for scope in sorted(groups)
        ]
        return tuple(sorted(receipts, key=lambda receipt: (receipt.scope_entity_ref or "", receipt.receipt_id)))
