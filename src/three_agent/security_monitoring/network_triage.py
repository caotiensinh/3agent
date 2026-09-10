from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Iterable

from .contracts import MonitoringContractError, SEVERITIES, sha256_fingerprint
from .correlation_graph import (
    RULE_AUTH_PROCESS,
    RULE_DNS_FLOW,
    RULE_FLOW_AUTH,
    RULE_IDS_CORROBORATION,
    STAGE_ORDER,
    IncidentGraph,
)

NETWORK_TRIAGE_SCHEMA = "workspace-security-monitoring/network-incident-triage-v1"
NETWORK_TRIAGE_PLAN_SCHEMA = "workspace-security-monitoring/network-incident-triage-plan-v1"
SUPPORTED_GRAPH_SCHEMA = "workspace-security-monitoring/incident-graph-v1"

TRIAGE_KINDS = {
    "dns-flow",
    "flow-auth",
    "auth-process",
    "dns-flow-auth",
    "flow-auth-process",
    "dns-flow-auth-process",
    "ids-corroborated",
    "mixed-correlated-activity",
}
CONFIDENCE_LEVELS = {"low", "medium", "high"}
INVESTIGATION_PRIORITIES = {"normal", "elevated", "high"}
SUPPORTED_RULES = {
    RULE_DNS_FLOW,
    RULE_FLOW_AUTH,
    RULE_AUTH_PROCESS,
    RULE_IDS_CORROBORATION,
}

_GRAPH_ID_RE = re.compile(r"^incident-[0-9a-f]{24}$")
_EDGE_ID_RE = re.compile(r"^edge-[0-9a-f]{24}$")
_ENTITY_REF_RE = re.compile(r"^entity:(ip|dns|user|process|service):sha256:[0-9a-f]{64}$")
_ASSET_REF_RE = re.compile(r"^asset:[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,127}$")
_COMPACT_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,255}$")


@dataclass(frozen=True)
class NetworkTriageConfig:
    """Hard bounds for analyst-side graph interpretation.

    These limits are intentionally independent from collection/correlation limits.
    Triage never broadens collection scope merely because upstream accepted a larger
    dataset.
    """

    max_graphs: int = 128
    max_event_refs: int = 4096
    max_entity_refs: int = 16384
    max_evidence_refs: int = 4096

    def validate(self) -> "NetworkTriageConfig":
        if not 1 <= int(self.max_graphs) <= 1024:
            raise MonitoringContractError("max_graphs must be within 1..1024")
        if not 1 <= int(self.max_event_refs) <= 50000:
            raise MonitoringContractError("max_event_refs must be within 1..50000")
        if not 1 <= int(self.max_entity_refs) <= 100000:
            raise MonitoringContractError("max_entity_refs must be within 1..100000")
        if not 1 <= int(self.max_evidence_refs) <= 50000:
            raise MonitoringContractError("max_evidence_refs must be within 1..50000")
        return self


@dataclass(frozen=True)
class NetworkIncidentTriage:
    triage_id: str
    graph_id: str
    graph_fingerprint: str
    triage_kind: str
    confidence: str
    severity: str
    investigation_priority: str
    reason_codes: tuple[str, ...]
    stage_types: tuple[str, ...]
    rule_ids: tuple[str, ...]
    event_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    entity_refs: tuple[str, ...]
    first_seen: str
    last_seen: str
    authority: str = "advisory"
    schema_version: str = NETWORK_TRIAGE_SCHEMA

    def public_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "triage_id": self.triage_id,
            "graph_id": self.graph_id,
            "graph_fingerprint": self.graph_fingerprint,
            "triage_kind": self.triage_kind,
            "confidence": self.confidence,
            "severity": self.severity,
            "investigation_priority": self.investigation_priority,
            "reason_codes": list(self.reason_codes),
            "stage_types": list(self.stage_types),
            "rule_ids": list(self.rule_ids),
            "event_ids": list(self.event_ids),
            "evidence_refs": list(self.evidence_refs),
            "entity_refs": list(self.entity_refs),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "authority": self.authority,
        }


def network_triage_plan() -> dict[str, object]:
    """Machine-readable authority contract for this analyst stage."""

    return {
        "schema_version": NETWORK_TRIAGE_PLAN_SCHEMA,
        "input_schema": SUPPORTED_GRAPH_SCHEMA,
        "output_schema": NETWORK_TRIAGE_SCHEMA,
        "authority": "advisory",
        "execution": "local_deterministic",
        "enabled_capabilities": [
            "validate_correlated_incident_graphs",
            "classify_exact_multistage_chains",
            "preserve_evidence_anchors",
            "produce_bounded_advisory_triage",
        ],
        "disabled_capabilities": [
            "active_discovery",
            "packet_capture",
            "command_execution",
            "network_mutation",
            "credential_retrieval",
            "remediation",
            "external_model_calls",
            "outbound_network",
        ],
    }


def _iso(value: str, field_name: str) -> datetime:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise MonitoringContractError(f"{field_name} must include timezone")
    return parsed


def _validate_compact_refs(values: tuple[str, ...], field_name: str, *, allow_empty: bool) -> tuple[str, ...]:
    rendered = tuple(str(value or "").strip() for value in values)
    if not allow_empty and not rendered:
        raise MonitoringContractError(f"{field_name} must not be empty")
    if len(set(rendered)) != len(rendered):
        raise MonitoringContractError(f"{field_name} must not contain duplicates")
    if any(not value or not _COMPACT_REF_RE.fullmatch(value) or "://" in value for value in rendered):
        raise MonitoringContractError(f"{field_name} contains an invalid reference")
    return rendered


def _validate_entity_refs(values: tuple[str, ...]) -> tuple[str, ...]:
    rendered = tuple(str(value or "").strip() for value in values)
    if len(set(rendered)) != len(rendered):
        raise MonitoringContractError("entity_refs must not contain duplicates")
    for value in rendered:
        if _ASSET_REF_RE.fullmatch(value) or _ENTITY_REF_RE.fullmatch(value):
            continue
        raise MonitoringContractError("entity_refs must contain only approved asset or typed SHA-256 references")
    return rendered


def _validate_graph(graph: IncidentGraph) -> IncidentGraph:
    if not isinstance(graph, IncidentGraph):
        raise MonitoringContractError("network triage accepts IncidentGraph inputs only")
    if graph.schema_version != SUPPORTED_GRAPH_SCHEMA:
        raise MonitoringContractError("unsupported incident graph schema")
    if graph.authority != "advisory":
        raise MonitoringContractError("incident graph must remain advisory")
    if not _GRAPH_ID_RE.fullmatch(str(graph.graph_id or "")):
        raise MonitoringContractError("incident graph_id is invalid")
    if graph.severity not in SEVERITIES:
        raise MonitoringContractError("incident graph severity is invalid")
    if graph.priority not in {"normal", "high"}:
        raise MonitoringContractError("incident graph priority is invalid")

    event_ids = _validate_compact_refs(graph.event_ids, "event_ids", allow_empty=False)
    evidence_refs = _validate_compact_refs(graph.evidence_refs, "evidence_refs", allow_empty=True)
    _validate_entity_refs(graph.entity_refs)
    _validate_compact_refs(graph.source_types, "source_types", allow_empty=False)
    edge_ids = _validate_compact_refs(graph.edge_ids, "edge_ids", allow_empty=False)
    if any(_EDGE_ID_RE.fullmatch(edge_id) is None for edge_id in edge_ids):
        raise MonitoringContractError("incident edge_id is invalid")

    stages = tuple(graph.stage_types)
    if not stages or len(set(stages)) != len(stages):
        raise MonitoringContractError("incident stage_types must be unique and non-empty")
    if any(stage not in STAGE_ORDER for stage in stages):
        raise MonitoringContractError("incident graph contains unsupported stage")
    if stages != tuple(stage for stage in STAGE_ORDER if stage in set(stages)):
        raise MonitoringContractError("incident stage_types must use canonical order")

    rules = tuple(graph.rule_ids)
    if not rules or len(set(rules)) != len(rules) or any(rule not in SUPPORTED_RULES for rule in rules):
        raise MonitoringContractError("incident graph contains unsupported or duplicate rule")

    required_stages = {
        RULE_DNS_FLOW: {"DNS", "FLOW"},
        RULE_FLOW_AUTH: {"FLOW", "AUTH"},
        RULE_AUTH_PROCESS: {"AUTH", "PROCESS"},
        RULE_IDS_CORROBORATION: {"IDS"},
    }
    stage_set = set(stages)
    for rule in rules:
        if not required_stages[rule].issubset(stage_set):
            raise MonitoringContractError("incident rule/stage binding is inconsistent")

    first = _iso(graph.first_seen, "first_seen")
    last = _iso(graph.last_seen, "last_seen")
    if first > last:
        raise MonitoringContractError("incident graph first_seen must not be after last_seen")

    # Touch values here so future IncidentGraph additions cannot silently bypass
    # the fields that form triage evidence identity.
    if not event_ids or evidence_refs is None:
        raise MonitoringContractError("incident graph evidence identity is invalid")
    return graph


def _classification(graph: IncidentGraph) -> tuple[str, str, str, tuple[str, ...]]:
    rules = set(graph.rule_ids)
    reasons: list[str] = []
    if RULE_DNS_FLOW in rules:
        reasons.append("exact_dns_flow")
    if RULE_FLOW_AUTH in rules:
        reasons.append("exact_flow_auth")
    if RULE_AUTH_PROCESS in rules:
        reasons.append("exact_auth_process")
    if RULE_IDS_CORROBORATION in rules:
        reasons.append("ids_exact_entity_corroboration")

    full_chain = {RULE_DNS_FLOW, RULE_FLOW_AUTH, RULE_AUTH_PROCESS}
    if full_chain.issubset(rules):
        kind = "dns-flow-auth-process"
        confidence = "high"
        priority = "high"
        reasons.append("complete_exact_multistage_chain")
    elif {RULE_FLOW_AUTH, RULE_AUTH_PROCESS}.issubset(rules):
        kind = "flow-auth-process"
        confidence = "high"
        priority = "high"
        reasons.append("exact_post_connection_execution_chain")
    elif {RULE_DNS_FLOW, RULE_FLOW_AUTH}.issubset(rules):
        kind = "dns-flow-auth"
        confidence = "high"
        priority = "elevated"
        reasons.append("exact_resolution_connection_auth_chain")
    elif RULE_AUTH_PROCESS in rules:
        kind = "auth-process"
        confidence = "medium"
        priority = "elevated"
    elif RULE_FLOW_AUTH in rules:
        kind = "flow-auth"
        confidence = "medium"
        priority = "elevated"
    elif RULE_DNS_FLOW in rules:
        kind = "dns-flow"
        confidence = "medium"
        priority = "normal"
    elif RULE_IDS_CORROBORATION in rules:
        kind = "ids-corroborated"
        confidence = "medium"
        priority = "elevated"
    else:
        kind = "mixed-correlated-activity"
        confidence = "low"
        priority = "normal"

    if RULE_IDS_CORROBORATION in rules and len(rules) > 1:
        confidence = "high"
        priority = "high" if graph.priority == "high" else "elevated"
        reasons.append("independent_ids_corroboration")
    if graph.priority == "high" or graph.severity in {"high", "critical"}:
        priority = "high"
        reasons.append("upstream_high_priority_evidence")

    return kind, confidence, priority, tuple(sorted(set(reasons)))


class DeterministicNetworkIncidentTriage:
    """Interpret exact correlation graphs locally without acquiring new evidence."""

    def __init__(self, config: NetworkTriageConfig | None = None):
        self.config = (config or NetworkTriageConfig()).validate()

    def triage(self, graphs: Iterable[IncidentGraph]) -> tuple[NetworkIncidentTriage, ...]:
        unique: dict[str, tuple[IncidentGraph, str]] = {}
        for raw in graphs:
            graph = _validate_graph(raw)
            fingerprint = sha256_fingerprint(graph.public_dict())
            previous = unique.get(graph.graph_id)
            if previous is not None:
                if previous[1] != fingerprint:
                    raise MonitoringContractError("duplicate graph_id has conflicting incident evidence")
                continue
            unique[graph.graph_id] = (graph, fingerprint)
            if len(unique) > self.config.max_graphs:
                raise MonitoringContractError("network triage graph bound exceeded")

        event_refs = sum(len(graph.event_ids) for graph, _ in unique.values())
        entity_refs = sum(len(graph.entity_refs) for graph, _ in unique.values())
        evidence_refs = sum(len(graph.evidence_refs) for graph, _ in unique.values())
        if event_refs > self.config.max_event_refs:
            raise MonitoringContractError("network triage event reference bound exceeded")
        if entity_refs > self.config.max_entity_refs:
            raise MonitoringContractError("network triage entity reference bound exceeded")
        if evidence_refs > self.config.max_evidence_refs:
            raise MonitoringContractError("network triage evidence reference bound exceeded")

        records: list[NetworkIncidentTriage] = []
        for graph, graph_fingerprint in sorted(unique.values(), key=lambda item: (item[0].first_seen, item[0].graph_id)):
            kind, confidence, priority, reasons = _classification(graph)
            identity = {
                "graph_id": graph.graph_id,
                "graph_fingerprint": graph_fingerprint,
                "triage_kind": kind,
                "confidence": confidence,
                "severity": graph.severity,
                "investigation_priority": priority,
                "reason_codes": list(reasons),
                "authority": "advisory",
            }
            triage_id = "triage-" + sha256_fingerprint(identity).split(":", 1)[1][:24]
            records.append(
                NetworkIncidentTriage(
                    triage_id=triage_id,
                    graph_id=graph.graph_id,
                    graph_fingerprint=graph_fingerprint,
                    triage_kind=kind,
                    confidence=confidence,
                    severity=graph.severity,
                    investigation_priority=priority,
                    reason_codes=reasons,
                    stage_types=tuple(graph.stage_types),
                    rule_ids=tuple(graph.rule_ids),
                    event_ids=tuple(graph.event_ids),
                    evidence_refs=tuple(graph.evidence_refs),
                    entity_refs=tuple(graph.entity_refs),
                    first_seen=graph.first_seen,
                    last_seen=graph.last_seen,
                )
            )
        return tuple(records)
