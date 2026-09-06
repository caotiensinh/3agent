from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Mapping

from .contracts import MonitoringContractError
from .correlation_graph import (
    CorrelationEvent,
    CorrelationGraphConfig,
    DeterministicIncidentCorrelator,
    STAGE_FLOW,
    STAGE_ORDER,
)
from .flow_analysis import analyze_flow_evidence
from .incident_timeline import build_incident_timeline

OPERATOR_POSTURE_SCHEMA = "workspace-security-monitoring/operator-posture-v1"
OPERATOR_POSTURE_EVENT_LIMIT = 100
OPERATOR_POSTURE_ENTITY_LIMIT = 4096
OPERATOR_POSTURE_EDGE_LIMIT = 2048
OPERATOR_POSTURE_WINDOW_SECONDS = 900

_SEVERITIES = ("info", "low", "medium", "high", "critical")
_HEALTH_BUCKETS = ("healthy", "degraded", "unreachable", "unknown")
_PRIORITY_BUCKETS = ("normal", "high", "other")
_RECENCY_BUCKETS = ("last_15m", "15m_to_1h", "1h_to_24h", "older", "future")


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _items(value: object, *, limit: int) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value[:limit] if isinstance(item, Mapping))


def _count(value: object) -> int:
    if isinstance(value, bool):
        return 0
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0
    return max(0, number)


def _severity_counts(raw: object) -> dict[str, int]:
    source = _mapping(raw)
    return {severity: _count(source.get(severity)) for severity in _SEVERITIES}


def _asset_health(assets: Mapping[str, object]) -> dict[str, object]:
    counts = {key: 0 for key in _HEALTH_BUCKETS}
    enabled_count = 0
    for item in _items(assets.get("items"), limit=1000):
        if item.get("enabled") is not True:
            continue
        enabled_count += 1
        state = _mapping(item.get("observed_state"))
        status = str(state.get("last_status") or "").strip().lower()
        if status == "ok":
            bucket = "healthy"
        elif status in {"unreachable", "timeout"}:
            bucket = "unreachable"
        elif status in {"error", "unsupported", "discontinuity"}:
            bucket = "degraded"
        else:
            bucket = "unknown"
        counts[bucket] += 1
    return {
        "scope": "enabled_assets_latest_observation",
        "enabled_asset_sample_count": enabled_count,
        "state_counts": counts,
    }


def _recency_bucket(observed_at: str, *, now: datetime) -> str:
    try:
        observed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError:
        return "older"
    if observed.tzinfo is None:
        return "older"
    age = (now - observed.astimezone(timezone.utc)).total_seconds()
    if age < 0:
        return "future"
    if age <= 15 * 60:
        return "last_15m"
    if age <= 60 * 60:
        return "15m_to_1h"
    if age <= 24 * 60 * 60:
        return "1h_to_24h"
    return "older"


def reduce_operator_posture(
    *,
    soc: Mapping[str, object],
    assets: Mapping[str, object],
    correlation_events: Iterable[CorrelationEvent],
    now: datetime | None = None,
) -> dict[str, object]:
    """Reduce canonical read-only monitoring truth to privacy-safe operator aggregates.

    The reducer accepts already-normalized in-process objects but never returns their
    identifiers, entity/evidence references, categories, source IDs, raw values, exact
    timestamps, rule IDs, graph IDs, or network addressing. All public dimensions are
    fixed enums or numeric aggregates.
    """

    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    events = tuple(correlation_events)
    if len(events) > OPERATOR_POSTURE_EVENT_LIMIT:
        raise MonitoringContractError("operator posture event bound exceeded")

    risk_source = _mapping(soc.get("risk_summary"))
    overview = _mapping(soc.get("overview"))
    today = _mapping(overview.get("today"))
    risk = {
        "today_open_high_critical": _count(risk_source.get("today_open_high_critical")),
        "rolling_7d_open_high_critical": _count(risk_source.get("rolling_7d_open_high_critical")),
        "rolling_30d_open_high_critical": _count(risk_source.get("rolling_30d_open_high_critical")),
        "today_data_gaps": _count(risk_source.get("today_data_gaps")),
        "today_event_count": _count(today.get("event_count")),
        "today_finding_count": _count(today.get("finding_count")),
        "today_severity_counts": _severity_counts(today.get("severity_counts")),
    }

    graph_config = CorrelationGraphConfig(
        window_seconds=OPERATOR_POSTURE_WINDOW_SECONDS,
        max_events=OPERATOR_POSTURE_EVENT_LIMIT,
        max_entities=OPERATOR_POSTURE_ENTITY_LIMIT,
        max_edges=OPERATOR_POSTURE_EDGE_LIMIT,
    )
    graphs = DeterministicIncidentCorrelator(graph_config).correlate(events)
    graph_severity = {severity: 0 for severity in _SEVERITIES}
    graph_priority = {priority: 0 for priority in _PRIORITY_BUCKETS}
    graph_stage_counts = {stage: 0 for stage in STAGE_ORDER}
    correlated_event_ids: set[str] = set()
    for graph in graphs:
        graph_severity[graph.severity] += 1
        priority = graph.priority if graph.priority in {"normal", "high"} else "other"
        graph_priority[priority] += 1
        correlated_event_ids.update(graph.event_ids)
        for stage in graph.stage_types:
            if stage in graph_stage_counts:
                graph_stage_counts[stage] += 1

    correlation = {
        "sample_event_count": len(events),
        "incident_graph_count": len(graphs),
        "correlated_event_count": len(correlated_event_ids),
        "multi_stage_graph_count": sum(len(graph.stage_types) >= 3 for graph in graphs),
        "severity_counts": graph_severity,
        "priority_counts": graph_priority,
        "stage_graph_counts": graph_stage_counts,
        "exact_correlation_observed": bool(graphs),
    }

    evidence_events = tuple(
        item for item in events if item.stage is not None and item.event.evidence_ref is not None
    )
    has_flow = any(item.stage == STAGE_FLOW for item in evidence_events)
    flow: dict[str, object] = {
        "available": False,
        "event_count": 0,
        "flow_event_count": 0,
        "incident_graph_count": 0,
        "severity_counts": {severity: 0 for severity in _SEVERITIES},
        "stage_present": {stage: False for stage in STAGE_ORDER},
        "cross_stage_correlation_observed": False,
    }
    if has_flow:
        analysis = analyze_flow_evidence(evidence_events)
        flow = {
            "available": True,
            "event_count": analysis.event_count,
            "flow_event_count": analysis.flow_event_count,
            "incident_graph_count": len(analysis.incident_graphs),
            "severity_counts": {severity: dict(analysis.severity_counts).get(severity, 0) for severity in _SEVERITIES},
            "stage_present": {stage: stage in analysis.stage_types for stage in STAGE_ORDER},
            "cross_stage_correlation_observed": bool(analysis.incident_graphs),
        }

    timeline: dict[str, object] = {
        "available": False,
        "entry_count": 0,
        "incident_graph_count": 0,
        "stage_counts": {stage: 0 for stage in STAGE_ORDER},
        "severity_counts": {severity: 0 for severity in _SEVERITIES},
        "recency_counts": {bucket: 0 for bucket in _RECENCY_BUCKETS},
    }
    if graphs and evidence_events:
        built = build_incident_timeline(evidence_events)
        stage_counts = {stage: 0 for stage in STAGE_ORDER}
        severity_counts = {severity: 0 for severity in _SEVERITIES}
        recency_counts = {bucket: 0 for bucket in _RECENCY_BUCKETS}
        for entry in built.entries:
            stage_counts[entry.stage] += 1
            severity_counts[entry.severity] += 1
            recency_counts[_recency_bucket(entry.observed_at, now=current)] += 1
        timeline = {
            "available": True,
            "entry_count": built.entry_count,
            "incident_graph_count": built.graph_count,
            "stage_counts": stage_counts,
            "severity_counts": severity_counts,
            "recency_counts": recency_counts,
        }

    return {
        "schema_version": OPERATOR_POSTURE_SCHEMA,
        "count_scope": "bounded_query_only_operator_projection",
        "max_correlation_events": OPERATOR_POSTURE_EVENT_LIMIT,
        "risk": risk,
        "asset_health": _asset_health(assets),
        "correlation": correlation,
        "flow": flow,
        "timeline": timeline,
        "contains_raw_evidence": False,
        "contains_raw_credentials": False,
        "authority": {
            "aggregate_only": True,
            "database_read_only": True,
            "exact_timestamps_exposed": False,
            "event_ids_exposed": False,
            "graph_ids_exposed": False,
            "entity_refs_exposed": False,
            "evidence_refs_exposed": False,
            "rule_ids_exposed": False,
            "asset_ids_exposed": False,
            "network_addresses_exposed": False,
            "raw_values_exposed": False,
            "browser_filters_exposed": False,
            "database_write": False,
            "network_execution": False,
            "collector_execution": False,
            "packet_capture_execution": False,
            "remediation_execution": False,
        },
    }
