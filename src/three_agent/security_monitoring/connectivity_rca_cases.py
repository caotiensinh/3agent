from __future__ import annotations

from dataclasses import dataclass

CONNECTIVITY_RCA_CORPUS_SCHEMA = "workspace-security-monitoring/connectivity-rca-corpus-v1"


@dataclass(frozen=True)
class ConnectivityRcaCase:
    case_id: str
    observed_facts: tuple[str, ...]
    expected_status: str
    expected_root_cause: str | None
    required_evidence_classes: tuple[str, ...]
    forbidden_claims: tuple[str, ...] = ("confirmed_without_quorum",)
    schema_version: str = CONNECTIVITY_RCA_CORPUS_SCHEMA


CONNECTIVITY_RCA_CASES = (
    ConnectivityRcaCase(
        "endpoint_only_down",
        ("gateway_reachable", "peer_endpoints_reachable", "endpoint_unreachable"),
        "supported",
        "endpoint_local_failure",
        ("reachability", "endpoint_state"),
    ),
    ConnectivityRcaCase(
        "gateway_and_downstream_down",
        ("gateway_unreachable", "multiple_downstream_unreachable"),
        "supported",
        "gateway_or_upstream_failure",
        ("reachability", "declared_dependency", "power_or_path"),
    ),
    ConnectivityRcaCase(
        "config_drift_after_change",
        ("previous_path_working", "configuration_drift_detected", "path_failed_after_drift"),
        "supported",
        "configuration_change_candidate",
        ("configuration_snapshot", "reachability", "timeline"),
    ),
    ConnectivityRcaCase(
        "dns_dependency_failure",
        ("ip_connectivity_ok", "name_resolution_failed", "dns_dependency_declared"),
        "supported",
        "dns_service_failure",
        ("reachability", "dns_event", "declared_dependency"),
    ),
    ConnectivityRcaCase(
        "insufficient_power_evidence",
        ("endpoint_unreachable", "gateway_reachable", "no_endpoint_power_telemetry"),
        "data_gap",
        None,
        ("reachability", "power"),
        ("power_failure_confirmed", "confirmed_without_quorum"),
    ),
)


def validate_connectivity_rca_corpus() -> tuple[ConnectivityRcaCase, ...]:
    ids: set[str] = set()
    for case in CONNECTIVITY_RCA_CASES:
        if not case.case_id or case.case_id in ids:
            raise ValueError("connectivity RCA case IDs must be unique")
        ids.add(case.case_id)
        if case.expected_status not in {"supported", "data_gap", "contradicted"}:
            raise ValueError("unsupported expected RCA status")
        if case.expected_status != "supported" and case.expected_root_cause is not None:
            raise ValueError("non-supported RCA cases cannot claim a root cause")
        if len(set(case.required_evidence_classes)) != len(case.required_evidence_classes):
            raise ValueError("required evidence classes must be unique")
        if "confirmed_without_quorum" not in case.forbidden_claims:
            raise ValueError("all cases must forbid confirmation without quorum")
    return CONNECTIVITY_RCA_CASES
