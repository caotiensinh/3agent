from __future__ import annotations

import pytest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.exfiltration_analysis import (
    ExfiltrationAssessment,
    ExfiltrationFlowObservation,
    analyze_exfiltration_metadata,
)


def flow(
    flow_id: str,
    *,
    bytes_out: int,
    baseline_p95_bytes: int = 1_000_000,
    destination_previously_seen: bool = True,
    protocol: str = "tls",
    minute: int = 0,
) -> ExfiltrationFlowObservation:
    return ExfiltrationFlowObservation(
        flow_id=flow_id,
        asset_ref="asset:host-a",
        destination_ref="destination:sha256:bbbb",
        protocol=protocol,
        observed_at=f"2026-09-03T00:{minute:02d}:00Z",
        evidence_ref=f"evidence:{flow_id}",
        bytes_out=bytes_out,
        baseline_p95_bytes=baseline_p95_bytes,
        destination_previously_seen=destination_previously_seen,
        process_ref="process:sha256:cccc",
        user_ref="user:sha256:dddd",
    )


def test_detects_large_new_destination_with_multi_session_evidence() -> None:
    assessment = analyze_exfiltration_metadata(
        (
            flow("a", bytes_out=8_000_000, destination_previously_seen=False, minute=1),
            flow("b", bytes_out=7_000_000, destination_previously_seen=False, minute=2),
        ),
        minimum_total_bytes=10_000_000,
    )

    assert len(assessment.candidates) == 1
    candidate = assessment.candidates[0]
    assert candidate.total_bytes_out == 15_000_000
    assert candidate.reasons == (
        "anomalous_outbound_volume",
        "multi_session_evidence",
        "new_destination",
    )
    assert candidate.process_refs == ("process:sha256:cccc",)
    assert candidate.user_refs == ("user:sha256:dddd",)
    assert assessment.payload_inspected is False
    assert assessment.authority == "advisory"
    assert assessment.fingerprint.startswith("sha256:")


def test_large_single_known_destination_without_corroboration_is_not_claimed() -> None:
    assessment = analyze_exfiltration_metadata(
        (flow("single", bytes_out=20_000_000, destination_previously_seen=True),),
        minimum_total_bytes=10_000_000,
    )
    assert assessment.candidates == ()


def test_baseline_multiplier_prevents_normal_volume_from_becoming_candidate() -> None:
    assessment = analyze_exfiltration_metadata(
        (
            flow("a", bytes_out=6_000_000, baseline_p95_bytes=5_000_000, destination_previously_seen=False),
            flow("b", bytes_out=6_000_000, baseline_p95_bytes=5_000_000, destination_previously_seen=False),
        ),
        minimum_total_bytes=1_000_000,
        baseline_multiplier=3.0,
    )
    assert assessment.candidates == ()


def test_dns_high_volume_is_metadata_reason_without_payload_inspection() -> None:
    assessment = analyze_exfiltration_metadata(
        (
            flow("dns-a", bytes_out=6_000_000, protocol="dns", minute=1),
            flow("dns-b", bytes_out=6_000_000, protocol="dns", minute=2),
        ),
        minimum_total_bytes=10_000_000,
    )
    assert len(assessment.candidates) == 1
    assert "high_volume_dns_channel" in assessment.candidates[0].reasons
    assert assessment.payload_inspected is False


def test_payload_inspection_and_invalid_multiplier_are_forbidden() -> None:
    invalid_flow = ExfiltrationFlowObservation(
        flow_id="raw",
        asset_ref="asset:host-a",
        destination_ref="destination:sha256:bbbb",
        protocol="tls",
        observed_at="2026-09-03T00:00:00Z",
        evidence_ref="evidence:raw",
        bytes_out=1,
        baseline_p95_bytes=0,
        destination_previously_seen=False,
        payload_inspected=True,
    )
    with pytest.raises(MonitoringContractError, match="metadata-only"):
        invalid_flow.validate()

    with pytest.raises(MonitoringContractError, match="baseline_multiplier"):
        analyze_exfiltration_metadata((), baseline_multiplier=0.5)

    invalid_assessment = ExfiltrationAssessment(candidates=(), flows_analyzed=0, payload_inspected=True)
    with pytest.raises(MonitoringContractError, match="metadata-only"):
        invalid_assessment.validate()
