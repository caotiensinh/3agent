from __future__ import annotations

import pytest

from three_agent.security_monitoring.anti_forensics_detection import (
    AntiForensicsAssessment,
    AntiForensicsObservation,
    detect_anti_forensics,
)
from three_agent.security_monitoring.contracts import MonitoringContractError


def row(
    observation_id: str,
    *,
    observation_type: str,
    indicator_present: bool = True,
    externally_corroborated: bool = False,
    minute: int = 0,
) -> AntiForensicsObservation:
    return AntiForensicsObservation(
        observation_id=observation_id,
        asset_ref="asset:host-a",
        observation_type=observation_type,
        observed_at=f"2026-09-03T00:{minute:02d}:00Z",
        evidence_ref=f"evidence:{observation_id}",
        indicator_present=indicator_present,
        externally_corroborated=externally_corroborated,
    )


def test_requires_destructive_indicator_and_corroboration() -> None:
    single = detect_anti_forensics((row("clear", observation_type="log_clear"),))
    assert single.findings == ()

    correlated = detect_anti_forensics(
        (
            row("clear", observation_type="log_clear", minute=1),
            row("gap", observation_type="telemetry_gap", minute=2),
        )
    )
    assert len(correlated.findings) == 1
    finding = correlated.findings[0]
    assert finding.indicators == ("log_clear", "telemetry_gap")
    assert finding.evidence_integrity_degraded is True
    assert correlated.evidence_absence_interpretation == "unknown_not_clean"
    assert correlated.authority == "advisory"
    assert correlated.fingerprint.startswith("sha256:")


def test_telemetry_gap_alone_is_not_compromise_claim_or_clean_bill() -> None:
    assessment = detect_anti_forensics((row("gap", observation_type="telemetry_gap"),))
    assert assessment.findings == ()
    assert assessment.evidence_absence_interpretation == "unknown_not_clean"


def test_external_corroboration_supports_destructive_observation() -> None:
    assessment = detect_anti_forensics(
        (row("audit", observation_type="audit_disabled", externally_corroborated=True),)
    )
    assert len(assessment.findings) == 1
    assert assessment.findings[0].indicators == ("audit_disabled",)


def test_non_boolean_and_unknown_indicator_are_rejected() -> None:
    invalid = AntiForensicsObservation(
        observation_id="bad",
        asset_ref="asset:host-a",
        observation_type="log_clear",
        observed_at="2026-09-03T00:00:00Z",
        evidence_ref="evidence:bad",
        indicator_present=1,  # type: ignore[arg-type]
    )
    with pytest.raises(MonitoringContractError, match="boolean"):
        invalid.validate()

    with pytest.raises(MonitoringContractError, match="unsupported anti-forensics observation type"):
        row("unknown", observation_type="unknown_cleanup").validate()


def test_contract_forbids_interpreting_missing_evidence_as_clean() -> None:
    invalid = AntiForensicsAssessment(
        findings=(),
        observations_analyzed=0,
        evidence_absence_interpretation="clean",
    )
    with pytest.raises(MonitoringContractError, match="clean host"):
        invalid.validate()
