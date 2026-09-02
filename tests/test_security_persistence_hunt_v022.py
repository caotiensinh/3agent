from __future__ import annotations

import pytest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.persistence_hunt import (
    PersistenceObservation,
    hunt_persistence,
)


def row(
    observation_id: str,
    *,
    mechanism: str = "scheduled_task",
    target_ref: str = "target:sha256:abc123",
    new_or_changed: bool = False,
    unsigned_target: bool = False,
    user_writable_target: bool = False,
    high_privilege_context: bool = False,
    enabled: bool = True,
    minute: int = 0,
) -> PersistenceObservation:
    return PersistenceObservation(
        observation_id=observation_id,
        asset_ref="asset:host-a",
        mechanism=mechanism,
        target_ref=target_ref,
        observed_at=f"2026-09-03T00:{minute:02d}:00Z",
        evidence_ref=f"evidence:{observation_id}",
        user_ref="user:sha256:aaaa",
        new_or_changed=new_or_changed,
        unsigned_target=unsigned_target,
        user_writable_target=user_writable_target,
        high_privilege_context=high_privilege_context,
        enabled=enabled,
    )


def test_requires_multiple_reasons_by_default() -> None:
    assessment = hunt_persistence(
        (
            row("one", new_or_changed=True, enabled=False),
            row("two", target_ref="target:sha256:def456", unsigned_target=True, enabled=False),
        )
    )
    assert assessment.candidates == ()
    assert assessment.observations_analyzed == 2


def test_correlates_reasons_and_evidence_for_same_persistence_identity() -> None:
    assessment = hunt_persistence(
        (
            row("a", new_or_changed=True, minute=1),
            row("b", unsigned_target=True, user_writable_target=True, minute=2),
        )
    )

    assert len(assessment.candidates) == 1
    candidate = assessment.candidates[0]
    assert candidate.mechanism == "scheduled_task"
    assert candidate.reasons == (
        "enabled_persistence",
        "new_or_changed",
        "unsigned_target",
        "user_writable_target",
    )
    assert candidate.evidence_refs == ("evidence:a", "evidence:b")
    assert candidate.first_seen.endswith("00:01:00Z")
    assert candidate.last_seen.endswith("00:02:00Z")
    assert 0.0 < candidate.confidence < 1.0
    assert assessment.authority == "advisory"
    assert assessment.fingerprint.startswith("sha256:")


def test_does_not_merge_different_mechanisms_or_targets() -> None:
    assessment = hunt_persistence(
        (
            row("a", mechanism="service", new_or_changed=True, unsigned_target=True),
            row(
                "b",
                mechanism="run_key",
                target_ref="target:sha256:other",
                user_writable_target=True,
                high_privilege_context=True,
            ),
        )
    )
    assert len(assessment.candidates) == 2
    assert {candidate.mechanism for candidate in assessment.candidates} == {"service", "run_key"}


def test_rejects_raw_paths_and_non_boolean_flags() -> None:
    with pytest.raises(MonitoringContractError, match="filesystem path"):
        row("bad", target_ref=r"C:\\Users\\Public\\evil.exe", new_or_changed=True).validate()

    invalid = PersistenceObservation(
        observation_id="bad-bool",
        asset_ref="asset:host-a",
        mechanism="service",
        target_ref="target:sha256:abc",
        observed_at="2026-09-03T00:00:00Z",
        evidence_ref="evidence:bad-bool",
        new_or_changed=1,  # type: ignore[arg-type]
        unsigned_target=False,
        user_writable_target=False,
        high_privilege_context=False,
    )
    with pytest.raises(MonitoringContractError, match="boolean"):
        invalid.validate()


def test_rejects_unsupported_mechanism_and_unbounded_threshold() -> None:
    with pytest.raises(MonitoringContractError, match="unsupported persistence mechanism"):
        row("bad-mechanism", mechanism="shell_rc", new_or_changed=True).validate()

    with pytest.raises(MonitoringContractError, match="minimum_reasons"):
        hunt_persistence((row("a", new_or_changed=True),), minimum_reasons=0)
