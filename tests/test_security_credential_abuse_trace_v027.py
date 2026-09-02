from __future__ import annotations

import pytest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.credential_abuse_trace import (
    AuthForensicEvent,
    trace_credential_abuse,
)


def event(
    event_id: str,
    *,
    outcome: str,
    minute: int,
    asset_ref: str = "asset:host-a",
    auth_method: str = "ntlm",
    privileged_context: bool = False,
) -> AuthForensicEvent:
    return AuthForensicEvent(
        event_id=event_id,
        asset_ref=asset_ref,
        user_ref="user:sha256:aaaa",
        source_ref="source:sha256:bbbb",
        observed_at=f"2026-09-03T00:{minute:02d}:00Z",
        evidence_ref=f"evidence:{event_id}",
        outcome=outcome,
        auth_method=auth_method,
        privileged_context=privileged_context,
    )


def test_detects_success_after_bounded_failure_burst() -> None:
    events = tuple(event(f"fail-{minute}", outcome="failure", minute=minute) for minute in range(1, 6)) + (
        event("success", outcome="success", minute=6, privileged_context=True),
    )
    assessment = trace_credential_abuse(
        events,
        authorized_asset_refs=("asset:host-a",),
        failure_threshold=5,
        window_minutes=15,
    )

    assert len(assessment.candidates) == 1
    candidate = assessment.candidates[0]
    assert candidate.failure_count == 5
    assert candidate.reasons == ("privileged_success", "success_after_failure_burst")
    assert candidate.success_event_id == "success"
    assert len(candidate.evidence_refs) == 6
    assert assessment.credential_material_accessed is False
    assert assessment.authority == "advisory"
    assert assessment.fingerprint.startswith("sha256:")


def test_does_not_flag_failures_without_later_success() -> None:
    events = tuple(event(f"fail-{minute}", outcome="failure", minute=minute) for minute in range(1, 8))
    assessment = trace_credential_abuse(events, authorized_asset_refs=("asset:host-a",))
    assert assessment.candidates == ()


def test_time_window_excludes_old_failures() -> None:
    events = (
        event("old-1", outcome="failure", minute=1),
        event("old-2", outcome="failure", minute=2),
        event("old-3", outcome="failure", minute=3),
        event("old-4", outcome="failure", minute=4),
        event("old-5", outcome="failure", minute=5),
        event("success", outcome="success", minute=30),
    )
    assessment = trace_credential_abuse(
        events,
        authorized_asset_refs=("asset:host-a",),
        window_minutes=10,
    )
    assert assessment.candidates == ()


def test_multi_asset_identity_use_requires_assets_to_be_authorized() -> None:
    events = tuple(event(f"fail-{minute}", outcome="failure", minute=minute) for minute in range(1, 5)) + (
        event("fail-b", outcome="failure", minute=5, asset_ref="asset:host-b"),
        event("success", outcome="success", minute=6, asset_ref="asset:host-b"),
    )
    assessment = trace_credential_abuse(
        events,
        authorized_asset_refs=("asset:host-a", "asset:host-b"),
    )
    assert "multi_asset_identity_use" in assessment.candidates[0].reasons

    with pytest.raises(MonitoringContractError, match="authorized asset scope"):
        trace_credential_abuse(events, authorized_asset_refs=("asset:host-a",))


def test_rejects_invalid_threshold_and_never_allows_credential_material_access() -> None:
    with pytest.raises(MonitoringContractError, match="failure_threshold"):
        trace_credential_abuse((), authorized_asset_refs=("asset:host-a",), failure_threshold=1)

    assessment = trace_credential_abuse((), authorized_asset_refs=("asset:host-a",))
    invalid = type(assessment)(
        candidates=(),
        events_analyzed=0,
        authorized_asset_refs=("asset:host-a",),
        credential_material_accessed=True,
    )
    with pytest.raises(MonitoringContractError, match="must not access credential material"):
        invalid.validate()
