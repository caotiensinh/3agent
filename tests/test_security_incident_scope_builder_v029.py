from __future__ import annotations

import pytest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.incident_scope_builder import (
    IncidentScopeAssessment,
    ScopeEvidenceLink,
    build_incident_scope,
)


def link(link_id: str, source: str, destination: str, *, relation: str = "authentication", minute: int = 0) -> ScopeEvidenceLink:
    return ScopeEvidenceLink(
        link_id=link_id,
        from_asset_ref=source,
        to_asset_ref=destination,
        relation=relation,
        observed_at=f"2026-09-03T00:{minute:02d}:00Z",
        evidence_ref=f"evidence:{link_id}",
    )


def test_expands_scope_only_through_evidence_backed_authorized_assets() -> None:
    assessment = build_incident_scope(
        (
            link("a-b", "asset:a", "asset:b", minute=1),
            link("b-c", "asset:b", "asset:c", relation="network", minute=2),
        ),
        seed_asset_refs=("asset:a",),
        authorized_asset_refs=("asset:a", "asset:b", "asset:c"),
    )

    assert [(asset.asset_ref, asset.depth) for asset in assessment.scoped_assets] == [
        ("asset:a", 0),
        ("asset:b", 1),
        ("asset:c", 2),
    ]
    assert assessment.evidence_refs == ("evidence:a-b", "evidence:b-c")
    assert assessment.active_discovery_performed is False
    assert assessment.authority == "advisory"
    assert assessment.fingerprint.startswith("sha256:")


def test_unknown_asset_fails_closed_instead_of_expanding_target_scope() -> None:
    with pytest.raises(MonitoringContractError, match="outside authorized inventory"):
        build_incident_scope(
            (link("unknown", "asset:a", "asset:unknown"),),
            seed_asset_refs=("asset:a",),
            authorized_asset_refs=("asset:a", "asset:b"),
        )


def test_depth_and_asset_bounds_mark_scope_as_truncated() -> None:
    rows = (
        link("a-b", "asset:a", "asset:b", minute=1),
        link("b-c", "asset:b", "asset:c", minute=2),
        link("c-d", "asset:c", "asset:d", minute=3),
    )
    by_depth = build_incident_scope(
        rows,
        seed_asset_refs=("asset:a",),
        authorized_asset_refs=("asset:a", "asset:b", "asset:c", "asset:d"),
        max_hops=1,
    )
    assert [asset.asset_ref for asset in by_depth.scoped_assets] == ["asset:a", "asset:b"]
    assert by_depth.truncated is True

    by_assets = build_incident_scope(
        rows,
        seed_asset_refs=("asset:a",),
        authorized_asset_refs=("asset:a", "asset:b", "asset:c", "asset:d"),
        max_assets=2,
    )
    assert [asset.asset_ref for asset in by_assets.scoped_assets] == ["asset:a", "asset:b"]
    assert by_assets.truncated is True


def test_seed_must_already_exist_in_inventory() -> None:
    with pytest.raises(MonitoringContractError, match="seed assets"):
        build_incident_scope(
            (),
            seed_asset_refs=("asset:unknown",),
            authorized_asset_refs=("asset:a",),
        )


def test_contract_explicitly_forbids_active_discovery() -> None:
    valid = build_incident_scope(
        (),
        seed_asset_refs=("asset:a",),
        authorized_asset_refs=("asset:a",),
    )
    invalid = IncidentScopeAssessment(
        seed_asset_refs=valid.seed_asset_refs,
        authorized_asset_refs=valid.authorized_asset_refs,
        scoped_assets=valid.scoped_assets,
        evidence_refs=valid.evidence_refs,
        truncated=False,
        active_discovery_performed=True,
    )
    with pytest.raises(MonitoringContractError, match="must not perform active discovery"):
        invalid.validate()
