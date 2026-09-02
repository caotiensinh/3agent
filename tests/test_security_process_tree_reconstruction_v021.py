from __future__ import annotations

import pytest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.process_tree_reconstruction import (
    ProcessObservation,
    reconstruct_process_tree,
)


def obs(
    process_ref: str,
    *,
    parent: str | None = None,
    asset: str = "asset:host-a",
    minute: int = 0,
) -> ProcessObservation:
    return ProcessObservation(
        event_id=f"event:{asset.split(':')[-1]}:{process_ref.split(':')[-1]}",
        asset_ref=asset,
        process_ref=process_ref,
        parent_process_ref=parent,
        user_ref="user:sha256:aaaaaaaa",
        observed_at=f"2026-09-03T00:{minute:02d}:00Z",
        evidence_ref=f"evidence:{asset.split(':')[-1]}:{process_ref.split(':')[-1]}",
    )


def test_reconstructs_deterministic_descendant_tree_without_cross_asset_contamination() -> None:
    rows = (
        obs("process:child-b", parent="process:root", minute=2),
        obs("process:root", minute=0),
        obs("process:grandchild", parent="process:child-a", minute=3),
        obs("process:child-a", parent="process:root", minute=1),
        obs("process:foreign", asset="asset:host-b", minute=4),
    )

    result = reconstruct_process_tree(rows, asset_ref="asset:host-a", root_process_ref="process:root")

    assert [node.process_ref for node in result.nodes] == [
        "process:root",
        "process:child-a",
        "process:child-b",
        "process:grandchild",
    ]
    assert [node.depth for node in result.nodes] == [0, 1, 1, 2]
    assert result.orphan_process_refs == ()
    assert result.cycle_process_refs == ()
    assert result.truncated is False
    assert result.authority == "advisory"
    assert result.fingerprint.startswith("sha256:")


def test_reports_orphans_and_cycles_without_guessing_edges() -> None:
    rows = (
        obs("process:root"),
        obs("process:orphan", parent="process:missing", minute=1),
        obs("process:cycle-a", parent="process:cycle-b", minute=2),
        obs("process:cycle-b", parent="process:cycle-a", minute=3),
    )

    result = reconstruct_process_tree(rows, asset_ref="asset:host-a", root_process_ref="process:root")

    assert [node.process_ref for node in result.nodes] == ["process:root"]
    assert result.orphan_process_refs == ("process:orphan",)
    assert result.cycle_process_refs == ("process:cycle-a", "process:cycle-b")


def test_rejects_conflicting_parentage_for_same_process_identity() -> None:
    rows = (
        obs("process:root"),
        obs("process:child", parent="process:root", minute=1),
        obs("process:child", parent="process:other", minute=1),
    )

    with pytest.raises(MonitoringContractError, match="conflicting observations"):
        reconstruct_process_tree(rows, asset_ref="asset:host-a", root_process_ref="process:root")


def test_enforces_node_and_depth_bounds() -> None:
    rows = (
        obs("process:root"),
        obs("process:a", parent="process:root", minute=1),
        obs("process:b", parent="process:a", minute=2),
    )

    by_nodes = reconstruct_process_tree(
        rows,
        asset_ref="asset:host-a",
        root_process_ref="process:root",
        max_nodes=1,
    )
    assert [node.process_ref for node in by_nodes.nodes] == ["process:root"]
    assert by_nodes.truncated is True

    by_depth = reconstruct_process_tree(
        rows,
        asset_ref="asset:host-a",
        root_process_ref="process:root",
        max_depth=1,
    )
    assert [node.process_ref for node in by_depth.nodes] == ["process:root", "process:a"]
    assert by_depth.truncated is True


def test_requires_timezone_and_exact_root_evidence() -> None:
    invalid = ProcessObservation(
        event_id="event:1",
        asset_ref="asset:host-a",
        process_ref="process:root",
        observed_at="2026-09-03T00:00:00",
        evidence_ref="evidence:1",
    )
    with pytest.raises(MonitoringContractError, match="timezone"):
        reconstruct_process_tree((invalid,), asset_ref="asset:host-a", root_process_ref="process:root")

    with pytest.raises(MonitoringContractError, match="root process"):
        reconstruct_process_tree((obs("process:other"),), asset_ref="asset:host-a", root_process_ref="process:root")
