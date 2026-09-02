from __future__ import annotations

import json

import pytest

from three_agent.security_monitoring.asset_dependency import (
    MAX_DEPENDENCIES,
    MAX_IMPACT_SEEDS,
    AssetDependency,
    DeclaredAssetDependencyGraph,
)
from three_agent.security_monitoring.contracts import AssetInventoryRecord, MonitoringContractError


def _asset(asset_id: str, host: str, *, enabled: bool = True) -> AssetInventoryRecord:
    return AssetInventoryRecord(
        asset_id=asset_id,
        role="server",
        management_host=host,
        collector_capabilities=("local_net_read",),
        enabled=enabled,
    )


def _declaration(char: str) -> str:
    return "sha256:" + char * 64


def _dependency(
    upstream: str,
    downstream: str,
    relation: str = "application_service",
    marker: str = "a",
) -> AssetDependency:
    return AssetDependency(
        upstream_asset_id=upstream,
        downstream_asset_id=downstream,
        relation=relation,
        declaration_sha256=_declaration(marker),
    )


def test_transitive_impact_is_deterministic_and_metadata_only() -> None:
    assets = [
        _asset("dns-01", "192.0.2.10"),
        _asset("app-01", "192.0.2.20"),
        _asset("db-01", "192.0.2.30"),
        _asset("unrelated-01", "192.0.2.40"),
    ]
    dependencies = [
        _dependency("dns-01", "app-01", "dns_service", "a"),
        _dependency("app-01", "db-01", "storage_service", "b"),
    ]

    first = DeclaredAssetDependencyGraph(assets, dependencies).impact(["dns-01"])
    second = DeclaredAssetDependencyGraph(reversed(assets), reversed(dependencies)).impact(["dns-01"])

    assert first == second
    assert first.potentially_affected_asset_ids == ("app-01", "db-01")
    assert first.depth_by_asset == (("app-01", 1), ("db-01", 2))
    assert first.truncated is False
    assert first.authority == "advisory"
    assert first.basis == "declared_dependencies_only"
    assert first.impact_type == "potential_dependency_impact"
    assert first.downstream_state_confirmed is False
    assert first.discovery_performed is False
    assert first.inferred_topology is False
    assert first.network_executed is False
    assert first.remediation_executed is False

    public = json.dumps(first.public_dict(), sort_keys=True)
    assert "192.0.2." not in public
    assert "credential" not in public.lower()
    assert "unrelated-01" not in public


def test_dependency_endpoint_must_be_enabled_approved_inventory() -> None:
    enabled = _asset("app-01", "192.0.2.20")
    disabled = _asset("db-01", "192.0.2.30", enabled=False)

    with pytest.raises(MonitoringContractError, match="enabled approved inventory"):
        DeclaredAssetDependencyGraph(
            [enabled, disabled],
            [_dependency("app-01", "db-01")],
        )

    with pytest.raises(MonitoringContractError, match="enabled approved inventory"):
        DeclaredAssetDependencyGraph(
            [enabled],
            [_dependency("app-01", "ghost-01")],
        )


def test_dependency_contract_rejects_self_loop_and_open_taxonomy() -> None:
    with pytest.raises(MonitoringContractError, match="self-loops"):
        _dependency("app-01", "app-01").validate()

    with pytest.raises(MonitoringContractError, match="unsupported asset dependency relation"):
        _dependency("app-01", "db-01", "model_inferred_route").validate()


def test_conflicting_duplicate_asset_id_fails_closed() -> None:
    with pytest.raises(MonitoringContractError, match="conflicting inventory content"):
        DeclaredAssetDependencyGraph(
            [
                _asset("app-01", "192.0.2.20"),
                _asset("app-01", "192.0.2.21"),
            ],
            [],
        )


def test_cycle_terminates_without_promoting_seed_to_affected() -> None:
    graph = DeclaredAssetDependencyGraph(
        [
            _asset("a-01", "192.0.2.1"),
            _asset("b-01", "192.0.2.2"),
            _asset("c-01", "192.0.2.3"),
        ],
        [
            _dependency("a-01", "b-01", marker="a"),
            _dependency("b-01", "c-01", marker="b"),
            _dependency("c-01", "a-01", marker="c"),
        ],
    )

    result = graph.impact(["a-01"])

    assert result.potentially_affected_asset_ids == ("b-01", "c-01")
    assert result.depth_by_asset == (("b-01", 1), ("c-01", 2))
    assert result.truncated is False


def test_unknown_or_disabled_seed_fails_closed() -> None:
    graph = DeclaredAssetDependencyGraph(
        [
            _asset("enabled-01", "192.0.2.1"),
            _asset("disabled-01", "192.0.2.2", enabled=False),
        ],
        [],
    )

    with pytest.raises(MonitoringContractError, match="enabled approved inventory"):
        graph.impact(["unknown-01"])

    with pytest.raises(MonitoringContractError, match="enabled approved inventory"):
        graph.impact(["disabled-01"])


def test_depth_limit_marks_assessment_truncated_without_inventing_impact() -> None:
    graph = DeclaredAssetDependencyGraph(
        [
            _asset("a-01", "192.0.2.1"),
            _asset("b-01", "192.0.2.2"),
            _asset("c-01", "192.0.2.3"),
        ],
        [
            _dependency("a-01", "b-01", marker="a"),
            _dependency("b-01", "c-01", marker="b"),
        ],
    )

    result = graph.impact(["a-01"], max_depth=1)

    assert result.potentially_affected_asset_ids == ("b-01",)
    assert result.depth_by_asset == (("b-01", 1),)
    assert result.truncated is True
    assert "c-01" not in result.potentially_affected_asset_ids


def test_dependency_and_seed_iterables_are_consumed_only_to_hard_bounds() -> None:
    assets = [_asset("a-01", "192.0.2.1"), _asset("b-01", "192.0.2.2")]
    repeated = _dependency("a-01", "b-01")

    def too_many_dependencies():
        for _ in range(MAX_DEPENDENCIES + 1):
            yield repeated
        raise AssertionError("dependency iterator consumed past hard bound")

    with pytest.raises(MonitoringContractError, match="dependency bound exceeded"):
        DeclaredAssetDependencyGraph(assets, too_many_dependencies())

    graph = DeclaredAssetDependencyGraph(assets, [repeated])

    def too_many_seeds():
        for _ in range(MAX_IMPACT_SEEDS + 1):
            yield "a-01"
        raise AssertionError("seed iterator consumed past hard bound")

    with pytest.raises(MonitoringContractError, match="seed bound exceeded"):
        graph.impact(too_many_seeds())
