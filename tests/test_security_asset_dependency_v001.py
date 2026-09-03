from __future__ import annotations

import json
import unittest

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


class AssetDependencyV001Tests(unittest.TestCase):
    def test_transitive_impact_is_deterministic_and_metadata_only(self) -> None:
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

        self.assertEqual(first, second)
        self.assertEqual(first.potentially_affected_asset_ids, ("app-01", "db-01"))
        self.assertEqual(first.depth_by_asset, (("app-01", 1), ("db-01", 2)))
        self.assertFalse(first.truncated)
        self.assertEqual(first.authority, "advisory")
        self.assertEqual(first.basis, "declared_dependencies_only")
        self.assertEqual(first.impact_type, "potential_dependency_impact")
        self.assertFalse(first.downstream_state_confirmed)
        self.assertFalse(first.discovery_performed)
        self.assertFalse(first.inferred_topology)
        self.assertFalse(first.network_executed)
        self.assertFalse(first.remediation_executed)

        public = json.dumps(first.public_dict(), sort_keys=True)
        self.assertNotIn("192.0.2.", public)
        self.assertNotIn("credential", public.lower())
        self.assertNotIn("unrelated-01", public)

    def test_dependency_endpoint_must_be_enabled_approved_inventory(self) -> None:
        enabled = _asset("app-01", "192.0.2.20")
        disabled = _asset("db-01", "192.0.2.30", enabled=False)

        with self.assertRaisesRegex(MonitoringContractError, "enabled approved inventory"):
            DeclaredAssetDependencyGraph(
                [enabled, disabled],
                [_dependency("app-01", "db-01")],
            )

        with self.assertRaisesRegex(MonitoringContractError, "enabled approved inventory"):
            DeclaredAssetDependencyGraph(
                [enabled],
                [_dependency("app-01", "ghost-01")],
            )

    def test_dependency_contract_rejects_self_loop_and_open_taxonomy(self) -> None:
        with self.assertRaisesRegex(MonitoringContractError, "self-loops"):
            _dependency("app-01", "app-01").validate()

        with self.assertRaisesRegex(MonitoringContractError, "unsupported asset dependency relation"):
            _dependency("app-01", "db-01", "model_inferred_route").validate()

    def test_conflicting_duplicate_asset_id_fails_closed(self) -> None:
        with self.assertRaisesRegex(MonitoringContractError, "conflicting inventory content"):
            DeclaredAssetDependencyGraph(
                [
                    _asset("app-01", "192.0.2.20"),
                    _asset("app-01", "192.0.2.21"),
                ],
                [],
            )

    def test_cycle_terminates_without_promoting_seed_to_affected(self) -> None:
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

        self.assertEqual(result.potentially_affected_asset_ids, ("b-01", "c-01"))
        self.assertEqual(result.depth_by_asset, (("b-01", 1), ("c-01", 2)))
        self.assertFalse(result.truncated)

    def test_unknown_or_disabled_seed_fails_closed(self) -> None:
        graph = DeclaredAssetDependencyGraph(
            [
                _asset("enabled-01", "192.0.2.1"),
                _asset("disabled-01", "192.0.2.2", enabled=False),
            ],
            [],
        )

        with self.assertRaisesRegex(MonitoringContractError, "enabled approved inventory"):
            graph.impact(["unknown-01"])

        with self.assertRaisesRegex(MonitoringContractError, "enabled approved inventory"):
            graph.impact(["disabled-01"])

    def test_depth_limit_marks_assessment_truncated_without_inventing_impact(self) -> None:
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

        self.assertEqual(result.potentially_affected_asset_ids, ("b-01",))
        self.assertEqual(result.depth_by_asset, (("b-01", 1),))
        self.assertTrue(result.truncated)
        self.assertNotIn("c-01", result.potentially_affected_asset_ids)

    def test_dependency_and_seed_iterables_are_consumed_only_to_hard_bounds(self) -> None:
        assets = [_asset("a-01", "192.0.2.1"), _asset("b-01", "192.0.2.2")]
        repeated = _dependency("a-01", "b-01")

        def too_many_dependencies():
            for _ in range(MAX_DEPENDENCIES + 1):
                yield repeated
            raise AssertionError("dependency iterator consumed past hard bound")

        with self.assertRaisesRegex(MonitoringContractError, "dependency bound exceeded"):
            DeclaredAssetDependencyGraph(assets, too_many_dependencies())

        graph = DeclaredAssetDependencyGraph(assets, [repeated])

        def too_many_seeds():
            for _ in range(MAX_IMACT_SEEDS + 1):
                yield "a-01"
            raise AssertionError("seed iterator consumed past hard bound")

        with self.assertRaisesRegex(MonitoringContractError, "seed bound exceeded"):
            graph.impact(too_many_seeds())


if __name__ == "__main__":
    unittest.main()
