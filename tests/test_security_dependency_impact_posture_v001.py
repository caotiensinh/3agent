from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.contracts import AssetInventoryRecord, MonitoringContractError
from three_agent.security_monitoring.demo import create_demo_environment
from three_agent.security_monitoring.operator_posture_reader import safe_operator_posture_summary
from three_agent.security_monitoring.policy import MonitoringPolicy
from three_agent.security_monitoring.runtime_config import MonitoringRuntimeConfig, load_runtime_config


def _asset(asset_id: str, host: str) -> AssetInventoryRecord:
    return AssetInventoryRecord(
        asset_id=asset_id,
        role="server",
        management_host=host,
        collector_capabilities=("local_net_read",),
        enabled=True,
    ).validate()


def _runtime_payload(database_path: Path) -> dict[str, object]:
    return {
        "enabled": True,
        "allow_real_network": False,
        "database_path": str(database_path.resolve()),
        "secret_directory": None,
        "policy": {},
        "assets": [
            {
                "asset_id": "router-01",
                "role": "router",
                "management_host": "192.0.2.1",
                "collector_capabilities": ["local_net_read"],
                "enabled": True,
            },
            {
                "asset_id": "switch-01",
                "role": "switch",
                "management_host": "192.0.2.2",
                "collector_capabilities": ["local_net_read"],
                "enabled": True,
            },
        ],
        "dependencies": [
            {
                "upstream_asset_id": "router-01",
                "downstream_asset_id": "switch-01",
                "relation": "network_path",
                "declaration_sha256": "sha256:" + "a" * 64,
            }
        ],
    }


class SecurityDependencyImpactPostureV001Tests(unittest.TestCase):
    def test_runtime_config_accepts_exact_declared_dependency_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "monitoring.json"
            payload = _runtime_payload(root / "monitoring.sqlite3")
            path.write_text(json.dumps(payload), encoding="utf-8")

            config = load_runtime_config(path)

            self.assertEqual(len(config.dependencies), 1)
            dependency = config.dependencies[0]
            self.assertEqual(dependency.upstream_asset_id, "router-01")
            self.assertEqual(dependency.downstream_asset_id, "switch-01")
            self.assertEqual(dependency.relation, "network_path")

    def test_runtime_config_rejects_unknown_dependency_fields_and_stale_endpoints(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "monitoring.json"
            payload = _runtime_payload(root / "monitoring.sqlite3")

            unknown = copy.deepcopy(payload)
            unknown["dependencies"][0]["browser_target"] = "192.0.2.99"  # type: ignore[index]
            path.write_text(json.dumps(unknown), encoding="utf-8")
            with self.assertRaisesRegex(MonitoringContractError, "unknown asset dependency keys"):
                load_runtime_config(path)

            stale = copy.deepcopy(payload)
            stale["dependencies"][0]["downstream_asset_id"] = "ghost-01"  # type: ignore[index]
            path.write_text(json.dumps(stale), encoding="utf-8")
            with self.assertRaisesRegex(MonitoringContractError, "enabled approved inventory"):
                load_runtime_config(path)

    def test_legacy_large_inventory_without_dependencies_keeps_previous_runtime_contract(self) -> None:
        assets = tuple(
            _asset(f"asset-{index:03d}", f"node-{index:03d}.example.test")
            for index in range(257)
        )
        with tempfile.TemporaryDirectory() as temp:
            config = MonitoringRuntimeConfig(
                enabled=True,
                allow_real_network=False,
                database_path=(Path(temp) / "monitoring.sqlite3").resolve(),
                secret_directory=None,
                policy=MonitoringPolicy(),
                assets=assets,
            )

            self.assertEqual(config.validate().dependencies, ())

    def test_demo_dependency_impact_is_real_bounded_and_privacy_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config_path = create_demo_environment(Path(temp))
            config = load_runtime_config(config_path)

            payload = safe_operator_posture_summary(config)
            impact = payload["dependency_impact"]

            self.assertTrue(impact["configured"])
            self.assertTrue(impact["available"])
            self.assertEqual(impact["data_state"], "available")
            self.assertEqual(impact["declared_dependency_count"], 2)
            self.assertEqual(impact["relation_counts"]["network_path"], 2)
            self.assertEqual(impact["source_finding_count"], 2)
            self.assertEqual(impact["active_seed_asset_count"], 2)
            self.assertEqual(impact["potential_affected_asset_count"], 2)
            self.assertEqual(impact["used_dependency_count"], 2)
            self.assertEqual(impact["observed_max_depth"], 2)
            self.assertEqual(impact["depth_counts"]["1"], 1)
            self.assertEqual(impact["depth_counts"]["2"], 1)
            self.assertFalse(impact["seed_input_truncated"])
            self.assertFalse(impact["impact_truncated"])

            authority = impact["authority"]
            self.assertTrue(authority["advisory_only"])
            self.assertTrue(authority["aggregate_only"])
            self.assertTrue(authority["database_read_only"])
            self.assertFalse(authority["browser_seed_selection"])
            self.assertFalse(authority["database_write"])
            self.assertFalse(authority["network_execution"])
            self.assertFalse(authority["collector_execution"])
            self.assertFalse(authority["packet_capture_execution"])
            self.assertFalse(authority["remediation_execution"])

            serialized = json.dumps(impact, sort_keys=True)
            for sensitive in (
                "demo-router-01",
                "demo-switch-01",
                "demo-camera-01",
                "demo-workstation-01",
                "demo-finding-critical",
                "demo-finding-medium",
                "dependency-",
                "assessment_id",
                "seed_asset_ids",
                "potentially_affected_asset_ids",
                '"dependency_ids":',
                "depth_by_asset",
                "declaration_sha256",
                "sha256:",
                "192.0.2.",
            ):
                self.assertNotIn(sensitive, serialized)


if __name__ == "__main__":
    unittest.main()
