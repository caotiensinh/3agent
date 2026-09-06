from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.capability_matrix import safe_capability_matrix
from three_agent.security_monitoring.contracts import AssetInventoryRecord, SecretReference
from three_agent.security_monitoring.policy import MonitoringPolicy
from three_agent.security_monitoring.runtime_config import MonitoringRuntimeConfig


class SecurityCapabilityMatrixTests(unittest.TestCase):
    def _config(
        self,
        root: Path,
        *,
        enabled: bool = True,
        allow_real_network: bool = False,
        allow_active_liveness: bool = False,
    ) -> MonitoringRuntimeConfig:
        policy = MonitoringPolicy(
            profile_id="test-profile",
            allow_active_liveness=allow_active_liveness,
        ).validate()
        return MonitoringRuntimeConfig(
            enabled=enabled,
            allow_real_network=allow_real_network,
            database_path=(root / "monitoring.sqlite3").resolve(),
            secret_directory=(root / "secrets").resolve(),
            policy=policy,
            assets=(
                AssetInventoryRecord(
                    asset_id="router-secret-01",
                    role="router",
                    management_host="192.0.2.10",
                    collector_capabilities=("tcp_connect",),
                    allowed_tcp_ports=(443,),
                    data_class="confidential",
                    enabled=True,
                ).validate(),
                AssetInventoryRecord(
                    asset_id="switch-secret-01",
                    role="switch",
                    management_host="192.0.2.20",
                    collector_capabilities=("snmpv3_read",),
                    data_class="restricted",
                    enabled=True,
                    credential_ref=SecretReference("secret-ref:snmp-switch-secret"),
                ).validate(),
            ),
        ).validate()

    def test_matrix_is_metadata_only_and_does_not_reflect_sensitive_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config = self._config(Path(temp))
            matrix = safe_capability_matrix(config, config_saved=True)

        self.assertEqual(
            matrix["schema_version"],
            "workspace-security-monitoring/capability-matrix-v1",
        )
        self.assertTrue(matrix["authority"]["metadata_only"])
        self.assertFalse(matrix["authority"]["network_execution"])
        self.assertFalse(matrix["authority"]["collector_execution"])
        self.assertFalse(matrix["authority"]["packet_capture_execution"])
        self.assertFalse(matrix["authority"]["remediation_execution"])
        self.assertFalse(matrix["authority"]["shell_execution"])

        collectors = {item["name"]: item for item in matrix["collector_capabilities"]}
        self.assertEqual(collectors["tcp_connect"]["state"], "gated")
        self.assertEqual(
            collectors["tcp_connect"]["reason_code"],
            "ACTIVE_LIVENESS_DISABLED",
        )
        self.assertEqual(collectors["snmpv3_read"]["state"], "gated")
        self.assertEqual(
            collectors["snmpv3_read"]["reason_code"],
            "REAL_NETWORK_NOT_ALLOWED",
        )
        self.assertEqual(collectors["icmp_echo"]["state"], "not_configured")

        operations = {item["name"]: item for item in matrix["local_operations"]}
        self.assertEqual(operations["initialize_local_database"]["state"], "ready")
        self.assertEqual(operations["run_hourly_readonly"]["state"], "gated")

        for item in matrix["restricted_surfaces"]:
            self.assertEqual(item["state"], "disabled")
            self.assertEqual(item["reason_code"], "NOT_EXPOSED_BY_LOCAL_CONSOLE")

        serialized = json.dumps(matrix, sort_keys=True)
        for sensitive in (
            "router-secret-01",
            "switch-secret-01",
            "192.0.2.10",
            "192.0.2.20",
            "snmp-switch-secret",
            "443",
        ):
            self.assertNotIn(sensitive, serialized)

    def test_ready_state_only_appears_when_existing_runtime_gates_are_satisfied(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = MonitoringRuntimeConfig(
                enabled=True,
                allow_real_network=True,
                database_path=(root / "monitoring.sqlite3").resolve(),
                secret_directory=None,
                policy=MonitoringPolicy(
                    profile_id="ready-profile",
                    allow_active_liveness=True,
                ).validate(),
                assets=(
                    AssetInventoryRecord(
                        asset_id="asset-hidden",
                        role="endpoint",
                        management_host="198.51.100.10",
                        collector_capabilities=("tcp_connect", "local_net_read"),
                        allowed_tcp_ports=(443,),
                        data_class="confidential",
                        enabled=True,
                    ).validate(),
                ),
            ).validate()
            matrix = safe_capability_matrix(config, config_saved=True)

        self.assertTrue(matrix["readiness"]["ready"])
        collectors = {item["name"]: item for item in matrix["collector_capabilities"]}
        self.assertEqual(collectors["tcp_connect"]["state"], "ready")
        self.assertEqual(collectors["local_net_read"]["state"], "ready")
        operations = {item["name"]: item for item in matrix["local_operations"]}
        self.assertEqual(operations["run_hourly_readonly"]["state"], "ready")
        self.assertTrue(operations["run_hourly_readonly"]["user_confirmation_required"])

    def test_unsaved_config_never_reports_initialize_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config = self._config(Path(temp), enabled=False)
            matrix = safe_capability_matrix(config, config_saved=False)

        operations = {item["name"]: item for item in matrix["local_operations"]}
        self.assertEqual(operations["initialize_local_database"]["state"], "gated")
        self.assertEqual(operations["initialize_local_database"]["reason_code"], "CONFIG_NOT_SAVED")
        self.assertEqual(operations["run_hourly_readonly"]["state"], "disabled")


if __name__ == "__main__":
    unittest.main()
