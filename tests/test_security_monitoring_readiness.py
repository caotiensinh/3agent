from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from three_agent.security_monitoring.readiness import READINESS_SCHEMA
from three_agent.security_monitoring.ui_config import (
    SecurityMonitoringUIConfigManager,
    safe_default_payload,
)
from three_agent.security_monitoring_cli import cmd_run_hourly


class SecurityMonitoringSharedReadinessTests(unittest.TestCase):
    def _snmp_payload(self, manager: SecurityMonitoringUIConfigManager) -> dict:
        payload = safe_default_payload(manager.path)
        payload["enabled"] = True
        payload["allow_real_network"] = True
        payload["assets"] = [
            {
                "asset_id": "router-01",
                "role": "router",
                "management_host": "192.0.2.1",
                "collector_capabilities": ["snmpv3_read"],
                "allowed_tcp_ports": [],
                "data_class": "confidential",
                "enabled": True,
                "credential_ref": "secret-ref:router-01",
            }
        ]
        return payload

    def test_ui_readiness_exposes_stable_shared_schema_without_secret_read(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manager = SecurityMonitoringUIConfigManager(
                root / "security_monitoring.json",
                path_source="test",
            )
            payload = self._snmp_payload(manager)
            result = manager.save(payload)
            readiness = result["readiness"]

            self.assertEqual(readiness["schema_version"], READINESS_SCHEMA)
            self.assertFalse(readiness["ready"])
            self.assertFalse(readiness["network_test_executed"])
            self.assertFalse(readiness["secret_values_read"])
            self.assertFalse(readiness["packet_capture_executed"])
            self.assertFalse(readiness["remediation_executed"])
            self.assertEqual(
                [item["code"] for item in readiness["issues"]],
                ["SECRET_REF_UNRESOLVED"],
            )

    def test_runtime_blocks_unresolved_snmp_reference_before_store_or_collectors(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manager = SecurityMonitoringUIConfigManager(
                root / "security_monitoring.json",
                path_source="test",
            )
            payload = self._snmp_payload(manager)
            manager.save(payload)
            database_path = Path(payload["database_path"])

            with (
                patch("three_agent.security_monitoring_cli.MonitoringStore") as store_cls,
                patch("three_agent.security_monitoring_cli._sync_inventory") as sync_inventory,
                patch("three_agent.security_monitoring_cli._snmp_backend") as snmp_backend,
                self.assertRaisesRegex(
                    RuntimeError,
                    "^MONITORING_READINESS_BLOCKED:SECRET_REF_UNRESOLVED$",
                ),
            ):
                cmd_run_hourly(manager.path, execute_readonly=True)

            store_cls.assert_not_called()
            sync_inventory.assert_not_called()
            snmp_backend.assert_not_called()
            self.assertFalse(database_path.exists())

    def test_resolved_reference_is_metadata_only_and_does_not_parse_secret_value(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manager = SecurityMonitoringUIConfigManager(
                root / "security_monitoring.json",
                path_source="test",
            )
            payload = self._snmp_payload(manager)
            secret_dir = Path(payload["secret_directory"])
            secret_dir.mkdir(parents=True)
            (secret_dir / "router-01.json").write_text(
                "intentionally-not-json-and-not-read-by-readiness",
                encoding="utf-8",
            )

            result = manager.save(payload)
            readiness = result["readiness"]

            self.assertEqual(readiness["schema_version"], READINESS_SCHEMA)
            self.assertTrue(readiness["ready"])
            self.assertFalse(readiness["secret_values_read"])


if __name__ == "__main__":
    unittest.main()
