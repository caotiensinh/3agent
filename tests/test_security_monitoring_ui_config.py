from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.ui_config import SecurityMonitoringUIConfigManager, safe_default_payload
from three_agent.workspace_frontend_v15 import WORKSPACE_HTML_V15, config_js, config_markup


class SecurityMonitoringUIConfigTests(unittest.TestCase):
    def manager(self, root: Path) -> SecurityMonitoringUIConfigManager:
        return SecurityMonitoringUIConfigManager(root / "security_monitoring.json", path_source="test")

    def test_safe_default_is_disabled_passive_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            payload = safe_default_payload(Path(td) / "security_monitoring.json")
        self.assertFalse(payload["enabled"])
        self.assertFalse(payload["allow_real_network"])
        self.assertTrue(payload["policy"]["read_only"])
        self.assertFalse(payload["policy"]["allow_active_liveness"])
        self.assertEqual(payload["policy"]["network_scope"], "approved_inventory_only")
        self.assertEqual(payload["policy"]["packet_analysis_mode"], "passive_only")
        self.assertEqual(payload["policy"]["bandwidth_measurement_mode"], "counter_only")

    def test_raw_secret_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manager = self.manager(root)
            payload = safe_default_payload(manager.path)
            payload["password"] = "must-never-be-accepted"
            with self.assertRaises(MonitoringContractError):
                manager.validate(payload)
            self.assertFalse(manager.path.exists())

    def test_policy_broadening_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manager = self.manager(root)
            payload = safe_default_payload(manager.path)
            payload["policy"]["read_only"] = False
            with self.assertRaises(MonitoringContractError):
                manager.validate(payload)
            payload = safe_default_payload(manager.path)
            payload["policy"]["packet_analysis_mode"] = "active"
            with self.assertRaises(MonitoringContractError):
                manager.validate(payload)

    def test_save_is_atomic_private_and_round_trips(self) -> None:
        if os.name != "posix":
            self.skipTest("POSIX mode assertion")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manager = self.manager(root)
            payload = safe_default_payload(manager.path)
            payload["assets"] = [
                {
                    "asset_id": "switch-01",
                    "role": "switch",
                    "management_host": "192.0.2.10",
                    "collector_capabilities": ["local_net_read"],
                    "allowed_tcp_ports": [],
                    "data_class": "confidential",
                    "enabled": True,
                    "credential_ref": None,
                }
            ]
            result = manager.save(payload)
            self.assertTrue(result["saved"])
            self.assertEqual(manager.path.stat().st_mode & 0o777, 0o600)
            loaded = manager.get()
            self.assertEqual(loaded["config"]["assets"][0]["asset_id"], "switch-01")
            self.assertEqual(loaded["summary"]["asset_count"], 1)

    def test_unresolved_snmp_reference_blocks_readiness_without_secret_read(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manager = self.manager(root)
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
            manager.save(payload)
            readiness = manager.readiness()
            self.assertFalse(readiness["ready"])
            self.assertFalse(readiness["network_test_executed"])
            self.assertFalse(readiness["secret_values_read"])
            self.assertFalse(readiness["packet_capture_executed"])
            self.assertFalse(readiness["remediation_executed"])
            self.assertTrue(any(x["code"] == "SECRET_REF_UNRESOLVED" for x in readiness["issues"]))

    def test_resolved_snmp_reference_uses_json_filename_without_reading_value(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manager = self.manager(root)
            payload = safe_default_payload(manager.path)
            payload["enabled"] = True
            payload["allow_real_network"] = True
            secret_dir = Path(payload["secret_directory"])
            secret_dir.mkdir(parents=True)
            (secret_dir / "router-01.json").write_text("not-read-by-readiness", encoding="utf-8")
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
            manager.save(payload)
            readiness = manager.readiness()
            self.assertTrue(readiness["ready"])
            self.assertFalse(readiness["secret_values_read"])

    def test_frontend_exposes_real_configuration_controls(self) -> None:
        for marker in (
            "Configuration",
            "Monitoring &amp; safety policy",
            "Allow approved real-network reads",
            "Approved asset inventory",
            "SNMPv3 read",
            "Readiness check",
            "/api/security/config/validate",
            "/api/security/config/readiness",
            "/api/security/config/save",
            "approved_inventory_only",
            "passive_only",
        ):
            self.assertIn(marker, WORKSPACE_HTML_V15)
        monitoring_ui = config_markup + config_js
        self.assertNotIn('type="password"', monitoring_ui)
        self.assertNotIn('name="password"', monitoring_ui)


if __name__ == "__main__":
    unittest.main()
