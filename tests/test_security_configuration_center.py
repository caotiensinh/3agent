from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.config_center import (
    MONITORING_CONFIG_ENV,
    REAL_NETWORK_CONFIRMATION,
    SecurityConfigurationStore,
)
from three_agent.security_monitoring.contracts import MonitoringContractError


class SecurityConfigurationCenterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = self.root / "security-monitoring.json"
        self.db_path = self.root / "monitoring.sqlite3"
        self.secret_dir = self.root / "secrets"
        self.secret_dir.mkdir()
        self.store = SecurityConfigurationStore.from_environment(
            {MONITORING_CONFIG_ENV: str(self.config_path)}
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def config(self) -> dict:
        return {
            "enabled": False,
            "allow_real_network": False,
            "database_path": str(self.db_path),
            "secret_directory": str(self.secret_dir),
            "policy": {
                "profile_id": "default",
                "network_scope": "approved_inventory_only",
                "read_only": True,
                "production_safety_profile": "non_disruptive_v1",
                "allow_active_liveness": False,
                "bandwidth_measurement_mode": "counter_only",
                "packet_analysis_mode": "passive_only",
                "max_workers": 2,
                "timeout_seconds": 2.0,
                "max_retries": 1,
                "max_catch_up_runs": 1,
                "allowed_capabilities": ["snmpv3_read", "local_net_read"],
            },
            "assets": [],
        }

    @staticmethod
    def asset(asset_id: str, host: str) -> dict:
        return {
            "asset_id": asset_id,
            "role": "switch",
            "management_host": host,
            "collector_capabilities": ["snmpv3_read"],
            "allowed_tcp_ports": [],
            "data_class": "confidential",
            "enabled": True,
            "credential_ref": f"secret-ref:{asset_id}",
        }

    def test_safe_disabled_config_saves_without_network_confirmation(self) -> None:
        result = self.store.save(self.config(), actor_user_id="admin-1")
        self.assertEqual(result["config_state"], "configured")
        self.assertFalse(result["save_executes_network"])
        self.assertFalse(result["save_restarts_services"])
        persisted = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertFalse(persisted["allow_real_network"])
        if os.name != "nt":
            self.assertEqual(self.config_path.stat().st_mode & 0o777, 0o600)

    def test_real_network_activation_requires_exact_confirmation(self) -> None:
        candidate = self.config()
        candidate["assets"] = [self.asset("switch-01", "192.0.2.10")]
        candidate["allow_real_network"] = True
        with self.assertRaisesRegex(PermissionError, "REAL_NETWORK_MONITORING_CONFIRMATION_REQUIRED"):
            self.store.save(candidate, actor_user_id="admin-1")
        result = self.store.save(candidate, actor_user_id="admin-1", confirmation=REAL_NETWORK_CONFIRMATION)
        self.assertTrue(result["config"]["allow_real_network"])

    def test_inventory_expansion_requires_confirmation_again_when_real_network_enabled(self) -> None:
        candidate = self.config()
        candidate["assets"] = [self.asset("switch-01", "192.0.2.10")]
        candidate["allow_real_network"] = True
        self.store.save(candidate, actor_user_id="admin-1", confirmation=REAL_NETWORK_CONFIRMATION)
        expanded = json.loads(json.dumps(candidate))
        expanded["assets"].append(self.asset("switch-02", "192.0.2.11"))
        with self.assertRaisesRegex(PermissionError, "REAL_NETWORK_MONITORING_CONFIRMATION_REQUIRED"):
            self.store.save(expanded, actor_user_id="admin-1")

    def test_policy_change_requires_confirmation_when_real_network_enabled(self) -> None:
        candidate = self.config()
        candidate["assets"] = [self.asset("switch-01", "192.0.2.10")]
        candidate["allow_real_network"] = True
        self.store.save(candidate, actor_user_id="admin-1", confirmation=REAL_NETWORK_CONFIRMATION)
        changed = json.loads(json.dumps(candidate))
        changed["policy"]["max_workers"] = 3
        with self.assertRaisesRegex(PermissionError, "REAL_NETWORK_MONITORING_CONFIRMATION_REQUIRED"):
            self.store.save(changed, actor_user_id="admin-1")

    def test_enabling_active_liveness_requires_confirmation(self) -> None:
        baseline = self.config()
        self.store.save(baseline, actor_user_id="admin-1")
        candidate = json.loads(json.dumps(baseline))
        candidate["policy"]["allow_active_liveness"] = True
        candidate["policy"]["allowed_capabilities"].extend(["icmp_echo", "tcp_connect"])
        with self.assertRaisesRegex(PermissionError, "REAL_NETWORK_MONITORING_CONFIRMATION_REQUIRED"):
            self.store.save(candidate, actor_user_id="admin-1")

    def test_raw_secret_field_is_rejected_and_not_persisted(self) -> None:
        candidate = self.config()
        asset = self.asset("switch-01", "192.0.2.10")
        asset["password"] = "must-never-be-written"
        candidate["assets"] = [asset]
        with self.assertRaises(MonitoringContractError):
            self.store.save(candidate, actor_user_id="admin-1")
        self.assertFalse(self.config_path.exists())

    def test_read_only_policy_cannot_be_disabled(self) -> None:
        candidate = self.config()
        candidate["policy"]["read_only"] = False
        with self.assertRaisesRegex(MonitoringContractError, "read-only"):
            self.store.save(candidate, actor_user_id="admin-1")

    def test_audit_is_metadata_only(self) -> None:
        candidate = self.config()
        candidate["assets"] = [self.asset("switch-01", "192.0.2.10")]
        self.store.save(candidate, actor_user_id="admin-1")
        audit_path = self.config_path.with_name(self.config_path.name + ".audit.jsonl")
        raw = audit_path.read_text(encoding="utf-8")
        self.assertNotIn("192.0.2.10", raw)
        self.assertNotIn("secret-ref:switch-01", raw)
        self.assertIn('"raw_secret_material_recorded":false', raw)
        items = self.store.audit(limit=10)["items"]
        self.assertEqual(items[0]["asset_count"], 1)

    def test_missing_environment_path_fails_closed(self) -> None:
        store = SecurityConfigurationStore.from_environment({})
        state = store.public_state()
        self.assertEqual(state["config_state"], "not_configured")
        self.assertFalse(state["writable"])
        with self.assertRaises(MonitoringContractError):
            store.save(self.config(), actor_user_id="admin-1")


if __name__ == "__main__":
    unittest.main()
