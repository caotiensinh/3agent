from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.run_security_readonly_pilot import (
    PilotError,
    sanitize_run_receipt,
    validate_host_local_config,
    write_ephemeral_runtime_config,
)


class SecurityReadonlyPilotTests(unittest.TestCase):
    def _safe_config(self) -> dict:
        return {
            "enabled": True,
            "allow_real_network": True,
            "database_path": "/var/lib/workspace/security-monitoring.db",
            "secret_directory": "/var/lib/workspace/secrets",
            "policy": {
                "profile_id": "pilot",
                "network_scope": "approved_inventory_only",
                "read_only": True,
                "production_safety_profile": "non_disruptive_v1",
                "allow_active_liveness": False,
                "bandwidth_measurement_mode": "counter_only",
                "packet_analysis_mode": "passive_only",
                "max_workers": 2,
                "timeout_seconds": 2.0,
                "max_retries": 0,
                "max_catch_up_runs": 0,
                "allowed_capabilities": ["snmpv3_read"],
            },
            "assets": [
                {
                    "asset_id": "secret-switch-name",
                    "role": "switch",
                    "management_host": "192.0.2.10",
                    "collector_capabilities": ["snmpv3_read"],
                    "allowed_tcp_ports": [],
                    "data_class": "confidential",
                    "enabled": True,
                    "credential_ref": "secret-ref:opaque",
                }
            ],
        }

    def test_host_local_config_requires_explicit_safe_policy(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            install.mkdir()
            config = root / "pilot.json"
            config.write_text(json.dumps(self._safe_config()), encoding="utf-8")
            payload = validate_host_local_config(config, install)
            self.assertTrue(payload["enabled"])

            unsafe = self._safe_config()
            unsafe["policy"]["allow_active_liveness"] = True
            config.write_text(json.dumps(unsafe), encoding="utf-8")
            with self.assertRaisesRegex(PilotError, "UNSAFE_POLICY_ALLOW_ACTIVE_LIVENESS"):
                validate_host_local_config(config, install)

    def test_config_inside_installed_tree_is_rejected(self) -> None:
        with TemporaryDirectory() as tmp:
            install = Path(tmp) / "install"
            install.mkdir()
            config = install / "pilot.json"
            config.write_text(json.dumps(self._safe_config()), encoding="utf-8")
            with self.assertRaisesRegex(PilotError, "HOST_LOCAL_CONFIG_MUST_BE_OUTSIDE_INSTALL"):
                validate_host_local_config(config, install)

    def test_ephemeral_runtime_config_forces_fresh_database_without_mutating_source(self) -> None:
        payload = self._safe_config()
        original_database = payload["database_path"]
        with TemporaryDirectory() as tmp:
            runtime_config = write_ephemeral_runtime_config(payload, Path(tmp))
            derived = json.loads(runtime_config.read_text(encoding="utf-8"))
            self.assertEqual(payload["database_path"], original_database)
            self.assertNotEqual(derived["database_path"], original_database)
            self.assertEqual(Path(derived["database_path"]).parent, Path(tmp).resolve())
            self.assertEqual(Path(derived["database_path"]).name, "monitoring.db")

    def test_sanitized_receipt_drops_asset_ids_hosts_raw_failures_and_paths(self) -> None:
        payload = sanitize_run_receipt(
            {
                "run_id": "run-secret-value",
                "slot_key": "hourly:secret-profile:2026-09-02T11",
                "status": "partial",
                "inventory_fingerprint": "sha256:inventory",
                "policy_fingerprint": "sha256:policy",
                "expected_assets": 2,
                "observed_assets": 1,
                "coverage_pct": 50.0,
                "failure_codes": ["DATA_GAP_SECRET_SWITCH_NAME", "COLLECTOR_EXCEPTION_TIMEOUT"],
                "management_host": "192.0.2.10",
                "database_path": "/private/path/security.db",
            },
            target_sha="a" * 40,
            config_fingerprint="sha256:config",
            policy_fingerprint="sha256:policy",
        )
        encoded = json.dumps(payload, sort_keys=True)
        self.assertEqual(payload["result"], "FAIL")
        self.assertEqual(payload["failure_count"], 2)
        self.assertNotIn("SECRET_SWITCH_NAME", encoded)
        self.assertNotIn("192.0.2.10", encoded)
        self.assertNotIn("/private/path", encoded)
        self.assertNotIn("run-secret-value", encoded)
        self.assertNotIn("slot_key", payload)
        self.assertTrue(payload["fresh_ephemeral_store"])
        self.assertFalse(payload["persistent_monitoring_store_modified"])
        self.assertFalse(payload["packet_capture_executed"])
        self.assertFalse(payload["network_mutation_executed"])
        self.assertFalse(payload["remediation_executed"])

    def test_complete_zero_failure_receipt_is_pass(self) -> None:
        payload = sanitize_run_receipt(
            {
                "run_id": "run-1",
                "status": "completed",
                "expected_assets": 3,
                "observed_assets": 3,
                "coverage_pct": 100.0,
                "failure_codes": [],
            },
            target_sha="b" * 40,
            config_fingerprint="sha256:config",
            policy_fingerprint="sha256:policy",
        )
        self.assertEqual(payload["result"], "PASS")
        self.assertEqual(payload["failure_count"], 0)
        self.assertTrue(payload["readonly_collector_invoked"])
        self.assertTrue(payload["fresh_ephemeral_store"])
        self.assertFalse(payload["persistent_monitoring_store_modified"])
        self.assertTrue(payload["real_network_authorized"])
        self.assertFalse(payload["active_liveness_allowed"])


if __name__ == "__main__":
    unittest.main()
