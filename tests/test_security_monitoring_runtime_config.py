import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.runtime_config import load_runtime_config
from three_agent.security_monitoring.storage import MonitoringStore
from three_agent.security_monitoring_cli import cmd_init, cmd_run_hourly, cmd_validate


class MonitoringRuntimeConfigTests(unittest.TestCase):
    def _write_config(self, tmp, *, enabled=False, allow_real_network=False, assets=None, extra=None):
        path = Path(tmp) / "monitoring.json"
        payload = {
            "enabled": enabled,
            "allow_real_network": allow_real_network,
            "database_path": str(Path(tmp) / "state" / "monitoring.sqlite3"),
            "policy": {
                "profile_id": "test",
                "network_scope": "approved_inventory_only",
                "read_only": True,
                "max_workers": 2,
                "timeout_seconds": 1,
                "max_retries": 1,
                "max_catch_up_runs": 1,
                "allowed_capabilities": ["icmp_echo", "tcp_connect", "local_net_read", "snmpv3_read"],
            },
            "assets": assets or [],
        }
        if extra:
            payload.update(extra)
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_example_style_config_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_config(tmp)
            config = load_runtime_config(path)
            self.assertFalse(config.enabled)
            self.assertFalse(config.allow_real_network)

    def test_raw_password_community_and_token_fields_are_rejected(self):
        for key in ("password", "community", "token", "api_key"):
            with tempfile.TemporaryDirectory() as tmp:
                path = self._write_config(tmp, extra={key: "PRIVATE"})
                with self.subTest(key=key), self.assertRaises(MonitoringContractError):
                    load_runtime_config(path)

    def test_validate_summary_does_not_print_management_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_config(
                tmp,
                assets=[
                    {
                        "asset_id": "router-1",
                        "role": "router",
                        "management_host": "192.0.2.1",
                        "collector_capabilities": ["icmp_echo"],
                    }
                ],
            )
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(cmd_validate(path), 0)
            text = output.getvalue()
            self.assertNotIn("192.0.2.1", text)
            self.assertIn("policy_fingerprint", text)

    def test_init_db_is_offline_and_synchronizes_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_config(
                tmp,
                assets=[
                    {
                        "asset_id": "router-1",
                        "role": "router",
                        "management_host": "192.0.2.1",
                        "collector_capabilities": [],
                    }
                ],
            )
            with redirect_stdout(StringIO()):
                self.assertEqual(cmd_init(path), 0)
            config = load_runtime_config(path)
            store = MonitoringStore(config.database_path)
            self.assertEqual(store.count("approved_assets"), 1)
            self.assertEqual(store.count("observations"), 0)

    def test_hourly_requires_both_config_and_explicit_flag_before_network_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            disabled = self._write_config(tmp, enabled=False, allow_real_network=False)
            with self.assertRaisesRegex(RuntimeError, "MONITORING_DISABLED"):
                cmd_run_hourly(disabled, execute_readonly=True)

        with tempfile.TemporaryDirectory() as tmp:
            no_network = self._write_config(tmp, enabled=True, allow_real_network=False)
            with self.assertRaisesRegex(RuntimeError, "REAL_NETWORK_NOT_ALLOWED_BY_CONFIG"):
                cmd_run_hourly(no_network, execute_readonly=True)

        with tempfile.TemporaryDirectory() as tmp:
            flag_missing = self._write_config(tmp, enabled=True, allow_real_network=True)
            with self.assertRaisesRegex(RuntimeError, "EXPLICIT_READONLY_EXECUTION_FLAG_REQUIRED"):
                cmd_run_hourly(flag_missing, execute_readonly=False)

    def test_hourly_with_empty_capability_asset_executes_no_network_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_config(
                tmp,
                enabled=True,
                allow_real_network=True,
                assets=[
                    {
                        "asset_id": "no-op-asset",
                        "role": "test",
                        "management_host": "192.0.2.55",
                        "collector_capabilities": [],
                    }
                ],
            )
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(cmd_run_hourly(path, execute_readonly=True), 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["status"], "partial")
            self.assertEqual(payload["coverage_pct"], 0.0)
            self.assertIn("DATA_GAP_NO_OP_ASSET", payload["failure_codes"])


if __name__ == "__main__":
    unittest.main()
