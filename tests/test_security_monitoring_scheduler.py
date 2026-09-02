from __future__ import annotations

import inspect
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from three_agent.security_monitoring.ui_config import safe_default_payload
import three_agent.security_monitoring_scheduler as scheduler


ROOT = Path(__file__).resolve().parents[1]


class SecurityMonitoringSchedulerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config_path = self.root / "security_monitoring.json"
        self.payload = safe_default_payload(self.config_path)
        self.payload["database_path"] = str(self.root / "monitoring.sqlite3")
        self.payload["secret_directory"] = str(self.root / "secrets")
        self._write()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write(self) -> None:
        self.config_path.write_text(
            json.dumps(self.payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_disabled_monitoring_is_safe_successful_skip(self) -> None:
        with mock.patch.object(scheduler, "cmd_run_hourly") as run:
            self.assertEqual(scheduler.run_scheduled(self.config_path), 0)
        run.assert_not_called()

    def test_real_network_disabled_is_safe_successful_skip(self) -> None:
        self.payload["enabled"] = True
        self.payload["allow_real_network"] = False
        self._write()
        with mock.patch.object(scheduler, "cmd_run_hourly") as run:
            self.assertEqual(scheduler.run_scheduled(self.config_path), 0)
        run.assert_not_called()

    def test_scheduler_executes_only_existing_readonly_hourly_entrypoint(self) -> None:
        self.payload["enabled"] = True
        self.payload["allow_real_network"] = True
        self._write()
        with mock.patch.object(
            scheduler,
            "evaluate_monitoring_readiness",
            return_value={"ready": True, "issues": []},
        ), mock.patch.object(scheduler, "cmd_run_hourly", return_value=0) as run:
            self.assertEqual(scheduler.run_scheduled(self.config_path), 0)
        run.assert_called_once_with(self.config_path, execute_readonly=True)

    def test_readiness_block_prevents_collector_execution(self) -> None:
        self.payload["enabled"] = True
        self.payload["allow_real_network"] = True
        self._write()
        with mock.patch.object(
            scheduler,
            "evaluate_monitoring_readiness",
            return_value={"ready": False, "issues": [{"code": "TEST_NOT_READY"}]},
        ), mock.patch.object(scheduler, "cmd_run_hourly") as run:
            self.assertEqual(scheduler.run_scheduled(self.config_path), 4)
        run.assert_not_called()

    def test_status_is_metadata_only(self) -> None:
        self.payload["assets"] = [
            {
                "asset_id": "router-test",
                "role": "router",
                "management_host": "192.0.2.10",
                "collector_capabilities": ["icmp_echo"],
                "allowed_tcp_ports": [],
                "data_class": "confidential",
                "enabled": True,
                "credential_ref": None,
            }
        ]
        self._write()
        with mock.patch.object(
            scheduler,
            "evaluate_monitoring_readiness",
            return_value={"ready": False, "issues": [{"code": "ACTIVE_LIVENESS_DISABLED"}]},
        ):
            status = scheduler.lifecycle_status(self.config_path)
        encoded = json.dumps(status, sort_keys=True)
        self.assertNotIn("192.0.2.10", encoded)
        self.assertNotIn("management_host", encoded)
        self.assertEqual(status["approved_asset_count"], 1)
        self.assertFalse(status["execution"]["model_authority"])
        self.assertFalse(status["execution"]["autonomous_remediation"])
        self.assertFalse(status["execution"]["packet_capture"])

    def test_scheduler_source_has_no_process_shell_or_network_implementation(self) -> None:
        source = inspect.getsource(scheduler)
        for forbidden in ("subprocess", "socket.", "os.system", "Popen", "shell=True"):
            self.assertNotIn(forbidden, source)
        self.assertIn("cmd_run_hourly(path, execute_readonly=True)", source)

    def test_environment_config_path_is_supported_for_systemd(self) -> None:
        with mock.patch.dict(os.environ, {scheduler.ENV_CONFIG: str(self.config_path)}, clear=False):
            with mock.patch.object(scheduler, "cmd_run_hourly") as run:
                self.assertEqual(scheduler.run_scheduled(), 0)
        run.assert_not_called()

    def test_symlink_config_is_rejected_before_execution(self) -> None:
        link = self.root / "security-link.json"
        try:
            link.symlink_to(self.config_path)
        except OSError:
            self.skipTest("symlinks unavailable")
        with mock.patch.object(scheduler, "cmd_run_hourly") as run:
            with self.assertRaises(Exception):
                scheduler._config_path(link)
        run.assert_not_called()


class SecurityMonitoringUserLifecycleInstallerContractTests(unittest.TestCase):
    @staticmethod
    def _installer() -> str:
        return (ROOT / "scripts/install_security_monitor_lifecycle.sh").read_text(encoding="utf-8")

    def test_lifecycle_installer_uses_same_authoritative_config_environment(self) -> None:
        text = self._installer()
        self.assertIn("ENV_FILE=\"$CONFIG_DIR/chat.env\"", text)
        self.assertIn("WORKSPACE_SECURITY_MONITORING_CONFIG", text)
        self.assertIn("EnvironmentFile=$ENV_FILE", text)
        self.assertIn("workspace-security-scheduler run-scheduled", text)
        self.assertNotIn("/etc/workspace/security-monitoring.json", text)

    def test_hourly_timer_is_explicit_opt_in(self) -> None:
        text = self._installer()
        self.assertIn("THREE_AGENT_START_SECURITY_TIMER", text)
        self.assertIn('if [[ "$START_SECURITY_TIMER" == "1" ]]', text)
        self.assertIn("OnCalendar=*-*-* *:05:00", text)
        self.assertIn("Persistent=true", text)
        self.assertIn("systemctl --user enable 3agent-security-monitor.timer", text)
        self.assertNotIn("systemctl --user enable --now 3agent-security-monitor.timer", text)

    def test_lifecycle_installer_does_not_bypass_runtime_authority(self) -> None:
        text = self._installer()
        self.assertNotIn("run-hourly --execute-readonly", text)
        self.assertNotIn("workspace-security-pcap", text)
        self.assertNotIn("nmap", text)
        self.assertNotIn("masscan", text)
        self.assertNotIn("iperf", text)
        self.assertNotIn("speedtest", text)

    def test_package_exposes_scheduler_entrypoint(self) -> None:
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn(
            'workspace-security-scheduler = "three_agent.security_monitoring_scheduler:main"',
            text,
        )


if __name__ == "__main__":
    unittest.main()
