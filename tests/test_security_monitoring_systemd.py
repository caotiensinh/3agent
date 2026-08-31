import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "scripts" / "systemd" / "workspace-security-monitor-hourly.service"
TIMER = ROOT / "scripts" / "systemd" / "workspace-security-monitor-hourly.timer"


class SystemdMonitoringContractTests(unittest.TestCase):
    def test_hourly_service_uses_dedicated_identity_and_network_deny_by_default(self):
        text = SERVICE.read_text(encoding="utf-8")
        self.assertIn("User=workspace-monitor", text)
        self.assertIn("Group=workspace-monitor", text)
        self.assertIn("NoNewPrivileges=true", text)
        self.assertIn("ProtectSystem=strict", text)
        self.assertIn("IPAddressDeny=any", text)
        self.assertIn("--execute-readonly", text)
        self.assertNotIn("User=workspace-core", text)

    def test_hourly_timer_runs_at_minute_five_and_persistent_catchup_is_single_systemd_activation(self):
        text = TIMER.read_text(encoding="utf-8")
        self.assertIn("OnCalendar=*-*-* *:05:00", text)
        self.assertIn("Persistent=true", text)
        self.assertNotIn("OnUnitActiveSec=", text)
        self.assertNotIn("Restart=always", text)


if __name__ == "__main__":
    unittest.main()
