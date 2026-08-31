import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "scripts" / "systemd" / "workspace-security-report-daily.service"
TIMER = ROOT / "scripts" / "systemd" / "workspace-security-report-daily.timer"


class ReportingSystemdContractTests(unittest.TestCase):
    def test_reporting_service_has_no_network_socket_authority_or_mount_command(self):
        text = SERVICE.read_text(encoding="utf-8")
        self.assertIn("User=workspace-monitor", text)
        self.assertIn("Group=workspace-monitor", text)
        self.assertIn("NoNewPrivileges=true", text)
        self.assertIn("ProtectSystem=strict", text)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", text)
        self.assertIn("IPAddressDeny=any", text)
        self.assertIn("workspace-security-report", text)
        self.assertIn("run-canonical", text)
        self.assertNotIn("AF_INET", text)
        self.assertNotIn("AF_INET6", text)
        self.assertNotIn("mount ", text.lower())
        self.assertNotIn("/bin/sh", text)
        self.assertNotIn("curl", text.lower())
        self.assertNotIn("wget", text.lower())
        self.assertNotIn("smbclient", text.lower())

    def test_reporting_timer_is_exact_1730_tokyo_and_single_persistent_activation(self):
        text = TIMER.read_text(encoding="utf-8")
        self.assertIn("OnCalendar=*-*-* 17:30:00 Asia/Tokyo", text)
        self.assertIn("Persistent=true", text)
        self.assertIn("RandomizedDelaySec=0", text)
        self.assertNotIn("OnUnitActiveSec=", text)
        self.assertNotIn("Restart=always", text)


if __name__ == "__main__":
    unittest.main()
