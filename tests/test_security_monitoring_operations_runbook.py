from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = ROOT / "docs" / "SECURITY_ANALYST_OPERATIONS_RUNBOOK_V1.md"


def shell_blocks(text: str) -> tuple[str, ...]:
    return tuple(
        match.group(1).strip()
        for match in re.finditer(r"```sh\s*\n(.*?)\n```", text, re.DOTALL)
    )


class SecurityMonitoringOperationsRunbookTests(unittest.TestCase):
    def setUp(self):
        self.text = RUNBOOK.read_text(encoding="utf-8")
        self.commands = "\n".join(shell_blocks(self.text)).lower()

    def test_runbook_covers_mandatory_operational_boundaries(self):
        required = (
            "non_disruptive_v1",
            "counter_only",
            "passive_only",
            "allow_active_liveness=false",
            "approved inventory",
            "workspace-monitor",
            "workspace-pcap",
            "ipaddressdeny=any",
            "15-minute runtime cap",
            "20-minute recovery threshold",
            "0 llm calls",
            "data_gap",
            "17:30 asia/tokyo",
            "pending_nas",
            "mountpoint -q",
            "approve_pcap",
            "authorize_pcap",
            "disabled by default",
            "one-shot",
            "ns1-18",
            "exact-head ci",
        )
        lowered = self.text.lower()
        for token in required:
            with self.subTest(token=token):
                self.assertIn(token, lowered)

    def test_command_blocks_do_not_offer_disruptive_or_scope_broadening_shortcuts(self):
        forbidden = (
            "nmap",
            "masscan",
            "iperf",
            "speedtest",
            "tcpdump",
            "snmpwalk",
            "mount -t",
            "reboot",
            "shutdown",
            "poweroff",
            "iptables",
            "nft ",
            "ip link set",
            "ifconfig",
            "nmcli",
            "curl ",
            "wget ",
        )
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, self.commands)

    def test_runbook_uses_reviewed_entrypoints_not_raw_capture_or_secret_argv(self):
        self.assertIn("workspace-security-monitor --config", self.commands)
        self.assertIn("workspace-security-report --config", self.commands)
        self.assertIn("systemctl start workspace-security-pcap@approval-", self.commands)
        self.assertNotIn(" -a ", self.commands)
        self.assertNotIn(" -x ", self.commands)
        self.assertNotIn("community", self.commands)
        self.assertNotIn("password=", self.commands)

    def test_rollback_stops_local_services_without_network_device_mutation(self):
        required_stops = (
            "systemctl stop workspace-security-monitor-hourly.timer",
            "systemctl stop workspace-security-report-daily.timer",
            "systemctl stop workspace-security-monitor-hourly.service",
            "systemctl stop workspace-security-report-daily.service",
        )
        for command in required_stops:
            self.assertIn(command, self.commands)
        self.assertIn("do not alter network devices to stop workspace", self.text.lower())

    def test_real_lan_acceptance_is_explicitly_optional_and_not_release_evidence(self):
        lowered = self.text.lower()
        self.assertIn("real-lan acceptance remains optional", lowered)
        self.assertIn("synthetic/offline", lowered)
        self.assertIn("do not claim real-lan acceptance", lowered)


if __name__ == "__main__":
    unittest.main()
