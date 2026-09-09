from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from three_agent.diagnostics.vpn_tools import (
    VPN_STATUS_LIMIT,
    VPN_STATUS_TOOL_ID,
    VPN_TOOL_METADATA,
    build_vpn_status_plan,
    read_local_vpn_status,
)


class _RecordingAuthority:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []

    def require(self, capability: str, *, resource_kind: str, resource_ref: str, effect: str):
        self.calls.append((capability, resource_kind, resource_ref, effect))
        return object()


class _DenyingAuthority:
    def require(self, capability: str, *, resource_kind: str, resource_ref: str, effect: str):
        raise PermissionError("DENIED")


class VpnStatusToolTests(unittest.TestCase):
    def test_metadata_is_local_sensitive_read_only(self) -> None:
        self.assertEqual(len(VPN_TOOL_METADATA), 1)
        metadata = VPN_TOOL_METADATA[0]
        self.assertEqual(metadata.id, VPN_STATUS_TOOL_ID)
        self.assertEqual(metadata.effect, "read")
        self.assertEqual(metadata.network_access, "none")
        self.assertEqual(metadata.risk, "sensitive_read")
        self.assertFalse(metadata.requires_admin)
        self.assertTrue(metadata.sensitive_outputs)

    def test_plans_are_fixed_and_do_not_accept_host_or_path(self) -> None:
        windows = build_vpn_status_plan(platform_name="Windows")
        self.assertEqual(windows[:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
        self.assertIn("Get-VpnConnection", windows[4])
        self.assertIn("Get-NetAdapter", windows[4])
        self.assertNotIn("Invoke-WebRequest", windows[4])
        self.assertNotIn("Test-NetConnection", windows[4])
        self.assertEqual(build_vpn_status_plan(platform_name="Linux"), ("ip", "-j", "-d", "link", "show"))

    @patch("three_agent.diagnostics.vpn_tools.subprocess.run")
    def test_windows_collects_profile_and_adapter_evidence_without_health_claim(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("powershell.exe",),
            returncode=0,
            stdout=(
                '{"profiles":[{"Name":"Corp VPN","ConnectionStatus":"Connected","TunnelType":"Ikev2",'
                '"AllUserConnection":false}],"adapters":[{"Name":"WireGuard Tunnel","InterfaceDescription":'
                '"WireGuard Tunnel","Status":"Up","ifIndex":42}]}'
            ),
            stderr="",
        )
        authority = _RecordingAuthority()
        result = read_local_vpn_status(authority=authority, platform_name="Windows")
        self.assertEqual(
            authority.calls,
            [(VPN_STATUS_TOOL_ID, "vpn_status", "local:vpn:status", "read")],
        )
        self.assertEqual(result["observed_evidence_count"], 2)
        self.assertEqual(result["profiles"][0]["connection_status"], "Connected")
        self.assertEqual(result["tunnel_like_adapters"][0]["if_index"], 42)
        self.assertFalse(result["remote_connectivity_tested"])
        self.assertFalse(result["vpn_health_claimed"])
        self.assertFalse(result["vpn_absence_claimed"])
        self.assertFalse(result["root_cause_claimed"])
        self.assertFalse(run_mock.call_args.kwargs["shell"])
        self.assertFalse(run_mock.call_args.kwargs["check"])

    @patch("three_agent.diagnostics.vpn_tools.subprocess.run")
    def test_linux_filters_only_tunnel_like_interfaces_and_bounds_rows(self, run_mock) -> None:
        rows = [
            {"ifindex": 1, "ifname": "lo", "operstate": "UNKNOWN", "link_type": "loopback"},
            {"ifindex": 5, "ifname": "wg0", "operstate": "UP", "link_type": "none", "linkinfo": {"info_kind": "wireguard"}},
            {"ifindex": 6, "ifname": "eth0", "operstate": "UP", "link_type": "ether"},
        ]
        rows.extend(
            {"ifindex": 100 + index, "ifname": f"tun{index}", "operstate": "UP", "link_type": "none", "linkinfo": {"info_kind": "tun"}}
            for index in range(VPN_STATUS_LIMIT + 10)
        )
        import json
        run_mock.return_value = subprocess.CompletedProcess(args=("ip",), returncode=0, stdout=json.dumps(rows), stderr="")
        result = read_local_vpn_status(authority=_RecordingAuthority(), platform_name="Linux")
        self.assertEqual(result["observed_evidence_count"], VPN_STATUS_LIMIT)
        self.assertEqual(result["tunnel_like_interfaces"][0]["interface"], "wg0")
        self.assertTrue(all(item["interface"] != "eth0" for item in result["tunnel_like_interfaces"]))
        self.assertFalse(result["vpn_absence_claimed"])

    @patch("three_agent.diagnostics.vpn_tools.subprocess.run")
    def test_empty_success_is_not_interpreted_as_vpn_absent(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(args=("ip",), returncode=0, stdout="[]", stderr="")
        result = read_local_vpn_status(authority=_RecordingAuthority(), platform_name="Linux")
        self.assertEqual(result["observed_evidence_count"], 0)
        self.assertFalse(result["vpn_absence_claimed"])
        self.assertFalse(result["vpn_health_claimed"])
        self.assertEqual(result["interpretation"], "evidence_only")

    @patch("three_agent.diagnostics.vpn_tools.subprocess.run")
    def test_authority_denial_happens_before_subprocess(self, run_mock) -> None:
        with self.assertRaisesRegex(PermissionError, "DENIED"):
            read_local_vpn_status(authority=_DenyingAuthority(), platform_name="Linux")
        run_mock.assert_not_called()

    def test_unsupported_platform_fails_closed(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "unsupported vpn-status platform"):
            build_vpn_status_plan(platform_name="Darwin")


if __name__ == "__main__":
    unittest.main()
