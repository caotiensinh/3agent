from __future__ import annotations

import inspect
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from three_agent.diagnostics.vpn_tools import (
    VPN_PROFILE_LIMIT,
    VPN_STATUS_TOOL_ID,
    VPN_STATUS_TOOL_METADATA,
    build_vpn_status_plan,
    read_vpn_status,
)


class RecordingAuthority:
    def __init__(self, events: list[tuple] | None = None) -> None:
        self.calls: list[tuple[str, str, str, str]] = []
        self.events = events

    def require(self, capability: str, *, resource_kind: str, resource_ref: str, effect: str):
        self.calls.append((capability, resource_kind, resource_ref, effect))
        if self.events is not None:
            self.events.append(("authority", capability))
        return object()


class VpnStatusToolTests(unittest.TestCase):
    def test_vpn_status_metadata_is_local_sensitive_read_only(self) -> None:
        self.assertEqual(len(VPN_STATUS_TOOL_METADATA), 1)
        metadata = VPN_STATUS_TOOL_METADATA[0]
        self.assertEqual(metadata.id, VPN_STATUS_TOOL_ID)
        self.assertEqual(metadata.cost, "C0")
        self.assertEqual(metadata.risk, "sensitive_read")
        self.assertFalse(metadata.requires_admin)
        self.assertEqual(metadata.network_access, "none")
        self.assertTrue(metadata.sensitive_outputs)
        self.assertEqual(metadata.effect, "read")

    def test_vpn_status_has_no_remote_target_or_credential_input_surface(self) -> None:
        parameters = set(inspect.signature(read_vpn_status).parameters)
        self.assertEqual(parameters, {"authority", "platform_name", "timeout"})
        self.assertFalse(
            parameters
            & {"host", "url", "username", "password", "token", "secret", "path", "command"}
        )

    def test_windows_plan_is_fixed_and_noninteractive(self) -> None:
        plan = build_vpn_status_plan(platform_name="Windows")
        self.assertEqual(
            plan[:4],
            ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"),
        )
        self.assertIn("Get-VpnConnection", plan[4])
        self.assertIn(str(VPN_PROFILE_LIMIT), plan[4])
        self.assertNotIn("Credential", plan[4])

    def test_linux_plan_is_fixed_local_link_inventory(self) -> None:
        self.assertEqual(
            build_vpn_status_plan(platform_name="Linux"),
            ("ip", "-details", "link", "show"),
        )

    def test_windows_collection_requires_authority_before_subprocess(self) -> None:
        events: list[tuple] = []
        authority = RecordingAuthority(events)

        def fake_run(argv, **kwargs):
            events.append(("subprocess", tuple(argv)))
            self.assertFalse(kwargs["shell"])
            self.assertFalse(kwargs["check"])
            self.assertTrue(kwargs["capture_output"])
            self.assertTrue(kwargs["text"])
            return SimpleNamespace(
                returncode=0,
                stdout='[{"Name":"Corp VPN","ConnectionStatus":"Connected","TunnelType":"Ikev2","SplitTunneling":true}]',
                stderr="",
            )

        with patch("three_agent.diagnostics.vpn_tools.subprocess.run", side_effect=fake_run):
            result = read_vpn_status(authority=authority, platform_name="Windows", timeout=3.0)

        self.assertEqual(events[0], ("authority", VPN_STATUS_TOOL_ID))
        self.assertEqual(events[1][0], "subprocess")
        self.assertEqual(
            authority.calls,
            [(VPN_STATUS_TOOL_ID, "vpn_status", "local:vpn:status", "read")],
        )
        self.assertEqual(result["observed_count"], 1)
        self.assertEqual(
            result["observations"],
            [
                {
                    "profile_name": "Corp VPN",
                    "connection_status": "Connected",
                    "tunnel_type": "Ikev2",
                    "split_tunneling": True,
                }
            ],
        )
        self.assertFalse(result["vpn_health_claimed"])
        self.assertFalse(result["connectivity_claimed"])
        self.assertFalse(result["root_cause_claimed"])
        self.assertEqual(result["interpretation"], "evidence_only")

    def test_linux_collection_only_reports_bounded_tunnel_candidates(self) -> None:
        authority = RecordingAuthority()
        stdout = "\n".join(
            (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN mode DEFAULT group default",
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP mode DEFAULT group default",
                "7: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 state UNKNOWN mode DEFAULT group default",
                "8: wg-office: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 state UNKNOWN mode DEFAULT group default",
            )
        )

        def fake_run(argv, **kwargs):
            self.assertEqual(tuple(argv), ("ip", "-details", "link", "show"))
            self.assertFalse(kwargs["shell"])
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        with patch("three_agent.diagnostics.vpn_tools.subprocess.run", side_effect=fake_run):
            result = read_vpn_status(authority=authority, platform_name="Linux")

        self.assertEqual(
            authority.calls,
            [(VPN_STATUS_TOOL_ID, "vpn_status", "local:vpn:status", "read")],
        )
        self.assertEqual(
            [row["interface_name"] for row in result["observations"]],
            ["tun0", "wg-office"],
        )
        self.assertTrue(
            all(
                row["classification"] == "vpn_candidate_by_interface_name"
                for row in result["observations"]
            )
        )
        self.assertEqual(
            result["observation_semantics"],
            "tunnel_candidate_interfaces_only",
        )
        self.assertEqual(result["interpretation"], "evidence_only")

    def test_empty_collection_is_not_interpreted_as_vpn_down(self) -> None:
        authority = RecordingAuthority()

        with patch(
            "three_agent.diagnostics.vpn_tools.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout="", stderr=""),
        ):
            result = read_vpn_status(authority=authority, platform_name="Linux")

        self.assertEqual(result["observed_count"], 0)
        self.assertTrue(result["collection_succeeded"])
        self.assertFalse(result["vpn_health_claimed"])
        self.assertFalse(result["connectivity_claimed"])
        self.assertFalse(result["root_cause_claimed"])


if __name__ == "__main__":
    unittest.main()
