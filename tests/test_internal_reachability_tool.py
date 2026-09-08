from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from three_agent.diagnostics.network_tools import (
    NETWORK_REACHABILITY_TOOL_ID,
    NETWORK_TOOL_METADATA,
    build_internal_ping_plan,
    is_internal_ip_literal,
    network_micro_tool_registry,
    probe_internal_reachability,
)


class RecordingAuthority:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []

    def require(
        self,
        capability: str,
        *,
        resource_kind: str,
        resource_ref: str,
        effect: str,
    ) -> None:
        self.calls.append((capability, resource_kind, resource_ref, effect))


class InternalReachabilityToolTests(unittest.TestCase):
    def test_metadata_is_internal_only_network_read(self) -> None:
        self.assertEqual(len(NETWORK_TOOL_METADATA), 1)
        tool = NETWORK_TOOL_METADATA[0]
        self.assertEqual(tool.id, NETWORK_REACHABILITY_TOOL_ID)
        self.assertEqual(tool.network_access, "internal_only")
        self.assertEqual(tool.effect, "network_read")
        self.assertTrue(tool.sensitive_outputs)
        self.assertEqual(len(network_micro_tool_registry().metadata_view()), 1)

    def test_private_loopback_link_local_and_ula_are_allowed(self) -> None:
        for host in (
            "10.0.0.1",
            "172.16.1.10",
            "192.168.11.1",
            "127.0.0.1",
            "169.254.1.1",
            "::1",
            "fe80::1",
            "fd00::1",
        ):
            self.assertTrue(is_internal_ip_literal(host), host)

    def test_public_ip_and_hostname_are_rejected(self) -> None:
        for host in (
            "8.8.8.8",
            "1.1.1.1",
            "203.0.113.5",
            "example.com",
            "printer.local",
            "",
        ):
            self.assertFalse(is_internal_ip_literal(host), host)

    def test_windows_ping_plan_is_fixed_and_bounded(self) -> None:
        self.assertEqual(
            build_internal_ping_plan(
                "192.168.11.10",
                platform_name="Windows",
                count=2,
                timeout_ms=1500,
            ),
            ("ping.exe", "-n", "2", "-w", "1500", "192.168.11.10"),
        )

    def test_linux_ping_plan_is_fixed_and_bounded(self) -> None:
        self.assertEqual(
            build_internal_ping_plan(
                "192.168.11.10",
                platform_name="Linux",
                count=2,
                timeout_ms=1500,
            ),
            ("ping", "-n", "-c", "2", "-W", "2", "192.168.11.10"),
        )

    def test_ping_plan_rejects_public_target_before_execution(self) -> None:
        with self.assertRaisesRegex(ValueError, "internal/private IP literal"):
            build_internal_ping_plan("8.8.8.8", platform_name="Linux")

    def test_ping_plan_rejects_hostname_to_prevent_implicit_dns_egress(self) -> None:
        with self.assertRaisesRegex(ValueError, "internal/private IP literal"):
            build_internal_ping_plan("internal-server.example", platform_name="Linux")

    def test_ping_plan_enforces_count_and_timeout_bounds(self) -> None:
        with self.assertRaises(ValueError):
            build_internal_ping_plan("192.168.1.2", platform_name="Linux", count=0)
        with self.assertRaises(ValueError):
            build_internal_ping_plan("192.168.1.2", platform_name="Linux", count=5)
        with self.assertRaises(ValueError):
            build_internal_ping_plan("192.168.1.2", platform_name="Linux", timeout_ms=99)
        with self.assertRaises(ValueError):
            build_internal_ping_plan("192.168.1.2", platform_name="Linux", timeout_ms=5001)

    @patch("three_agent.diagnostics.network_tools.subprocess.run")
    def test_probe_requires_exact_authority_and_never_uses_shell(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("ping",),
            returncode=0,
            stdout="reply",
            stderr="",
        )
        authority = RecordingAuthority()
        with patch("three_agent.diagnostics.network_tools.platform.system", return_value="Linux"):
            result = probe_internal_reachability(
                "192.168.11.10",
                authority=authority,  # type: ignore[arg-type]
            )
        self.assertTrue(result["icmp_reply_observed"])
        self.assertEqual(result["interpretation"], "evidence_only")
        self.assertEqual(
            authority.calls,
            [
                (
                    NETWORK_REACHABILITY_TOOL_ID,
                    "network_endpoint",
                    "192.168.11.10:icmp",
                    "network_read",
                )
            ],
        )
        _, kwargs = run_mock.call_args
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["check"], False)

    @patch("three_agent.diagnostics.network_tools.subprocess.run")
    def test_ping_failure_is_only_negative_evidence_not_root_cause(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("ping",),
            returncode=1,
            stdout="no reply",
            stderr="",
        )
        authority = RecordingAuthority()
        with patch("three_agent.diagnostics.network_tools.platform.system", return_value="Linux"):
            result = probe_internal_reachability(
                "192.168.11.20",
                authority=authority,  # type: ignore[arg-type]
            )
        self.assertFalse(result["icmp_reply_observed"])
        self.assertEqual(result["interpretation"], "evidence_only")
        self.assertNotIn("root_cause", result)
        self.assertNotIn("device_down", result)


if __name__ == "__main__":
    unittest.main()
