from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from three_agent.diagnostics.meeting_client_tools import (
    MEETING_CLIENT_LIMIT,
    MEETING_CLIENT_TOOL_ID,
    MEETING_CLIENT_TOOL_METADATA,
    build_meeting_client_plan,
    read_running_meeting_clients,
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


class MeetingClientToolTests(unittest.TestCase):
    def test_metadata_is_local_read_only_and_sensitive(self) -> None:
        self.assertEqual(len(MEETING_CLIENT_TOOL_METADATA), 1)
        metadata = MEETING_CLIENT_TOOL_METADATA[0]
        self.assertEqual(metadata.id, MEETING_CLIENT_TOOL_ID)
        self.assertEqual(metadata.cost, "C0")
        self.assertEqual(metadata.risk, "sensitive_read")
        self.assertEqual(metadata.effect, "read")
        self.assertEqual(metadata.network_access, "none")
        self.assertFalse(metadata.requires_admin)
        self.assertTrue(metadata.sensitive_outputs)

    def test_windows_plan_is_fixed_and_does_not_request_command_lines_or_paths(self) -> None:
        plan = build_meeting_client_plan(platform_name="Windows")
        self.assertEqual(plan[:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
        command = plan[4]
        self.assertIn("Get-Process", command)
        self.assertIn("ProcessName,Id", command)
        self.assertNotIn("CommandLine", command)
        self.assertNotIn("Environment", command)
        self.assertNotIn("Path,", command)

    def test_linux_plan_reads_only_pid_and_process_name(self) -> None:
        self.assertEqual(
            build_meeting_client_plan(platform_name="Linux"),
            ("ps", "-eo", "pid=,comm="),
        )

    @patch("three_agent.diagnostics.meeting_client_tools.subprocess.run")
    def test_windows_snapshot_returns_only_allowlisted_running_clients(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("powershell.exe",),
            returncode=0,
            stdout='[{"ProcessName":"ms-teams","Id":101},{"ProcessName":"Zoom","Id":202}]',
            stderr="",
        )
        authority = _RecordingAuthority()
        result = read_running_meeting_clients(authority=authority, platform_name="Windows")

        self.assertEqual(
            authority.calls,
            [(MEETING_CLIENT_TOOL_ID, "meeting_clients", "local:meeting:clients", "read")],
        )
        self.assertTrue(result["collection_succeeded"])
        self.assertEqual(result["observed_count"], 2)
        self.assertEqual(
            [item["client_family"] for item in result["observed_running_clients"]],
            ["microsoft_teams", "zoom"],
        )
        self.assertEqual(result["observation_semantics"], "running_processes_only")
        self.assertFalse(result["installation_state_claimed"])
        self.assertFalse(result["service_health_claimed"])
        self.assertFalse(result["root_cause_claimed"])
        self.assertEqual(result["interpretation"], "evidence_only")
        self.assertFalse(run_mock.call_args.kwargs["shell"])

    @patch("three_agent.diagnostics.meeting_client_tools.subprocess.run")
    def test_linux_snapshot_filters_unrelated_processes_and_bounds_rows(self, run_mock) -> None:
        lines = ["1 chrome", "2 Zoom", "3 Webex"]
        lines.extend(f"{1000 + index} Teams" for index in range(MEETING_CLIENT_LIMIT + 10))
        run_mock.return_value = subprocess.CompletedProcess(
            args=("ps",),
            returncode=0,
            stdout="\n".join(lines),
            stderr="",
        )
        result = read_running_meeting_clients(
            authority=_RecordingAuthority(),
            platform_name="Linux",
        )
        self.assertEqual(result["observed_count"], MEETING_CLIENT_LIMIT)
        self.assertTrue(all(item["process_name"] != "chrome" for item in result["observed_running_clients"]))
        self.assertEqual(result["observed_running_clients"][0]["client_family"], "zoom")

    @patch("three_agent.diagnostics.meeting_client_tools.subprocess.run")
    def test_empty_success_does_not_claim_not_installed_or_service_failure(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("ps",),
            returncode=0,
            stdout="",
            stderr="",
        )
        result = read_running_meeting_clients(
            authority=_RecordingAuthority(),
            platform_name="Linux",
        )
        self.assertEqual(result["observed_count"], 0)
        self.assertEqual(result["observed_running_clients"], [])
        self.assertFalse(result["installation_state_claimed"])
        self.assertFalse(result["service_health_claimed"])
        self.assertFalse(result["root_cause_claimed"])

    @patch("three_agent.diagnostics.meeting_client_tools.subprocess.run")
    def test_authority_denial_happens_before_process_collection(self, run_mock) -> None:
        with self.assertRaisesRegex(PermissionError, "DENIED"):
            read_running_meeting_clients(
                authority=_DenyingAuthority(),
                platform_name="Linux",
            )
        run_mock.assert_not_called()

    def test_unsupported_platform_fails_closed(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "unsupported meeting-client platform"):
            build_meeting_client_plan(platform_name="Darwin")


if __name__ == "__main__":
    unittest.main()
