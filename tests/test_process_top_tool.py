from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from three_agent.diagnostics.process_tools import (
    PROCESS_TOP_LIMIT,
    PROCESS_TOP_TOOL_ID,
    PROCESS_TOOL_METADATA,
    build_process_top_plan,
    process_micro_tool_registry,
    read_top_processes,
)


class RecordingAuthority:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []

    def require(self, capability: str, *, resource_kind: str, resource_ref: str, effect: str) -> None:
        self.calls.append((capability, resource_kind, resource_ref, effect))


class DenyingAuthority:
    def require(self, *args, **kwargs) -> None:
        raise PermissionError("denied")


class ProcessTopToolTests(unittest.TestCase):
    def test_metadata_is_local_read_only_and_sensitive(self) -> None:
        self.assertEqual(len(PROCESS_TOOL_METADATA), 1)
        tool = PROCESS_TOOL_METADATA[0]
        self.assertEqual(tool.id, PROCESS_TOP_TOOL_ID)
        self.assertEqual(tool.network_access, "none")
        self.assertEqual(tool.effect, "read")
        self.assertTrue(tool.sensitive_outputs)
        self.assertFalse(tool.requires_admin)
        self.assertEqual(len(process_micro_tool_registry().metadata_view()), 1)

    def test_windows_plan_is_fixed_and_non_mutating(self) -> None:
        plan = build_process_top_plan(platform_name="Windows")
        self.assertEqual(plan[:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
        self.assertIn("Get-Process", plan[4])
        self.assertIn(f"Select-Object -First {PROCESS_TOP_LIMIT}", plan[4])
        self.assertNotIn("Stop-Process", plan[4])
        self.assertNotIn("Set-", plan[4])

    def test_linux_plan_is_fixed_ps_argv(self) -> None:
        self.assertEqual(
            build_process_top_plan(platform_name="Linux"),
            ("ps", "-eo", "pid=,comm=,%cpu=,%mem=,rss=,vsz=", "--sort=-%cpu"),
        )

    @patch("three_agent.diagnostics.process_tools.subprocess.run")
    def test_windows_read_requires_authority_and_never_uses_shell(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("powershell.exe",),
            returncode=0,
            stdout='[{"Name":"python","Id":42,"CPU":12.5}]',
            stderr="",
        )
        authority = RecordingAuthority()
        result = read_top_processes(authority=authority, platform_name="Windows")  # type: ignore[arg-type]
        self.assertEqual(
            authority.calls,
            [(PROCESS_TOP_TOOL_ID, "process_inventory", "local:processes:top", "read")],
        )
        self.assertEqual(result["interpretation"], "evidence_only")
        self.assertFalse(result["root_cause_claimed"])
        _, kwargs = run_mock.call_args
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["check"], False)

    @patch("three_agent.diagnostics.process_tools.subprocess.run")
    def test_linux_output_is_bounded_to_twenty_rows(self, run_mock) -> None:
        rows = "\n".join(f"{index} proc{index} 1.0 0.1 100 200" for index in range(1, 31))
        run_mock.return_value = subprocess.CompletedProcess(
            args=("ps",),
            returncode=0,
            stdout=rows,
            stderr="",
        )
        result = read_top_processes(
            authority=RecordingAuthority(),  # type: ignore[arg-type]
            platform_name="Linux",
        )
        self.assertEqual(result["selected_rows"], PROCESS_TOP_LIMIT)
        self.assertEqual(len(result["stdout"].splitlines()), PROCESS_TOP_LIMIT)
        self.assertNotIn("proc30", result["stdout"])
        self.assertFalse(result["root_cause_claimed"])

    @patch("three_agent.diagnostics.process_tools.subprocess.run")
    def test_authority_denial_happens_before_subprocess(self, run_mock) -> None:
        with self.assertRaises(PermissionError):
            read_top_processes(
                authority=DenyingAuthority(),  # type: ignore[arg-type]
                platform_name="Linux",
            )
        run_mock.assert_not_called()

    def test_unsupported_platform_fails_closed_before_authority(self) -> None:
        authority = RecordingAuthority()
        with self.assertRaisesRegex(RuntimeError, "unsupported process-inventory platform"):
            read_top_processes(authority=authority, platform_name="Darwin")  # type: ignore[arg-type]
        self.assertEqual(authority.calls, [])


if __name__ == "__main__":
    unittest.main()
