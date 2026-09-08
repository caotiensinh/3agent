from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from three_agent.diagnostics.print_driver_tools import (
    PRINT_DRIVER_LIMIT,
    PRINT_DRIVER_TOOL_ID,
    PRINT_DRIVER_TOOL_METADATA,
    build_windows_print_driver_plan,
    print_driver_micro_tool_registry,
    read_print_drivers,
)


class RecordingAuthority:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []

    def require(self, capability: str, *, resource_kind: str, resource_ref: str, effect: str) -> None:
        self.calls.append((capability, resource_kind, resource_ref, effect))


class PrintDriverToolTests(unittest.TestCase):
    def test_metadata_is_windows_local_read_only(self) -> None:
        tool = PRINT_DRIVER_TOOL_METADATA[0]
        self.assertEqual(tool.id, PRINT_DRIVER_TOOL_ID)
        self.assertEqual(tool.platform, "windows")
        self.assertEqual(tool.network_access, "none")
        self.assertEqual(tool.effect, "read")
        self.assertFalse(tool.requires_admin)
        self.assertEqual(len(print_driver_micro_tool_registry().metadata_view()), 1)

    def test_plan_is_fixed_bounded_and_non_mutating(self) -> None:
        plan = build_windows_print_driver_plan()
        self.assertEqual(plan[:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
        self.assertIn("Get-CimInstance Win32_PrinterDriver", plan[4])
        self.assertIn(f"Select-Object -First {PRINT_DRIVER_LIMIT}", plan[4])
        self.assertNotIn("Set-", plan[4])
        self.assertNotIn("Remove-", plan[4])
        self.assertNotIn("Add-PrinterDriver", plan[4])

    @patch("three_agent.diagnostics.print_driver_tools.subprocess.run")
    def test_read_requires_authority_and_never_uses_shell(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("powershell.exe",),
            returncode=0,
            stdout='[{"Name":"Example Driver","SupportedPlatform":"Windows x64","Version":3}]',
            stderr="",
        )
        authority = RecordingAuthority()
        result = read_print_drivers(authority=authority, platform_name="Windows")  # type: ignore[arg-type]
        self.assertEqual(
            authority.calls,
            [(PRINT_DRIVER_TOOL_ID, "printer_drivers", "local:printer:drivers", "read")],
        )
        self.assertEqual(result["source"], "Win32_PrinterDriver")
        self.assertFalse(result["root_cause_claimed"])
        _, kwargs = run_mock.call_args
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["check"], False)

    @patch("three_agent.diagnostics.print_driver_tools.subprocess.run")
    def test_unsupported_platform_fails_before_subprocess_or_authority(self, run_mock) -> None:
        authority = RecordingAuthority()
        with self.assertRaisesRegex(RuntimeError, "unsupported printer-driver platform"):
            read_print_drivers(authority=authority, platform_name="Linux")  # type: ignore[arg-type]
        self.assertEqual(authority.calls, [])
        run_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
