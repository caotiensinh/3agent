from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from three_agent.diagnostics.windows_boot_tools import (
    WINDOWS_BOOT_TOOL_ID,
    WINDOWS_BOOT_TOOL_METADATA,
    build_windows_boot_plan,
    read_windows_boot,
    windows_boot_micro_tool_registry,
)


class RecordingAuthority:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []

    def require(self, capability: str, *, resource_kind: str, resource_ref: str, effect: str) -> None:
        self.calls.append((capability, resource_kind, resource_ref, effect))


class WindowsBootToolTests(unittest.TestCase):
    def test_metadata_is_windows_local_read_only(self) -> None:
        tool = WINDOWS_BOOT_TOOL_METADATA[0]
        self.assertEqual(tool.id, WINDOWS_BOOT_TOOL_ID)
        self.assertEqual(tool.platform, "windows")
        self.assertEqual(tool.network_access, "none")
        self.assertEqual(tool.effect, "read")
        self.assertFalse(tool.requires_admin)
        self.assertEqual(len(windows_boot_micro_tool_registry().metadata_view()), 1)

    def test_plan_is_fixed_and_non_mutating(self) -> None:
        plan = build_windows_boot_plan()
        self.assertEqual(plan[:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
        self.assertIn("Get-CimInstance Win32_OperatingSystem", plan[4])
        self.assertIn("LastBootUpTime", plan[4])
        self.assertNotIn("Restart-Computer", plan[4])
        self.assertNotIn("Stop-Computer", plan[4])
        self.assertNotIn("shutdown", plan[4].lower())

    @patch("three_agent.diagnostics.windows_boot_tools.subprocess.run")
    def test_read_requires_authority_and_never_uses_shell(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("powershell.exe",),
            returncode=0,
            stdout='{"LastBootUpTime":"2026-09-08T08:00:00","LocalDateTime":"2026-09-08T15:00:00"}',
            stderr="",
        )
        authority = RecordingAuthority()
        result = read_windows_boot(authority=authority, platform_name="Windows")  # type: ignore[arg-type]
        self.assertEqual(
            authority.calls,
            [(WINDOWS_BOOT_TOOL_ID, "boot_state", "local:windows:boot", "read")],
        )
        self.assertEqual(result["interpretation"], "evidence_only")
        self.assertFalse(result["root_cause_claimed"])
        _, kwargs = run_mock.call_args
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["check"], False)

    @patch("three_agent.diagnostics.windows_boot_tools.subprocess.run")
    def test_unsupported_platform_fails_before_subprocess_or_authority(self, run_mock) -> None:
        authority = RecordingAuthority()
        with self.assertRaisesRegex(RuntimeError, "unsupported Windows boot-evidence platform"):
            read_windows_boot(authority=authority, platform_name="Linux")  # type: ignore[arg-type]
        self.assertEqual(authority.calls, [])
        run_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
