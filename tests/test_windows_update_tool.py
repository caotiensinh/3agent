from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from three_agent.diagnostics.windows_update_tools import (
    WINDOWS_UPDATE_HISTORY_LIMIT,
    WINDOWS_UPDATE_TOOL_ID,
    WINDOWS_UPDATE_TOOL_METADATA,
    build_windows_update_history_plan,
    read_windows_update_history,
    windows_update_micro_tool_registry,
)


class RecordingAuthority:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []

    def require(self, capability: str, *, resource_kind: str, resource_ref: str, effect: str) -> None:
        self.calls.append((capability, resource_kind, resource_ref, effect))


class WindowsUpdateToolTests(unittest.TestCase):
    def test_metadata_is_windows_local_read_only(self) -> None:
        tool = WINDOWS_UPDATE_TOOL_METADATA[0]
        self.assertEqual(tool.id, WINDOWS_UPDATE_TOOL_ID)
        self.assertEqual(tool.platform, "windows")
        self.assertEqual(tool.network_access, "none")
        self.assertEqual(tool.effect, "read")
        self.assertTrue(tool.sensitive_outputs)
        self.assertFalse(tool.requires_admin)
        self.assertEqual(len(windows_update_micro_tool_registry().metadata_view()), 1)

    def test_plan_is_fixed_bounded_history_only(self) -> None:
        plan = build_windows_update_history_plan()
        self.assertEqual(plan[:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
        script = plan[4]
        self.assertIn("Microsoft.Update.Session", script)
        self.assertIn("CreateUpdateSearcher", script)
        self.assertIn("QueryHistory", script)
        self.assertIn(str(WINDOWS_UPDATE_HISTORY_LIMIT), script)
        self.assertNotIn(".Install(", script)
        self.assertNotIn(".Download(", script)
        self.assertNotIn("UsoClient", script)
        self.assertNotIn("wuauclt", script.lower())

    @patch("three_agent.diagnostics.windows_update_tools.subprocess.run")
    def test_read_requires_authority_and_never_uses_shell(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("powershell.exe",),
            returncode=0,
            stdout='[{"Date":"2026-09-01","Title":"KB000000","ResultCode":2}]',
            stderr="",
        )
        authority = RecordingAuthority()
        result = read_windows_update_history(authority=authority, platform_name="Windows")  # type: ignore[arg-type]
        self.assertEqual(
            authority.calls,
            [(WINDOWS_UPDATE_TOOL_ID, "windows_update_history", "local:windows:update-history", "read")],
        )
        self.assertEqual(result["source"], "Microsoft.Update.Session.QueryHistory")
        self.assertEqual(result["interpretation"], "evidence_only")
        self.assertFalse(result["root_cause_claimed"])
        _, kwargs = run_mock.call_args
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["check"], False)

    @patch("three_agent.diagnostics.windows_update_tools.subprocess.run")
    def test_unsupported_platform_fails_before_subprocess_or_authority(self, run_mock) -> None:
        authority = RecordingAuthority()
        with self.assertRaisesRegex(RuntimeError, "unsupported Windows update-evidence platform"):
            read_windows_update_history(authority=authority, platform_name="Linux")  # type: ignore[arg-type]
        self.assertEqual(authority.calls, [])
        run_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
