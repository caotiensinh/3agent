from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from three_agent.diagnostics.identity_tools import (
    IDENTITY_SESSION_TOOL_ID,
    IDENTITY_TOOL_METADATA,
    build_identity_session_plan,
    identity_micro_tool_registry,
    read_identity_session,
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


class IdentityDiagnosticToolsTests(unittest.TestCase):
    def test_identity_registry_contains_one_local_sensitive_read_tool(self) -> None:
        self.assertEqual(len(IDENTITY_TOOL_METADATA), 1)
        tool = IDENTITY_TOOL_METADATA[0]
        self.assertEqual(tool.id, IDENTITY_SESSION_TOOL_ID)
        self.assertEqual(tool.effect, "read")
        self.assertEqual(tool.network_access, "none")
        self.assertEqual(tool.risk, "sensitive_read")
        self.assertTrue(tool.sensitive_outputs)
        self.assertEqual(len(identity_micro_tool_registry().metadata_view()), 1)

    def test_windows_identity_plan_is_fixed_and_current_user_only(self) -> None:
        self.assertEqual(
            build_identity_session_plan(platform_name="Windows"),
            ("whoami.exe", "/user", "/fo", "csv", "/nh"),
        )

    def test_linux_identity_plan_is_fixed_and_current_process_only(self) -> None:
        self.assertEqual(build_identity_session_plan(platform_name="Linux"), ("id",))

    def test_unsupported_platform_fails_closed(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "unsupported identity-session platform"):
            build_identity_session_plan(platform_name="Darwin")

    @patch("three_agent.diagnostics.identity_tools.subprocess.run")
    def test_read_identity_requires_exact_authority_and_never_uses_shell(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("id",),
            returncode=0,
            stdout="uid=1000(user) gid=1000(user) groups=1000(user)\n",
            stderr="",
        )
        authority = RecordingAuthority()
        with patch("three_agent.diagnostics.identity_tools.platform.system", return_value="Linux"):
            result = read_identity_session(authority=authority)  # type: ignore[arg-type]
        self.assertEqual(result["tool_id"], IDENTITY_SESSION_TOOL_ID)
        self.assertEqual(result["scope"], "current_process_identity")
        self.assertEqual(result["interpretation"], "evidence_only")
        self.assertEqual(
            authority.calls,
            [
                (
                    IDENTITY_SESSION_TOOL_ID,
                    "identity_session",
                    "local:identity:current",
                    "read",
                )
            ],
        )
        _, kwargs = run_mock.call_args
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["check"], False)

    @patch("three_agent.diagnostics.identity_tools.subprocess.run")
    def test_authority_is_checked_before_subprocess(self, run_mock) -> None:
        class DenyingAuthority:
            def require(self, *args, **kwargs):
                raise PermissionError("DENIED")

        with self.assertRaisesRegex(PermissionError, "DENIED"):
            read_identity_session(authority=DenyingAuthority())  # type: ignore[arg-type]
        run_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
