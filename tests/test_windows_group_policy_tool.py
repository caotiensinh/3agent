from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from three_agent.diagnostics.windows_policy_tools import (
    GROUP_POLICY_TOOL_ID,
    GROUP_POLICY_TOOL_METADATA,
    build_group_policy_plan,
    group_policy_micro_tool_registry,
    read_group_policy_result,
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


class WindowsGroupPolicyToolTests(unittest.TestCase):
    def test_metadata_is_windows_local_sensitive_read(self) -> None:
        self.assertEqual(len(GROUP_POLICY_TOOL_METADATA), 1)
        tool = GROUP_POLICY_TOOL_METADATA[0]
        self.assertEqual(tool.id, GROUP_POLICY_TOOL_ID)
        self.assertEqual(tool.platform, "windows")
        self.assertEqual(tool.effect, "read")
        self.assertEqual(tool.network_access, "none")
        self.assertTrue(tool.sensitive_outputs)
        self.assertEqual(len(group_policy_micro_tool_registry().metadata_view()), 1)

    def test_user_computer_and_all_plans_are_fixed(self) -> None:
        self.assertEqual(
            build_group_policy_plan(scope="user"),
            ("gpresult.exe", "/R", "/SCOPE", "USER"),
        )
        self.assertEqual(
            build_group_policy_plan(scope="computer"),
            ("gpresult.exe", "/R", "/SCOPE", "COMPUTER"),
        )
        self.assertEqual(build_group_policy_plan(scope="all"), ("gpresult.exe", "/R"))

    def test_unknown_scope_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "scope must be"):
            build_group_policy_plan(scope="user & del c:\\")

    @patch("three_agent.diagnostics.windows_policy_tools.subprocess.run")
    def test_execution_requires_authority_and_never_uses_shell(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("gpresult.exe",),
            returncode=0,
            stdout="Applied Group Policy Objects",
            stderr="",
        )
        authority = RecordingAuthority()
        result = read_group_policy_result(
            authority=authority,  # type: ignore[arg-type]
            scope="user",
        )
        self.assertEqual(result["tool_id"], GROUP_POLICY_TOOL_ID)
        self.assertEqual(result["scope"], "user")
        self.assertEqual(result["interpretation"], "evidence_only")
        self.assertEqual(
            authority.calls,
            [
                (
                    GROUP_POLICY_TOOL_ID,
                    "group_policy",
                    "local:gpresult:user",
                    "read",
                )
            ],
        )
        _, kwargs = run_mock.call_args
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["check"], False)

    @patch("three_agent.diagnostics.windows_policy_tools.subprocess.run")
    def test_gpresult_failure_remains_evidence_not_diagnosis(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("gpresult.exe",),
            returncode=1,
            stdout="",
            stderr="Access denied",
        )
        authority = RecordingAuthority()
        result = read_group_policy_result(
            authority=authority,  # type: ignore[arg-type]
            scope="computer",
        )
        self.assertEqual(result["returncode"], 1)
        self.assertEqual(result["interpretation"], "evidence_only")
        self.assertNotIn("root_cause", result)
        self.assertNotIn("gpo_broken", result)


if __name__ == "__main__":
    unittest.main()
