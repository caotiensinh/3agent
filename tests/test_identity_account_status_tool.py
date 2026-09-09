from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from three_agent.diagnostics.identity_account_tools import (
    IDENTITY_ACCOUNT_STATUS_METADATA,
    IDENTITY_ACCOUNT_STATUS_TOOL_ID,
    build_identity_account_plan,
    read_identity_account_state,
)


class RecordingAuthority:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []

    def require(self, capability: str, *, resource_kind: str, resource_ref: str, effect: str):
        self.calls.append((capability, resource_kind, resource_ref, effect))
        return object()


class IdentityAccountStatusToolTests(unittest.TestCase):
    def test_metadata_is_local_sensitive_read_only(self) -> None:
        self.assertEqual(len(IDENTITY_ACCOUNT_STATUS_METADATA), 1)
        metadata = IDENTITY_ACCOUNT_STATUS_METADATA[0]
        self.assertEqual(metadata.id, IDENTITY_ACCOUNT_STATUS_TOOL_ID)
        self.assertEqual(metadata.network_access, "none")
        self.assertEqual(metadata.effect, "read")
        self.assertFalse(metadata.requires_admin)
        self.assertTrue(metadata.sensitive_outputs)

    def test_windows_plan_is_fixed_noninteractive_current_account_only(self) -> None:
        plan = build_identity_account_plan(platform_name="Windows")
        self.assertEqual(plan[:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
        self.assertIn("Get-LocalUser", plan[4])
        self.assertIn("$env:USERNAME", plan[4])
        self.assertNotIn("Credential", plan[4])

    def test_linux_plan_targets_current_local_username_without_shell(self) -> None:
        with patch("three_agent.diagnostics.identity_account_tools.getpass.getuser", return_value="alice"):
            self.assertEqual(
                build_identity_account_plan(platform_name="Linux"),
                ("passwd", "-S", "alice"),
            )

    def test_linux_collection_requires_exact_authority_and_reports_evidence_only(self) -> None:
        authority = RecordingAuthority()
        completed = SimpleNamespace(returncode=0, stdout="alice L 2026-09-01 0 99999 7 -1\n", stderr="")
        with patch("three_agent.diagnostics.identity_account_tools.getpass.getuser", return_value="alice"), patch(
            "three_agent.diagnostics.identity_account_tools.subprocess.run", return_value=completed
        ) as run:
            result = read_identity_account_state(
                authority=authority,
                platform_name="Linux",
                timeout=2.0,
            )

        self.assertEqual(
            authority.calls,
            [(
                IDENTITY_ACCOUNT_STATUS_TOOL_ID,
                "identity_account_state",
                "local:identity:current-account",
                "read",
            )],
        )
        argv = run.call_args.args[0]
        self.assertEqual(tuple(argv), ("passwd", "-S", "alice"))
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertEqual(result["observation"]["account_name"], "alice")
        self.assertTrue(result["observation"]["password_locked_observed"])
        self.assertFalse(result["directory_health_claimed"])
        self.assertFalse(result["authentication_claimed"])
        self.assertFalse(result["root_cause_claimed"])
        self.assertEqual(result["interpretation"], "evidence_only")

    def test_windows_collection_parses_only_local_account_state(self) -> None:
        authority = RecordingAuthority()
        stdout = (
            '{"Name":"alice","Enabled":false,"PasswordExpires":true,'
            '"UserMayChangePassword":false,"PasswordRequired":true,"LastLogon":"2026-09-09"}'
        )
        completed = SimpleNamespace(returncode=0, stdout=stdout, stderr="")
        with patch("three_agent.diagnostics.identity_account_tools.subprocess.run", return_value=completed):
            result = read_identity_account_state(authority=authority, platform_name="Windows")

        observation = result["observation"]
        self.assertTrue(observation["account_observed"])
        self.assertEqual(observation["account_name"], "alice")
        self.assertFalse(observation["enabled_observed"])
        self.assertTrue(observation["password_expires_observed"])
        self.assertFalse(result["root_cause_claimed"])

    def test_missing_collector_is_not_identity_failure(self) -> None:
        authority = RecordingAuthority()
        with patch("three_agent.diagnostics.identity_account_tools.subprocess.run", side_effect=FileNotFoundError):
            result = read_identity_account_state(authority=authority, platform_name="Linux")

        self.assertFalse(result["collector_available"])
        self.assertFalse(result["collection_succeeded"])
        self.assertFalse(result["directory_health_claimed"])
        self.assertFalse(result["authentication_claimed"])
        self.assertFalse(result["root_cause_claimed"])


if __name__ == "__main__":
    unittest.main()
