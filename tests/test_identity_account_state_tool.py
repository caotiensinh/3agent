from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from three_agent.diagnostics.identity_account_state_tools import (
    IDENTITY_ACCOUNT_STATE_METADATA,
    IDENTITY_ACCOUNT_STATE_TOOL_ID,
    build_identity_account_state_plan,
    read_identity_account_state,
)


class RecordingAuthority:
    def __init__(self) -> None:
        self.calls = []

    def require(self, capability: str, *, resource_kind: str, resource_ref: str, effect: str):
        self.calls.append((capability, resource_kind, resource_ref, effect))
        return object()


class IdentityAccountStateToolTests(unittest.TestCase):
    def test_metadata_is_local_read_only(self) -> None:
        metadata = IDENTITY_ACCOUNT_STATE_METADATA[0]
        self.assertEqual(metadata.id, IDENTITY_ACCOUNT_STATE_TOOL_ID)
        self.assertEqual(metadata.network_access, "none")
        self.assertEqual(metadata.effect, "read")
        self.assertFalse(metadata.requires_admin)

    def test_windows_plan_is_fixed_and_local_only(self) -> None:
        plan = build_identity_account_state_plan(platform_name="Windows")
        self.assertEqual(plan[:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
        self.assertIn("Get-LocalUser", plan[4])
        self.assertNotIn("Get-ADUser", plan[4])
        self.assertNotIn("Invoke-WebRequest", plan[4])
        self.assertNotIn("Credential", plan[4])

    def test_linux_plan_is_bounded_to_local_username(self) -> None:
        self.assertEqual(
            build_identity_account_state_plan(platform_name="Linux", username="operator"),
            ("passwd", "-S", "operator"),
        )
        with self.assertRaises(RuntimeError):
            build_identity_account_state_plan(platform_name="Linux", username="bad user;curl example")

    def test_collection_requires_exact_authority_and_does_not_claim_directory_health(self) -> None:
        authority = RecordingAuthority()
        completed = SimpleNamespace(returncode=0, stdout="operator P 2026-09-01 0 99999 7 -1\n", stderr="")
        with patch("three_agent.diagnostics.identity_account_state_tools.subprocess.run", return_value=completed) as run:
            result = read_identity_account_state(authority=authority, platform_name="Linux")

        self.assertEqual(
            authority.calls,
            [(IDENTITY_ACCOUNT_STATE_TOOL_ID, "identity_account_state", "local:identity:account-state", "read")],
        )
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertFalse(result["directory_health_claimed"])
        self.assertFalse(result["authentication_claimed"])
        self.assertFalse(result["remote_lockout_claimed"])
        self.assertFalse(result["root_cause_claimed"])
        self.assertEqual(result["interpretation"], "evidence_only")


if __name__ == "__main__":
    unittest.main()
