from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from three_agent.diagnostics.voip_tools import (
    VOIP_CLIENT_STATE_METADATA,
    VOIP_CLIENT_STATE_TOOL_ID,
    build_voip_client_plan,
    read_voip_client_state,
)


class RecordingAuthority:
    def __init__(self) -> None:
        self.calls = []

    def require(self, capability: str, *, resource_kind: str, resource_ref: str, effect: str):
        self.calls.append((capability, resource_kind, resource_ref, effect))
        return object()


class VoipToolTests(unittest.TestCase):
    def test_metadata_is_local_read_only(self) -> None:
        metadata = VOIP_CLIENT_STATE_METADATA[0]
        self.assertEqual(metadata.id, VOIP_CLIENT_STATE_TOOL_ID)
        self.assertEqual(metadata.network_access, "none")
        self.assertEqual(metadata.effect, "read")
        self.assertFalse(metadata.requires_admin)

    def test_windows_plan_has_no_call_or_remote_action(self) -> None:
        plan = build_voip_client_plan(platform_name="Windows")
        self.assertEqual(plan[:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
        self.assertIn("Get-Process", plan[4])
        self.assertNotIn("Invoke-WebRequest", plan[4])
        self.assertNotIn("Credential", plan[4])
        self.assertNotIn("Start-Process", plan[4])

    def test_collection_requires_exact_authority_and_is_evidence_only(self) -> None:
        authority = RecordingAuthority()
        completed = SimpleNamespace(returncode=0, stdout="Teams\n", stderr="")
        with patch("three_agent.diagnostics.voip_tools.subprocess.run", return_value=completed) as run:
            result = read_voip_client_state(authority=authority, platform_name="Linux")

        self.assertEqual(
            authority.calls,
            [(VOIP_CLIENT_STATE_TOOL_ID, "voip_client_state", "local:voip:client-state", "read")],
        )
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertFalse(result["sip_registration_claimed"])
        self.assertFalse(result["remote_pbx_health_claimed"])
        self.assertFalse(result["media_capture_performed"])
        self.assertFalse(result["call_action_performed"])
        self.assertFalse(result["root_cause_claimed"])
        self.assertEqual(result["interpretation"], "evidence_only")


if __name__ == "__main__":
    unittest.main()
