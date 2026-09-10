from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from three_agent.diagnostics.cloud_files_tools import (
    CLOUD_FILES_STATUS_METADATA,
    CLOUD_FILES_STATUS_TOOL_ID,
    build_cloud_files_plan,
    read_cloud_files_client_state,
)


class RecordingAuthority:
    def __init__(self) -> None:
        self.calls = []

    def require(self, capability: str, *, resource_kind: str, resource_ref: str, effect: str):
        self.calls.append((capability, resource_kind, resource_ref, effect))
        return object()


class CloudFilesToolTests(unittest.TestCase):
    def test_metadata_is_local_read_only(self) -> None:
        metadata = CLOUD_FILES_STATUS_METADATA[0]
        self.assertEqual(metadata.id, CLOUD_FILES_STATUS_TOOL_ID)
        self.assertEqual(metadata.network_access, "none")
        self.assertEqual(metadata.effect, "read")
        self.assertFalse(metadata.requires_admin)

    def test_windows_plan_has_no_remote_or_credential_surface(self) -> None:
        plan = build_cloud_files_plan(platform_name="Windows")
        self.assertEqual(plan[:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
        self.assertIn("Get-Process", plan[4])
        self.assertNotIn("Credential", plan[4])
        self.assertNotIn("Invoke-WebRequest", plan[4])

    def test_collection_requires_exact_authority_and_remains_evidence_only(self) -> None:
        authority = RecordingAuthority()
        completed = SimpleNamespace(returncode=0, stdout="OneDrive\n", stderr="")
        with patch("three_agent.diagnostics.cloud_files_tools.subprocess.run", return_value=completed) as run:
            result = read_cloud_files_client_state(authority=authority, platform_name="Linux")

        self.assertEqual(
            authority.calls,
            [(CLOUD_FILES_STATUS_TOOL_ID, "cloud_files_client_state", "local:cloud-files:client-state", "read")],
        )
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertFalse(result["remote_provider_health_claimed"])
        self.assertFalse(result["authentication_claimed"])
        self.assertFalse(result["sync_success_claimed"])
        self.assertFalse(result["root_cause_claimed"])
        self.assertEqual(result["interpretation"], "evidence_only")


if __name__ == "__main__":
    unittest.main()
