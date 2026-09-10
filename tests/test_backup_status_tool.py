from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from three_agent.diagnostics.backup_status_tools import (
    BACKUP_STATUS_METADATA,
    BACKUP_STATUS_TOOL_ID,
    build_backup_status_plan,
    read_backup_local_state,
)


class RecordingAuthority:
    def __init__(self) -> None:
        self.calls = []

    def require(self, capability: str, *, resource_kind: str, resource_ref: str, effect: str):
        self.calls.append((capability, resource_kind, resource_ref, effect))
        return object()


class BackupStatusToolTests(unittest.TestCase):
    def test_metadata_is_local_read_only(self) -> None:
        metadata = BACKUP_STATUS_METADATA[0]
        self.assertEqual(metadata.id, BACKUP_STATUS_TOOL_ID)
        self.assertEqual(metadata.network_access, "none")
        self.assertEqual(metadata.effect, "read")
        self.assertFalse(metadata.requires_admin)

    def test_windows_plan_uses_local_services_only(self) -> None:
        plan = build_backup_status_plan(platform_name="Windows")
        self.assertEqual(plan[:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
        self.assertIn("Get-Service", plan[4])
        self.assertNotIn("Start-Service", plan[4])
        self.assertNotIn("Invoke-WebRequest", plan[4])
        self.assertNotIn("Credential", plan[4])

    def test_linux_plan_is_fixed_and_does_not_start_backup(self) -> None:
        plan = build_backup_status_plan(platform_name="Linux")
        self.assertEqual(plan[0:2], ("systemctl", "show"))
        self.assertIn("restic-backup.timer", plan)
        self.assertNotIn("start", plan)
        self.assertNotIn("restart", plan)

    def test_collection_requires_exact_authority_and_never_claims_backup_success(self) -> None:
        authority = RecordingAuthority()
        completed = SimpleNamespace(returncode=0, stdout="Id=backup.timer\nActiveState=active\n", stderr="")
        with patch("three_agent.diagnostics.backup_status_tools.subprocess.run", return_value=completed) as run:
            result = read_backup_local_state(authority=authority, platform_name="Linux")

        self.assertEqual(
            authority.calls,
            [(BACKUP_STATUS_TOOL_ID, "backup_local_state", "local:backup:state", "read")],
        )
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertFalse(result["backup_success_claimed"])
        self.assertFalse(result["backup_freshness_claimed"])
        self.assertFalse(result["restore_viability_claimed"])
        self.assertFalse(result["remote_destination_health_claimed"])
        self.assertFalse(result["root_cause_claimed"])
        self.assertEqual(result["interpretation"], "evidence_only")


if __name__ == "__main__":
    unittest.main()
