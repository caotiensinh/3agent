from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from three_agent.diagnostics.backup_status_tools import (
    BACKUP_EVENT_LIMIT,
    BACKUP_STATUS_METADATA,
    BACKUP_STATUS_TOOL_ID,
    build_backup_status_plan,
    read_backup_status,
)


class RecordingAuthority:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []

    def require(self, capability: str, *, resource_kind: str, resource_ref: str, effect: str):
        self.calls.append((capability, resource_kind, resource_ref, effect))
        return object()


class BackupStatusToolTests(unittest.TestCase):
    def test_metadata_is_local_sensitive_read_only(self) -> None:
        metadata = BACKUP_STATUS_METADATA[0]
        self.assertEqual(metadata.id, BACKUP_STATUS_TOOL_ID)
        self.assertEqual(metadata.network_access, "none")
        self.assertEqual(metadata.effect, "read")
        self.assertFalse(metadata.requires_admin)
        self.assertTrue(metadata.sensitive_outputs)

    def test_windows_plan_is_fixed_event_metadata_only(self) -> None:
        plan = build_backup_status_plan(platform_name="Windows")
        self.assertEqual(plan[:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
        self.assertIn("Microsoft-Windows-Backup", plan[4])
        self.assertIn(str(BACKUP_EVENT_LIMIT), plan[4])
        self.assertNotIn("Credential", plan[4])
        self.assertNotIn("Get-Content", plan[4])

    def test_linux_plan_is_fixed_service_metadata_only(self) -> None:
        plan = build_backup_status_plan(platform_name="Linux")
        self.assertEqual(plan[:3], ("systemctl", "show", "--no-pager"))
        self.assertIn("restic-backup.service", plan)
        self.assertIn("borgbackup.service", plan)

    def test_windows_collection_requires_authority_and_does_not_claim_backup_success(self) -> None:
        authority = RecordingAuthority()
        completed = SimpleNamespace(
            returncode=0,
            stdout='[{"TimeCreated":"2026-09-09","Id":4,"LevelDisplayName":"Information","ProviderName":"Microsoft-Windows-Backup"}]',
            stderr="",
        )
        with patch("three_agent.diagnostics.backup_status_tools.subprocess.run", return_value=completed) as run:
            result = read_backup_status(authority=authority, platform_name="Windows", timeout=3.0)

        self.assertEqual(
            authority.calls,
            [(BACKUP_STATUS_TOOL_ID, "backup_status", "local:backup:status", "read")],
        )
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertEqual(result["observed_count"], 1)
        self.assertFalse(result["backup_success_claimed"])
        self.assertFalse(result["backup_completeness_claimed"])
        self.assertFalse(result["remote_repository_health_claimed"])
        self.assertFalse(result["root_cause_claimed"])
        self.assertEqual(result["interpretation"], "evidence_only")

    def test_linux_collection_ignores_missing_units(self) -> None:
        authority = RecordingAuthority()
        stdout = "\n".join(
            (
                "Id=restic-backup.service",
                "LoadState=loaded",
                "ActiveState=inactive",
                "SubState=dead",
                "Result=success",
                "ExecMainStatus=0",
                "",
                "Id=borgbackup.service",
                "LoadState=not-found",
                "ActiveState=inactive",
                "SubState=dead",
                "Result=success",
                "ExecMainStatus=0",
                "",
            )
        )
        completed = SimpleNamespace(returncode=0, stdout=stdout, stderr="")
        with patch("three_agent.diagnostics.backup_status_tools.subprocess.run", return_value=completed):
            result = read_backup_status(authority=authority, platform_name="Linux")

        self.assertEqual(result["observed_count"], 1)
        self.assertEqual(result["observations"][0]["unit"], "restic-backup.service")
        self.assertFalse(result["backup_success_claimed"])

    def test_missing_collector_is_not_backup_failure(self) -> None:
        authority = RecordingAuthority()
        with patch("three_agent.diagnostics.backup_status_tools.subprocess.run", side_effect=FileNotFoundError):
            result = read_backup_status(authority=authority, platform_name="Linux")

        self.assertFalse(result["collector_available"])
        self.assertFalse(result["collection_succeeded"])
        self.assertFalse(result["backup_success_claimed"])
        self.assertFalse(result["root_cause_claimed"])


if __name__ == "__main__":
    unittest.main()
