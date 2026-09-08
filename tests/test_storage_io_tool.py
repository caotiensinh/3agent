from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from three_agent.diagnostics.storage_io_tools import (
    STORAGE_IO_DEVICE_LIMIT,
    STORAGE_IO_TOOL_ID,
    STORAGE_IO_TOOL_METADATA,
    build_windows_storage_io_plan,
    read_storage_io,
    storage_io_micro_tool_registry,
)


class RecordingAuthority:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []

    def require(self, capability: str, *, resource_kind: str, resource_ref: str, effect: str) -> None:
        self.calls.append((capability, resource_kind, resource_ref, effect))


class DenyingAuthority:
    def require(self, *args, **kwargs) -> None:
        raise PermissionError("denied")


class StorageIoToolTests(unittest.TestCase):
    def test_metadata_is_local_read_only(self) -> None:
        self.assertEqual(len(STORAGE_IO_TOOL_METADATA), 1)
        tool = STORAGE_IO_TOOL_METADATA[0]
        self.assertEqual(tool.id, STORAGE_IO_TOOL_ID)
        self.assertEqual(tool.network_access, "none")
        self.assertEqual(tool.effect, "read")
        self.assertFalse(tool.requires_admin)
        self.assertEqual(len(storage_io_micro_tool_registry().metadata_view()), 1)

    def test_windows_plan_is_fixed_and_non_mutating(self) -> None:
        plan = build_windows_storage_io_plan()
        self.assertEqual(plan[:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
        self.assertIn("Win32_PerfFormattedData_PerfDisk_PhysicalDisk", plan[4])
        self.assertIn(f"Select-Object -First {STORAGE_IO_DEVICE_LIMIT}", plan[4])
        self.assertNotIn("Set-", plan[4])
        self.assertNotIn("Clear-", plan[4])
        self.assertNotIn("Repair-", plan[4])

    @patch("three_agent.diagnostics.storage_io_tools.subprocess.run")
    def test_windows_read_requires_authority_and_never_uses_shell(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("powershell.exe",),
            returncode=0,
            stdout='[{"Name":"0 C:","DiskBytesPersec":1024}]',
            stderr="",
        )
        authority = RecordingAuthority()
        result = read_storage_io(authority=authority, platform_name="Windows")  # type: ignore[arg-type]
        self.assertEqual(
            authority.calls,
            [(STORAGE_IO_TOOL_ID, "storage_io", "local:storage:io", "read")],
        )
        self.assertEqual(result["interpretation"], "evidence_only")
        self.assertFalse(result["root_cause_claimed"])
        _, kwargs = run_mock.call_args
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["check"], False)

    def test_linux_reads_only_fixed_diskstats_and_bounds_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "diskstats"
            path.write_text(
                "\n".join(f"8 {index} sd{index} 1 2 3 4 5 6 7 8 9 10 11" for index in range(40)),
                encoding="utf-8",
            )
            with patch("three_agent.diagnostics.storage_io_tools.LINUX_DISKSTATS_PATH", path):
                authority = RecordingAuthority()
                result = read_storage_io(authority=authority, platform_name="Linux")  # type: ignore[arg-type]
        self.assertEqual(
            authority.calls,
            [(STORAGE_IO_TOOL_ID, "storage_io", "local:storage:io", "read")],
        )
        self.assertEqual(result["source"], "proc_diskstats")
        self.assertEqual(len(result["rows"]), STORAGE_IO_DEVICE_LIMIT)
        self.assertEqual(result["counter_semantics"], "cumulative_kernel_counters")
        self.assertFalse(result["root_cause_claimed"])

    @patch("pathlib.Path.read_text")
    def test_authority_denial_happens_before_linux_file_read(self, read_text_mock) -> None:
        with self.assertRaises(PermissionError):
            read_storage_io(authority=DenyingAuthority(), platform_name="Linux")  # type: ignore[arg-type]
        read_text_mock.assert_not_called()

    def test_unsupported_platform_fails_closed_before_authority(self) -> None:
        authority = RecordingAuthority()
        with self.assertRaisesRegex(RuntimeError, "unsupported storage-io platform"):
            read_storage_io(authority=authority, platform_name="Darwin")  # type: ignore[arg-type]
        self.assertEqual(authority.calls, [])


if __name__ == "__main__":
    unittest.main()
