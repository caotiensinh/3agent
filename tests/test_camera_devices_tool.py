from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from three_agent.diagnostics.camera_device_tools import (
    CAMERA_DEVICE_LIMIT,
    CAMERA_DEVICES_TOOL_ID,
    CAMERA_DEVICE_TOOL_METADATA,
    build_windows_camera_device_plan,
    camera_device_micro_tool_registry,
    read_camera_devices,
)


class RecordingAuthority:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []

    def require(self, capability: str, *, resource_kind: str, resource_ref: str, effect: str) -> None:
        self.calls.append((capability, resource_kind, resource_ref, effect))


class DenyingAuthority:
    def require(self, *args, **kwargs) -> None:
        raise PermissionError("denied")


class CameraDevicesToolTests(unittest.TestCase):
    def test_metadata_is_local_read_only_and_sensitive(self) -> None:
        self.assertEqual(len(CAMERA_DEVICE_TOOL_METADATA), 1)
        tool = CAMERA_DEVICE_TOOL_METADATA[0]
        self.assertEqual(tool.id, CAMERA_DEVICES_TOOL_ID)
        self.assertEqual(tool.network_access, "none")
        self.assertEqual(tool.effect, "read")
        self.assertTrue(tool.sensitive_outputs)
        self.assertFalse(tool.requires_admin)
        self.assertEqual(len(camera_device_micro_tool_registry().metadata_view()), 1)

    def test_windows_plan_is_fixed_and_non_mutating(self) -> None:
        plan = build_windows_camera_device_plan()
        self.assertEqual(plan[:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
        self.assertIn("Get-CimInstance Win32_PnPEntity", plan[4])
        self.assertIn("@('Camera','Image')", plan[4])
        self.assertNotIn("Set-", plan[4])
        self.assertNotIn("Remove-", plan[4])
        self.assertNotIn("Disable-", plan[4])

    @patch("three_agent.diagnostics.camera_device_tools.subprocess.run")
    def test_windows_read_requires_authority_and_never_uses_shell(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("powershell.exe",),
            returncode=0,
            stdout='[{"Name":"USB Camera","Status":"OK"}]',
            stderr="",
        )
        authority = RecordingAuthority()
        result = read_camera_devices(authority=authority, platform_name="Windows")  # type: ignore[arg-type]
        self.assertEqual(
            authority.calls,
            [(CAMERA_DEVICES_TOOL_ID, "camera_devices", "local:camera:devices", "read")],
        )
        self.assertEqual(result["source"], "Win32_PnPEntity")
        self.assertFalse(result["root_cause_claimed"])
        _, kwargs = run_mock.call_args
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["check"], False)

    def test_linux_inventory_uses_fixed_video4linux_and_dev_roots_and_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            video_root = base / "video4linux"
            dev_root = base / "dev"
            video_root.mkdir()
            dev_root.mkdir()
            for index in range(CAMERA_DEVICE_LIMIT + 5):
                entry = video_root / f"video{index}"
                entry.mkdir()
                (entry / "name").write_text(f"Camera {index}", encoding="utf-8")
                if index % 2 == 0:
                    (dev_root / f"video{index}").write_text("", encoding="utf-8")
            with (
                patch("three_agent.diagnostics.camera_device_tools.LINUX_VIDEO_CLASS_ROOT", video_root),
                patch("three_agent.diagnostics.camera_device_tools.LINUX_DEVICE_ROOT", dev_root),
            ):
                result = read_camera_devices(
                    authority=RecordingAuthority(),  # type: ignore[arg-type]
                    platform_name="Linux",
                )
        self.assertEqual(result["source"], "video4linux_sysfs")
        self.assertEqual(len(result["devices"]), CAMERA_DEVICE_LIMIT)
        self.assertEqual(result["devices"][0]["sysfs_name"], "video0")
        self.assertIn("device_node_present", result["devices"][0])
        self.assertFalse(result["root_cause_claimed"])

    @patch("pathlib.Path.iterdir")
    def test_authority_denial_happens_before_linux_directory_read(self, iterdir_mock) -> None:
        with self.assertRaises(PermissionError):
            read_camera_devices(
                authority=DenyingAuthority(),  # type: ignore[arg-type]
                platform_name="Linux",
            )
        iterdir_mock.assert_not_called()

    def test_unsupported_platform_fails_closed_before_authority(self) -> None:
        authority = RecordingAuthority()
        with self.assertRaisesRegex(RuntimeError, "unsupported camera-device platform"):
            read_camera_devices(authority=authority, platform_name="Darwin")  # type: ignore[arg-type]
        self.assertEqual(authority.calls, [])


if __name__ == "__main__":
    unittest.main()
