from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from three_agent.diagnostics.usb_tools import (
    USB_DEVICE_LIMIT,
    USB_DEVICES_TOOL_ID,
    USB_TOOL_METADATA,
    build_windows_usb_plan,
    read_usb_devices,
    usb_micro_tool_registry,
)


class RecordingAuthority:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []

    def require(self, capability: str, *, resource_kind: str, resource_ref: str, effect: str) -> None:
        self.calls.append((capability, resource_kind, resource_ref, effect))


class DenyingAuthority:
    def require(self, *args, **kwargs) -> None:
        raise PermissionError("denied")


class UsbDevicesToolTests(unittest.TestCase):
    def test_metadata_is_local_read_only_and_sensitive(self) -> None:
        self.assertEqual(len(USB_TOOL_METADATA), 1)
        tool = USB_TOOL_METADATA[0]
        self.assertEqual(tool.id, USB_DEVICES_TOOL_ID)
        self.assertEqual(tool.network_access, "none")
        self.assertEqual(tool.effect, "read")
        self.assertTrue(tool.sensitive_outputs)
        self.assertFalse(tool.requires_admin)
        self.assertEqual(len(usb_micro_tool_registry().metadata_view()), 1)

    def test_windows_plan_is_fixed_and_non_mutating(self) -> None:
        plan = build_windows_usb_plan()
        self.assertEqual(plan[:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
        self.assertIn("Get-CimInstance Win32_PnPEntity", plan[4])
        self.assertIn("PNPDeviceID -like 'USB*'", plan[4])
        self.assertNotIn("Set-", plan[4])
        self.assertNotIn("Remove-", plan[4])
        self.assertNotIn("Disable-", plan[4])

    @patch("three_agent.diagnostics.usb_tools.subprocess.run")
    def test_windows_read_requires_authority_and_never_uses_shell(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("powershell.exe",),
            returncode=0,
            stdout='[{"Name":"USB Hub","Status":"OK"}]',
            stderr="",
        )
        authority = RecordingAuthority()
        result = read_usb_devices(authority=authority, platform_name="Windows")  # type: ignore[arg-type]
        self.assertEqual(
            authority.calls,
            [(USB_DEVICES_TOOL_ID, "usb_devices", "local:usb:devices", "read")],
        )
        self.assertEqual(result["source"], "Win32_PnPEntity")
        self.assertFalse(result["root_cause_claimed"])
        _, kwargs = run_mock.call_args
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["check"], False)

    def test_linux_inventory_reads_only_fixed_non_serial_fields_and_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for index in range(USB_DEVICE_LIMIT + 6):
                device = root / f"1-{index}"
                device.mkdir()
                (device / "manufacturer").write_text("Vendor", encoding="utf-8")
                (device / "product").write_text(f"Device {index}", encoding="utf-8")
                (device / "idVendor").write_text("1234", encoding="utf-8")
                (device / "idProduct").write_text("5678", encoding="utf-8")
                (device / "serial").write_text("SECRET-SERIAL", encoding="utf-8")
            with patch("three_agent.diagnostics.usb_tools.LINUX_USB_ROOT", root):
                result = read_usb_devices(
                    authority=RecordingAuthority(),  # type: ignore[arg-type]
                    platform_name="Linux",
                )
        self.assertEqual(result["source"], "sysfs_usb")
        self.assertEqual(len(result["devices"]), USB_DEVICE_LIMIT)
        self.assertTrue(all("serial" not in item for item in result["devices"]))
        self.assertTrue(all("SECRET-SERIAL" not in str(item) for item in result["devices"]))
        self.assertFalse(result["root_cause_claimed"])

    @patch("pathlib.Path.iterdir")
    def test_authority_denial_happens_before_linux_directory_read(self, iterdir_mock) -> None:
        with self.assertRaises(PermissionError):
            read_usb_devices(
                authority=DenyingAuthority(),  # type: ignore[arg-type]
                platform_name="Linux",
            )
        iterdir_mock.assert_not_called()

    def test_unsupported_platform_fails_closed_before_authority(self) -> None:
        authority = RecordingAuthority()
        with self.assertRaisesRegex(RuntimeError, "unsupported usb-inventory platform"):
            read_usb_devices(authority=authority, platform_name="Darwin")  # type: ignore[arg-type]
        self.assertEqual(authority.calls, [])


if __name__ == "__main__":
    unittest.main()
