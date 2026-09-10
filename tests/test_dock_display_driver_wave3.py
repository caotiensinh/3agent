from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from three_agent.capability_authority import CapabilityAuthorityDenied, TaskCapabilityAuthority
from three_agent.capability_invocation_adapter import (
    CapabilityInvocationAdapterError,
    CapabilityInvocationRequest,
    current_runtime_invocation_identity,
    invoke_runtime_tool,
)
from three_agent.diagnostics.display_tools import (
    DISPLAY_CONNECTOR_LIMIT,
    DISPLAY_TOOL_ID,
    DISPLAY_TOOL_METADATA,
    build_windows_display_plan,
    read_display_snapshot,
)
from three_agent.diagnostics.dock_tools import (
    DOCK_DEVICE_LIMIT,
    DOCK_TOOL_ID,
    DOCK_TOOL_METADATA,
    build_windows_dock_plan,
    read_dock_snapshot,
)
from three_agent.diagnostics.driver_inventory_tools import (
    DRIVER_DEVICE_LIMIT,
    DRIVER_INVENTORY_METADATA,
    DRIVER_INVENTORY_TOOL_ID,
    build_windows_driver_inventory_plan,
    read_driver_inventory,
)
from three_agent.diagnostics.runtime_registry import default_runtime_capability_bindings
from three_agent.task_contract import DIAGNOSTIC_LOCAL_READ_TOOLS, TaskContractCompiler


WAVE3_CASES = (
    (DISPLAY_TOOL_ID, "display_devices", "local:display:devices"),
    (DOCK_TOOL_ID, "dock_devices", "local:dock:devices"),
    (DRIVER_INVENTORY_TOOL_ID, "driver_inventory", "local:driver:inventory"),
)


class RecordingAuthority:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []

    def require(self, capability: str, *, resource_kind: str, resource_ref: str, effect: str) -> None:
        self.calls.append((capability, resource_kind, resource_ref, effect))


class DenyingAuthority:
    def require(self, *args, **kwargs) -> None:
        raise PermissionError("denied")


def _authority(tool_id: str, *, task_id: str = "TASK-WAVE3") -> TaskCapabilityAuthority:
    return TaskCapabilityAuthority._build(
        task_id=task_id,
        sensitivity="internal",
        allowed_sources=(),
        allowed_tools=(tool_id,),
        write_scope="none",
        network_scope="deny",
    )


def _request(tool_id: str, *, parameters: dict[str, object] | None = None) -> CapabilityInvocationRequest:
    snapshot, descriptor = current_runtime_invocation_identity(tool_id)
    return CapabilityInvocationRequest.create(
        task_id="TASK-WAVE3",
        tool_id=tool_id,
        snapshot_fingerprint=snapshot,
        descriptor_fingerprint=descriptor,
        parameters=parameters,
    )


class DockDisplayDriverWave3Tests(unittest.TestCase):
    def test_metadata_is_local_read_only_sensitive_and_canonical(self) -> None:
        for metadata, tool_id in (
            (DISPLAY_TOOL_METADATA, DISPLAY_TOOL_ID),
            (DOCK_TOOL_METADATA, DOCK_TOOL_ID),
            (DRIVER_INVENTORY_METADATA, DRIVER_INVENTORY_TOOL_ID),
        ):
            with self.subTest(tool_id=tool_id):
                self.assertEqual(len(metadata), 1)
                tool = metadata[0]
                self.assertEqual(tool.id, tool_id)
                self.assertEqual(tool.network_access, "none")
                self.assertEqual(tool.effect, "read")
                self.assertTrue(tool.sensitive_outputs)
                self.assertFalse(tool.requires_admin)
                self.assertIn(tool_id, DIAGNOSTIC_LOCAL_READ_TOOLS)

    def test_windows_plans_are_fixed_bounded_and_non_mutating(self) -> None:
        for plan, expected_source in (
            (build_windows_display_plan(), "Win32_DesktopMonitor"),
            (build_windows_dock_plan(), "Win32_PnPEntity"),
            (build_windows_driver_inventory_plan(), "Win32_PnPSignedDriver"),
        ):
            with self.subTest(source=expected_source):
                self.assertEqual(plan[:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
                self.assertIn(expected_source, plan[4])
                self.assertIn("Select-Object -First", plan[4])
                for forbidden in ("Set-", "Remove-", "Disable-", "Enable-", "pnputil", "devcon"):
                    self.assertNotIn(forbidden, plan[4])

    @patch("three_agent.diagnostics.display_tools.subprocess.run")
    def test_windows_display_requires_authority_and_never_uses_shell(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("powershell.exe",), returncode=0, stdout='[{"Name":"Monitor"}]', stderr=""
        )
        authority = RecordingAuthority()
        result = read_display_snapshot(authority=authority, platform_name="Windows")  # type: ignore[arg-type]
        self.assertEqual(authority.calls, [(DISPLAY_TOOL_ID, "display_devices", "local:display:devices", "read")])
        self.assertEqual(result["source"], "Win32_DesktopMonitor")
        self.assertFalse(result["root_cause_claimed"])
        _, kwargs = run_mock.call_args
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["check"], False)

    @patch("three_agent.diagnostics.dock_tools.subprocess.run")
    def test_windows_dock_requires_authority_and_never_uses_shell(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("powershell.exe",), returncode=0, stdout='[{"Name":"USB-C Dock"}]', stderr=""
        )
        authority = RecordingAuthority()
        result = read_dock_snapshot(authority=authority, platform_name="Windows")  # type: ignore[arg-type]
        self.assertEqual(authority.calls, [(DOCK_TOOL_ID, "dock_devices", "local:dock:devices", "read")])
        self.assertEqual(result["source"], "Win32_PnPEntity_filtered")
        self.assertFalse(result["root_cause_claimed"])
        _, kwargs = run_mock.call_args
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["check"], False)

    @patch("three_agent.diagnostics.driver_inventory_tools.subprocess.run")
    def test_windows_driver_inventory_requires_authority_and_never_uses_shell(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("powershell.exe",), returncode=0, stdout='[{"DeviceName":"Adapter"}]', stderr=""
        )
        authority = RecordingAuthority()
        result = read_driver_inventory(authority=authority, platform_name="Windows")  # type: ignore[arg-type]
        self.assertEqual(
            authority.calls,
            [(DRIVER_INVENTORY_TOOL_ID, "driver_inventory", "local:driver:inventory", "read")],
        )
        self.assertEqual(result["source"], "Win32_PnPSignedDriver")
        self.assertFalse(result["root_cause_claimed"])
        _, kwargs = run_mock.call_args
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["check"], False)

    def test_linux_display_inventory_is_bounded_and_excludes_edid(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for index in range(DISPLAY_CONNECTOR_LIMIT + 4):
                connector = root / f"card0-HDMI-A-{index}"
                connector.mkdir()
                (connector / "status").write_text("connected", encoding="utf-8")
                (connector / "enabled").write_text("enabled", encoding="utf-8")
                (connector / "modes").write_text("1920x1080\n1280x720\n", encoding="utf-8")
                (connector / "edid").write_text("SECRET-EDID", encoding="utf-8")
            with patch("three_agent.diagnostics.display_tools.LINUX_DRM_ROOT", root):
                result = read_display_snapshot(
                    authority=RecordingAuthority(),  # type: ignore[arg-type]
                    platform_name="Linux",
                )
        self.assertEqual(result["source"], "sysfs_drm")
        self.assertEqual(len(result["connectors"]), DISPLAY_CONNECTOR_LIMIT)
        self.assertNotIn("SECRET-EDID", str(result))
        self.assertFalse(result["root_cause_claimed"])

    def test_linux_dock_inventory_is_bounded_and_excludes_serial(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            thunderbolt = root / "thunderbolt"
            usb = root / "usb"
            thunderbolt.mkdir()
            usb.mkdir()
            for index in range(DOCK_DEVICE_LIMIT + 4):
                device = usb / f"1-{index}"
                device.mkdir()
                (device / "manufacturer").write_text("Vendor", encoding="utf-8")
                (device / "product").write_text(f"USB-C Dock {index}", encoding="utf-8")
                (device / "idVendor").write_text("1234", encoding="utf-8")
                (device / "idProduct").write_text("5678", encoding="utf-8")
                (device / "serial").write_text("SECRET-SERIAL", encoding="utf-8")
            with patch("three_agent.diagnostics.dock_tools.LINUX_THUNDERBOLT_ROOT", thunderbolt), patch(
                "three_agent.diagnostics.dock_tools.LINUX_USB_ROOT", usb
            ):
                result = read_dock_snapshot(
                    authority=RecordingAuthority(),  # type: ignore[arg-type]
                    platform_name="Linux",
                )
        self.assertEqual(result["source"], "sysfs_dock_candidates")
        self.assertEqual(len(result["devices"]), DOCK_DEVICE_LIMIT)
        self.assertNotIn("SECRET-SERIAL", str(result))
        self.assertFalse(result["root_cause_claimed"])

    def test_linux_driver_inventory_is_bounded_and_excludes_usb_serial(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pci = root / "pci"
            usb = root / "usb"
            pci.mkdir()
            usb.mkdir()
            pci_device = pci / "device-0"
            pci_device.mkdir()
            (pci_device / "vendor").write_text("0x1234", encoding="utf-8")
            (pci_device / "device").write_text("0x5678", encoding="utf-8")
            (pci_device / "class").write_text("0x020000", encoding="utf-8")
            usb_device = usb / "1-1"
            usb_device.mkdir()
            (usb_device / "manufacturer").write_text("Vendor", encoding="utf-8")
            (usb_device / "product").write_text("Peripheral", encoding="utf-8")
            (usb_device / "idVendor").write_text("1234", encoding="utf-8")
            (usb_device / "idProduct").write_text("5678", encoding="utf-8")
            (usb_device / "serial").write_text("SECRET-SERIAL", encoding="utf-8")
            with patch(
                "three_agent.diagnostics.driver_inventory_tools._driver_name",
                side_effect=lambda entry: "fixture_driver" if entry == pci_device else None,
            ), patch("three_agent.diagnostics.driver_inventory_tools.LINUX_PCI_ROOT", pci), patch(
                "three_agent.diagnostics.driver_inventory_tools.LINUX_USB_ROOT", usb
            ):
                result = read_driver_inventory(
                    authority=RecordingAuthority(),  # type: ignore[arg-type]
                    platform_name="Linux",
                )
        self.assertEqual(result["source"], "sysfs_pci_usb_driver_binding")
        self.assertLessEqual(len(result["devices"]), DRIVER_DEVICE_LIMIT)
        self.assertIn("fixture_driver", str(result))
        self.assertNotIn("SECRET-SERIAL", str(result))
        self.assertFalse(result["root_cause_claimed"])

    @patch("pathlib.Path.iterdir")
    def test_authority_denial_happens_before_any_linux_directory_read(self, iterdir_mock) -> None:
        for reader in (read_display_snapshot, read_dock_snapshot, read_driver_inventory):
            with self.subTest(reader=reader.__name__):
                with self.assertRaises(PermissionError):
                    reader(authority=DenyingAuthority(), platform_name="Linux")  # type: ignore[arg-type]
        iterdir_mock.assert_not_called()

    def test_unsupported_platform_fails_closed_before_authority(self) -> None:
        for reader in (read_display_snapshot, read_dock_snapshot, read_driver_inventory):
            with self.subTest(reader=reader.__name__):
                authority = RecordingAuthority()
                with self.assertRaisesRegex(RuntimeError, "unsupported .* platform"):
                    reader(authority=authority, platform_name="Darwin")  # type: ignore[arg-type]
                self.assertEqual(authority.calls, [])

    def test_runtime_capability_bindings_use_exact_wave3_tools(self) -> None:
        mapping = {
            binding.capability_tag: binding.tool_ids
            for binding in default_runtime_capability_bindings()
        }
        self.assertEqual(mapping["hardware.display"], (DISPLAY_TOOL_ID,))
        self.assertEqual(mapping["hardware.dock"], (DOCK_TOOL_ID,))
        self.assertEqual(mapping["driver.inventory"], (DRIVER_INVENTORY_TOOL_ID,))

    def test_explicit_task_authority_allows_only_exact_wave3_resources(self) -> None:
        for tool_id, resource_kind, resource_ref in WAVE3_CASES:
            with self.subTest(tool_id=tool_id):
                contract = TaskContractCompiler().compile(
                    task_id=f"TASK-WAVE3-{tool_id}",
                    task_type="analysis",
                    sensitivity="internal",
                    allowed_tools=(tool_id,),
                )
                self.assertEqual(contract.allowed_tools, (tool_id,))
                authority = TaskCapabilityAuthority.from_contract(contract)
                decision = authority.require(
                    tool_id,
                    resource_kind=resource_kind,
                    resource_ref=resource_ref,
                    effect="read",
                )
                self.assertTrue(decision.allowed)
                with self.assertRaisesRegex(CapabilityAuthorityDenied, "RESOURCE_REF_NOT_AUTHORIZED"):
                    authority.require(
                        tool_id,
                        resource_kind=resource_kind,
                        resource_ref="local:diagnostics:wrong-resource",
                        effect="read",
                    )
                with self.assertRaisesRegex(CapabilityAuthorityDenied, "CAPABILITY_EFFECT_NOT_ALLOWED"):
                    authority.require(
                        tool_id,
                        resource_kind=resource_kind,
                        resource_ref=resource_ref,
                        effect="write",
                    )

    def test_default_analysis_does_not_auto_grant_wave3_tools(self) -> None:
        contract = TaskContractCompiler().compile(
            task_id="TASK-WAVE3-DEFAULT",
            task_type="analysis",
            sensitivity="internal",
        )
        for tool_id, _, _ in WAVE3_CASES:
            self.assertNotIn(tool_id, contract.allowed_tools)

    def test_wave3_tools_are_invocable_through_reviewed_runtime_boundary(self) -> None:
        cases = (
            (DISPLAY_TOOL_ID, "read_display_snapshot"),
            (DOCK_TOOL_ID, "read_dock_snapshot"),
            (DRIVER_INVENTORY_TOOL_ID, "read_driver_inventory"),
        )
        for tool_id, handler_name in cases:
            with self.subTest(tool_id=tool_id):
                request = _request(tool_id)
                authority = _authority(tool_id)
                fake_result = {
                    "tool_id": tool_id,
                    "interpretation": "evidence_only",
                    "root_cause_claimed": False,
                }
                with patch(
                    f"three_agent.capability_invocation_adapter.{handler_name}",
                    return_value=fake_result,
                ) as handler:
                    result = invoke_runtime_tool(request, authority=authority)
                handler.assert_called_once_with(authority=authority)
                self.assertEqual(result.tool_id, tool_id)
                self.assertTrue(result.decision_receipt.allowed)
                self.assertFalse(result.decision_receipt.automatic_action_allowed)
                self.assertIn('"interpretation":"evidence_only"', result.bounded_payload.text)

    def test_platform_spoof_is_rejected_before_wave3_handler(self) -> None:
        cases = (
            (DISPLAY_TOOL_ID, "read_display_snapshot"),
            (DOCK_TOOL_ID, "read_dock_snapshot"),
            (DRIVER_INVENTORY_TOOL_ID, "read_driver_inventory"),
        )
        for tool_id, handler_name in cases:
            with self.subTest(tool_id=tool_id):
                request = _request(tool_id, parameters={"platform_name": "Windows"})
                with patch(f"three_agent.capability_invocation_adapter.{handler_name}") as handler:
                    with self.assertRaisesRegex(
                        CapabilityInvocationAdapterError,
                        "UNSUPPORTED_INVOCATION_PARAMETERS:platform_name",
                    ):
                        invoke_runtime_tool(request, authority=_authority(tool_id))
                    handler.assert_not_called()


if __name__ == "__main__":
    unittest.main()
