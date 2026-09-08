from __future__ import annotations

import platform
import subprocess
from pathlib import Path
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output, bound_text_result

USB_DEVICES_TOOL_ID = "hardware.usb.snapshot"
USB_DEVICE_LIMIT = 64
LINUX_USB_ROOT = Path("/sys/bus/usb/devices")

USB_TOOL_METADATA = (
    ToolMetadata(
        id=USB_DEVICES_TOOL_ID,
        platform="any",
        category="hardware",
        keywords=(
            "usb device",
            "usb not detected",
            "usb disconnect",
            "usb peripheral",
            "dock usb",
            "thiet bi usb",
            "usb khong nhan",
            "USB デバイス",
            "USB 認識しない",
            "USB 切断",
        ),
        cost="C0",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ).validate(),
)

_WINDOWS_USB_QUERY = (
    "Get-CimInstance Win32_PnPEntity | "
    "Where-Object { $_.PNPDeviceID -like 'USB*' } | "
    "Select-Object Name,Status,Manufacturer,PNPClass,PNPDeviceID | "
    "ConvertTo-Json -Depth 3 -Compress"
)

_LINUX_USB_FIELDS = (
    "manufacturer",
    "product",
    "idVendor",
    "idProduct",
    "bDeviceClass",
    "bDeviceSubClass",
    "bDeviceProtocol",
)


def usb_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(USB_TOOL_METADATA)


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported usb-inventory platform: {value or 'unknown'}")


def build_windows_usb_plan() -> tuple[str, ...]:
    return (
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        _WINDOWS_USB_QUERY,
    )


def _read_small_text(path: Path) -> str | None:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    bounded = bound_text_result(raw, max_bytes=1024)
    return bounded.text


def _read_linux_usb_inventory() -> tuple[dict[str, Any], ...]:
    try:
        entries = sorted(LINUX_USB_ROOT.iterdir(), key=lambda item: item.name)
    except OSError:
        return ()
    devices: list[dict[str, Any]] = []
    for entry in entries[:USB_DEVICE_LIMIT]:
        item: dict[str, Any] = {"sysfs_name": entry.name}
        for field in _LINUX_USB_FIELDS:
            value = _read_small_text(entry / field)
            if value is not None:
                item[field] = value
        if len(item) > 1:
            devices.append(item)
    return tuple(devices)


def read_usb_devices(
    *,
    authority: TaskCapabilityAuthority,
    platform_name: str | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Collect local USB inventory evidence without reset, detach, bind, or driver mutation."""
    target_platform = _platform_key(platform_name)
    authority.require(
        USB_DEVICES_TOOL_ID,
        resource_kind="usb_devices",
        resource_ref="local:usb:devices",
        effect="read",
    )
    base: dict[str, Any] = {
        "tool_id": USB_DEVICES_TOOL_ID,
        "platform": target_platform,
        "scope": "local_usb_inventory",
        "device_limit": USB_DEVICE_LIMIT,
        "interpretation": "evidence_only",
        "root_cause_claimed": False,
    }
    if target_platform == "windows":
        completed = subprocess.run(
            build_windows_usb_plan(),
            capture_output=True,
            text=True,
            timeout=max(1.0, min(float(timeout), 20.0)),
            check=False,
            shell=False,
        )
        return {
            **base,
            "source": "Win32_PnPEntity",
            "returncode": completed.returncode,
            **bound_process_output(completed.stdout, completed.stderr),
        }
    return {
        **base,
        "source": "sysfs_usb",
        "devices": _read_linux_usb_inventory(),
    }


__all__ = [
    "LINUX_USB_ROOT",
    "USB_DEVICE_LIMIT",
    "USB_DEVICES_TOOL_ID",
    "USB_TOOL_METADATA",
    "build_windows_usb_plan",
    "read_usb_devices",
    "usb_micro_tool_registry",
]
