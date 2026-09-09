from __future__ import annotations

import platform
import subprocess
from pathlib import Path
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output, bound_text_result

DRIVER_INVENTORY_TOOL_ID = "driver.inventory.snapshot"
DRIVER_DEVICE_LIMIT = 64
LINUX_PCI_ROOT = Path("/sys/bus/pci/devices")
LINUX_USB_ROOT = Path("/sys/bus/usb/devices")

DRIVER_INVENTORY_METADATA = (
    ToolMetadata(
        id=DRIVER_INVENTORY_TOOL_ID,
        platform="any",
        category="hardware",
        keywords=(
            "driver inventory",
            "device driver",
            "driver binding",
            "driver version",
            "driver missing",
            "peripheral driver",
            "loi driver",
            "ドライバー一覧",
            "デバイスドライバー",
            "ドライバー認識",
        ),
        cost="C1",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ).validate(),
)

_WINDOWS_DRIVER_QUERY = (
    "Get-CimInstance Win32_PnPSignedDriver | "
    "Select-Object DeviceName,DeviceClass,DriverProviderName,DriverVersion,DriverDate,InfName,IsSigned | "
    f"Select-Object -First {DRIVER_DEVICE_LIMIT} | "
    "ConvertTo-Json -Depth 3 -Compress"
)


def driver_inventory_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(DRIVER_INVENTORY_METADATA)


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported driver-inventory platform: {value or 'unknown'}")


def build_windows_driver_inventory_plan() -> tuple[str, ...]:
    return (
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        _WINDOWS_DRIVER_QUERY,
    )


def _read_small_text(path: Path) -> str | None:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    return bound_text_result(raw, max_bytes=1024).text


def _driver_name(entry: Path) -> str | None:
    driver_path = entry / "driver"
    try:
        if not driver_path.exists():
            return None
        return driver_path.resolve(strict=True).name
    except OSError:
        return None


def _read_linux_bus(root: Path, *, bus: str, remaining: int) -> list[dict[str, Any]]:
    if remaining <= 0:
        return []
    try:
        entries = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError:
        return []
    devices: list[dict[str, Any]] = []
    fields = (
        ("vendor", "device", "class")
        if bus == "pci"
        else ("manufacturer", "product", "idVendor", "idProduct")
    )
    for entry in entries:
        item: dict[str, Any] = {"bus": bus, "sysfs_name": entry.name}
        for field in fields:
            value = _read_small_text(entry / field)
            if value is not None:
                item[field] = value
        driver = _driver_name(entry)
        item["driver_bound"] = driver is not None
        if driver is not None:
            item["driver"] = driver
        if len(item) > 3 or driver is not None:
            devices.append(item)
        if len(devices) >= remaining:
            break
    return devices


def _read_linux_driver_inventory() -> tuple[dict[str, Any], ...]:
    devices = _read_linux_bus(LINUX_PCI_ROOT, bus="pci", remaining=DRIVER_DEVICE_LIMIT)
    remaining = DRIVER_DEVICE_LIMIT - len(devices)
    if remaining > 0:
        devices.extend(_read_linux_bus(LINUX_USB_ROOT, bus="usb", remaining=remaining))
    return tuple(devices[:DRIVER_DEVICE_LIMIT])


def read_driver_inventory(
    *,
    authority: TaskCapabilityAuthority,
    platform_name: str | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Collect bounded device-driver binding evidence without install, update, bind, or unload."""
    target_platform = _platform_key(platform_name)
    authority.require(
        DRIVER_INVENTORY_TOOL_ID,
        resource_kind="driver_inventory",
        resource_ref="local:driver:inventory",
        effect="read",
    )
    base: dict[str, Any] = {
        "tool_id": DRIVER_INVENTORY_TOOL_ID,
        "platform": target_platform,
        "scope": "local_driver_inventory",
        "device_limit": DRIVER_DEVICE_LIMIT,
        "interpretation": "evidence_only",
        "root_cause_claimed": False,
    }
    if target_platform == "windows":
        completed = subprocess.run(
            build_windows_driver_inventory_plan(),
            capture_output=True,
            text=True,
            timeout=max(1.0, min(float(timeout), 20.0)),
            check=False,
            shell=False,
        )
        return {
            **base,
            "source": "Win32_PnPSignedDriver",
            "returncode": completed.returncode,
            **bound_process_output(completed.stdout, completed.stderr),
        }
    return {
        **base,
        "source": "sysfs_pci_usb_driver_binding",
        "devices": _read_linux_driver_inventory(),
    }


__all__ = [
    "DRIVER_DEVICE_LIMIT",
    "DRIVER_INVENTORY_METADATA",
    "DRIVER_INVENTORY_TOOL_ID",
    "LINUX_PCI_ROOT",
    "LINUX_USB_ROOT",
    "build_windows_driver_inventory_plan",
    "driver_inventory_micro_tool_registry",
    "read_driver_inventory",
]
