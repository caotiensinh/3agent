from __future__ import annotations

import platform
import subprocess
from pathlib import Path
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output, bound_text_result

DOCK_TOOL_ID = "hardware.dock.snapshot"
DOCK_DEVICE_LIMIT = 32
LINUX_THUNDERBOLT_ROOT = Path("/sys/bus/thunderbolt/devices")
LINUX_USB_ROOT = Path("/sys/bus/usb/devices")

DOCK_TOOL_METADATA = (
    ToolMetadata(
        id=DOCK_TOOL_ID,
        platform="any",
        category="hardware",
        keywords=(
            "usb-c dock",
            "dock station",
            "docking station",
            "thunderbolt dock",
            "usb4 dock",
            "dock not detected",
            "khong nhan dock",
            "ドッキングステーション",
            "USB-C ドック",
            "Thunderbolt ドック",
        ),
        cost="C0",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ).validate(),
)

_WINDOWS_DOCK_QUERY = (
    "Get-CimInstance Win32_PnPEntity | "
    "Where-Object { $_.Name -match '(?i)dock|docking|thunderbolt|usb4|type-c|usb-c' } | "
    "Select-Object Name,Status,Manufacturer,PNPClass,PNPDeviceID | "
    f"Select-Object -First {DOCK_DEVICE_LIMIT} | "
    "ConvertTo-Json -Depth 3 -Compress"
)

_LINUX_DOCK_FIELDS = ("manufacturer", "product", "idVendor", "idProduct")
_DOCK_MARKERS = ("dock", "docking", "thunderbolt", "usb4", "usb-c", "usb c", "type-c")


def dock_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(DOCK_TOOL_METADATA)


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported dock-inventory platform: {value or 'unknown'}")


def build_windows_dock_plan() -> tuple[str, ...]:
    return (
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        _WINDOWS_DOCK_QUERY,
    )


def _read_small_text(path: Path) -> str | None:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    return bound_text_result(raw, max_bytes=1024).text


def _read_linux_dock_inventory() -> tuple[dict[str, Any], ...]:
    candidates: list[dict[str, Any]] = []
    try:
        thunderbolt_entries = sorted(LINUX_THUNDERBOLT_ROOT.iterdir(), key=lambda item: item.name)
    except OSError:
        thunderbolt_entries = []
    for entry in thunderbolt_entries:
        item: dict[str, Any] = {"source_bus": "thunderbolt", "sysfs_name": entry.name}
        for field in ("device_name", "vendor_name", "generation", "authorized"):
            value = _read_small_text(entry / field)
            if value is not None:
                item[field] = value
        candidates.append(item)
        if len(candidates) >= DOCK_DEVICE_LIMIT:
            return tuple(candidates)

    try:
        usb_entries = sorted(LINUX_USB_ROOT.iterdir(), key=lambda item: item.name)
    except OSError:
        usb_entries = []
    for entry in usb_entries:
        values: dict[str, str] = {}
        for field in _LINUX_DOCK_FIELDS:
            value = _read_small_text(entry / field)
            if value is not None:
                values[field] = value
        searchable = " ".join(values.values()).lower()
        if not searchable or not any(marker in searchable for marker in _DOCK_MARKERS):
            continue
        candidates.append({"source_bus": "usb", "sysfs_name": entry.name, **values})
        if len(candidates) >= DOCK_DEVICE_LIMIT:
            break
    return tuple(candidates)


def read_dock_snapshot(
    *,
    authority: TaskCapabilityAuthority,
    platform_name: str | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Collect bounded dock candidates without USB reset, authorization, or device mutation."""
    target_platform = _platform_key(platform_name)
    authority.require(
        DOCK_TOOL_ID,
        resource_kind="dock_devices",
        resource_ref="local:dock:devices",
        effect="read",
    )
    base: dict[str, Any] = {
        "tool_id": DOCK_TOOL_ID,
        "platform": target_platform,
        "scope": "local_dock_inventory",
        "device_limit": DOCK_DEVICE_LIMIT,
        "interpretation": "evidence_only",
        "root_cause_claimed": False,
    }
    if target_platform == "windows":
        completed = subprocess.run(
            build_windows_dock_plan(),
            capture_output=True,
            text=True,
            timeout=max(1.0, min(float(timeout), 20.0)),
            check=False,
            shell=False,
        )
        return {
            **base,
            "source": "Win32_PnPEntity_filtered",
            "returncode": completed.returncode,
            **bound_process_output(completed.stdout, completed.stderr),
        }
    return {
        **base,
        "source": "sysfs_dock_candidates",
        "devices": _read_linux_dock_inventory(),
    }


__all__ = [
    "DOCK_DEVICE_LIMIT",
    "DOCK_TOOL_ID",
    "DOCK_TOOL_METADATA",
    "LINUX_THUNDERBOLT_ROOT",
    "LINUX_USB_ROOT",
    "build_windows_dock_plan",
    "dock_micro_tool_registry",
    "read_dock_snapshot",
]
