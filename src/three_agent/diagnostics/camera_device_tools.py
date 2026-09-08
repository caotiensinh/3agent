from __future__ import annotations

import platform
import subprocess
from pathlib import Path
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output, bound_text_result

CAMERA_DEVICES_TOOL_ID = "camera.devices.snapshot"
CAMERA_DEVICE_LIMIT = 32
LINUX_VIDEO_CLASS_ROOT = Path("/sys/class/video4linux")
LINUX_DEVICE_ROOT = Path("/dev")

CAMERA_DEVICE_TOOL_METADATA = (
    ToolMetadata(
        id=CAMERA_DEVICES_TOOL_ID,
        platform="any",
        category="camera",
        keywords=(
            "webcam",
            "camera device",
            "camera not detected",
            "teams camera",
            "zoom camera",
            "camera khong nhan",
            "webcam khong hoat dong",
            "カメラ",
            "Webカメラ",
            "カメラ 認識しない",
        ),
        cost="C0",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ).validate(),
)

_WINDOWS_CAMERA_QUERY = (
    "Get-CimInstance Win32_PnPEntity | "
    "Where-Object { $_.PNPClass -in @('Camera','Image') } | "
    "Select-Object Name,Status,Manufacturer,PNPClass,PNPDeviceID | "
    "ConvertTo-Json -Depth 3 -Compress"
)


def camera_device_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(CAMERA_DEVICE_TOOL_METADATA)


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported camera-device platform: {value or 'unknown'}")


def build_windows_camera_device_plan() -> tuple[str, ...]:
    return (
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        _WINDOWS_CAMERA_QUERY,
    )


def _read_linux_camera_inventory() -> tuple[dict[str, Any], ...]:
    try:
        entries = sorted(LINUX_VIDEO_CLASS_ROOT.iterdir(), key=lambda item: item.name)
    except OSError:
        return ()
    devices: list[dict[str, Any]] = []
    for entry in entries[:CAMERA_DEVICE_LIMIT]:
        try:
            raw_name = (entry / "name").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            raw_name = ""
        bounded_name = bound_text_result(raw_name, max_bytes=1024).text if raw_name else ""
        device_path = LINUX_DEVICE_ROOT / entry.name
        devices.append(
            {
                "sysfs_name": entry.name,
                "name": bounded_name,
                "device_node": device_path.as_posix(),
                "device_node_present": device_path.exists(),
            }
        )
    return tuple(devices)


def read_camera_devices(
    *,
    authority: TaskCapabilityAuthority,
    platform_name: str | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Collect local webcam/video-device inventory without opening streams or changing settings."""
    target_platform = _platform_key(platform_name)
    authority.require(
        CAMERA_DEVICES_TOOL_ID,
        resource_kind="camera_devices",
        resource_ref="local:camera:devices",
        effect="read",
    )
    base: dict[str, Any] = {
        "tool_id": CAMERA_DEVICES_TOOL_ID,
        "platform": target_platform,
        "scope": "local_camera_device_inventory",
        "device_limit": CAMERA_DEVICE_LIMIT,
        "interpretation": "evidence_only",
        "root_cause_claimed": False,
    }
    if target_platform == "windows":
        completed = subprocess.run(
            build_windows_camera_device_plan(),
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
        "source": "video4linux_sysfs",
        "devices": _read_linux_camera_inventory(),
    }


__all__ = [
    "CAMERA_DEVICE_LIMIT",
    "CAMERA_DEVICES_TOOL_ID",
    "CAMERA_DEVICE_TOOL_METADATA",
    "LINUX_DEVICE_ROOT",
    "LINUX_VIDEO_CLASS_ROOT",
    "build_windows_camera_device_plan",
    "camera_device_micro_tool_registry",
    "read_camera_devices",
]
