from __future__ import annotations

import platform
import subprocess
from pathlib import Path
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output, bound_text_result

DISPLAY_TOOL_ID = "hardware.display.snapshot"
DISPLAY_CONNECTOR_LIMIT = 16
DISPLAY_MODE_LIMIT = 8
LINUX_DRM_ROOT = Path("/sys/class/drm")

DISPLAY_TOOL_METADATA = (
    ToolMetadata(
        id=DISPLAY_TOOL_ID,
        platform="any",
        category="hardware",
        keywords=(
            "display topology",
            "external monitor",
            "monitor not detected",
            "display disconnected",
            "screen resolution",
            "man hinh ngoai",
            "khong nhan man hinh",
            "外部モニター",
            "ディスプレイ認識",
            "画面を認識しない",
        ),
        cost="C0",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ).validate(),
)

_WINDOWS_DISPLAY_QUERY = (
    "Get-CimInstance Win32_DesktopMonitor | "
    "Select-Object Name,Status,PNPDeviceID,ScreenWidth,ScreenHeight | "
    f"Select-Object -First {DISPLAY_CONNECTOR_LIMIT} | "
    "ConvertTo-Json -Depth 3 -Compress"
)


def display_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(DISPLAY_TOOL_METADATA)


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported display-inventory platform: {value or 'unknown'}")


def build_windows_display_plan() -> tuple[str, ...]:
    return (
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        _WINDOWS_DISPLAY_QUERY,
    )


def _read_small_text(path: Path, *, max_bytes: int = 4096) -> str | None:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    return bound_text_result(raw, max_bytes=max_bytes).text


def _read_linux_display_inventory() -> tuple[dict[str, Any], ...]:
    try:
        entries = sorted(LINUX_DRM_ROOT.iterdir(), key=lambda item: item.name)
    except OSError:
        return ()
    connectors: list[dict[str, Any]] = []
    for entry in entries:
        status_path = entry / "status"
        if not status_path.exists():
            continue
        item: dict[str, Any] = {"connector": entry.name}
        status = _read_small_text(status_path, max_bytes=128)
        enabled = _read_small_text(entry / "enabled", max_bytes=128)
        if status is not None:
            item["status"] = status
        if enabled is not None:
            item["enabled"] = enabled
        modes = _read_small_text(entry / "modes")
        if modes:
            item["modes"] = tuple(
                line.strip() for line in modes.splitlines() if line.strip()
            )[:DISPLAY_MODE_LIMIT]
        connectors.append(item)
        if len(connectors) >= DISPLAY_CONNECTOR_LIMIT:
            break
    return tuple(connectors)


def read_display_snapshot(
    *,
    authority: TaskCapabilityAuthority,
    platform_name: str | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Collect bounded local display evidence without changing display configuration."""
    target_platform = _platform_key(platform_name)
    authority.require(
        DISPLAY_TOOL_ID,
        resource_kind="display_devices",
        resource_ref="local:display:devices",
        effect="read",
    )
    base: dict[str, Any] = {
        "tool_id": DISPLAY_TOOL_ID,
        "platform": target_platform,
        "scope": "local_display_inventory",
        "connector_limit": DISPLAY_CONNECTOR_LIMIT,
        "interpretation": "evidence_only",
        "root_cause_claimed": False,
    }
    if target_platform == "windows":
        completed = subprocess.run(
            build_windows_display_plan(),
            capture_output=True,
            text=True,
            timeout=max(1.0, min(float(timeout), 20.0)),
            check=False,
            shell=False,
        )
        return {
            **base,
            "source": "Win32_DesktopMonitor",
            "returncode": completed.returncode,
            **bound_process_output(completed.stdout, completed.stderr),
        }
    return {
        **base,
        "source": "sysfs_drm",
        "connectors": _read_linux_display_inventory(),
    }


__all__ = [
    "DISPLAY_CONNECTOR_LIMIT",
    "DISPLAY_MODE_LIMIT",
    "DISPLAY_TOOL_ID",
    "DISPLAY_TOOL_METADATA",
    "LINUX_DRM_ROOT",
    "build_windows_display_plan",
    "display_micro_tool_registry",
    "read_display_snapshot",
]
