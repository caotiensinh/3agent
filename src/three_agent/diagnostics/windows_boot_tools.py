from __future__ import annotations

import platform
import subprocess
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output

WINDOWS_BOOT_TOOL_ID = "windows.boot.snapshot"

WINDOWS_BOOT_TOOL_METADATA = (
    ToolMetadata(
        id=WINDOWS_BOOT_TOOL_ID,
        platform="windows",
        category="windows",
        keywords=(
            "boot time",
            "last boot",
            "startup",
            "reboot",
            "windows boot",
            "khoi dong",
            "khởi động",
            "起動",
            "再起動",
        ),
        cost="C0",
        risk="read_only",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=False,
        effect="read",
    ).validate(),
)

_WINDOWS_BOOT_QUERY = (
    "Get-CimInstance Win32_OperatingSystem -ErrorAction Stop | "
    "Select-Object LastBootUpTime,LocalDateTime | "
    "ConvertTo-Json -Depth 3 -Compress"
)


def windows_boot_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(WINDOWS_BOOT_TOOL_METADATA)


def _require_windows(platform_name: str | None = None) -> None:
    value = str(platform_name or platform.system()).strip().lower()
    if not value.startswith("win"):
        raise RuntimeError(f"unsupported Windows boot-evidence platform: {value or 'unknown'}")


def build_windows_boot_plan() -> tuple[str, ...]:
    return (
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        _WINDOWS_BOOT_QUERY,
    )


def read_windows_boot(
    *,
    authority: TaskCapabilityAuthority,
    platform_name: str | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Collect Windows boot timestamps without rebooting or changing startup state."""
    _require_windows(platform_name)
    authority.require(
        WINDOWS_BOOT_TOOL_ID,
        resource_kind="boot_state",
        resource_ref="local:windows:boot",
        effect="read",
    )
    completed = subprocess.run(
        build_windows_boot_plan(),
        capture_output=True,
        text=True,
        timeout=max(1.0, min(float(timeout), 20.0)),
        check=False,
        shell=False,
    )
    return {
        "tool_id": WINDOWS_BOOT_TOOL_ID,
        "platform": "windows",
        "scope": "local_windows_boot_state",
        "source": "Win32_OperatingSystem",
        "interpretation": "evidence_only",
        "root_cause_claimed": False,
        "returncode": completed.returncode,
        **bound_process_output(completed.stdout, completed.stderr),
    }


__all__ = [
    "WINDOWS_BOOT_TOOL_ID",
    "WINDOWS_BOOT_TOOL_METADATA",
    "build_windows_boot_plan",
    "read_windows_boot",
    "windows_boot_micro_tool_registry",
]
