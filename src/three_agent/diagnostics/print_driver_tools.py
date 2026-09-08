from __future__ import annotations

import platform
import subprocess
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output

PRINT_DRIVER_TOOL_ID = "windows.print.driver.snapshot"
PRINT_DRIVER_LIMIT = 64

PRINT_DRIVER_TOOL_METADATA = (
    ToolMetadata(
        id=PRINT_DRIVER_TOOL_ID,
        platform="windows",
        category="printer",
        keywords=(
            "printer driver",
            "print driver",
            "wrong printer driver",
            "printer driver missing",
            "driver may in",
            "プリンタードライバー",
            "印刷 ドライバー",
        ),
        cost="C1",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ).validate(),
)

_WINDOWS_PRINT_DRIVER_QUERY = (
    "Get-CimInstance Win32_PrinterDriver -ErrorAction Stop | "
    "Sort-Object Name | "
    f"Select-Object -First {PRINT_DRIVER_LIMIT} Name,SupportedPlatform,Version | "
    "ConvertTo-Json -Depth 3 -Compress"
)


def print_driver_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(PRINT_DRIVER_TOOL_METADATA)


def _require_windows(platform_name: str | None = None) -> None:
    value = str(platform_name or platform.system()).strip().lower()
    if not value.startswith("win"):
        raise RuntimeError(f"unsupported printer-driver platform: {value or 'unknown'}")


def build_windows_print_driver_plan() -> tuple[str, ...]:
    return (
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        _WINDOWS_PRINT_DRIVER_QUERY,
    )


def read_print_drivers(
    *,
    authority: TaskCapabilityAuthority,
    platform_name: str | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Collect bounded Windows printer-driver inventory without modifying print state."""
    _require_windows(platform_name)
    authority.require(
        PRINT_DRIVER_TOOL_ID,
        resource_kind="printer_drivers",
        resource_ref="local:printer:drivers",
        effect="read",
    )
    completed = subprocess.run(
        build_windows_print_driver_plan(),
        capture_output=True,
        text=True,
        timeout=max(1.0, min(float(timeout), 20.0)),
        check=False,
        shell=False,
    )
    return {
        "tool_id": PRINT_DRIVER_TOOL_ID,
        "platform": "windows",
        "scope": "local_printer_driver_inventory",
        "driver_limit": PRINT_DRIVER_LIMIT,
        "source": "Win32_PrinterDriver",
        "interpretation": "evidence_only",
        "root_cause_claimed": False,
        "returncode": completed.returncode,
        **bound_process_output(completed.stdout, completed.stderr),
    }


__all__ = [
    "PRINT_DRIVER_LIMIT",
    "PRINT_DRIVER_TOOL_ID",
    "PRINT_DRIVER_TOOL_METADATA",
    "build_windows_print_driver_plan",
    "print_driver_micro_tool_registry",
    "read_print_drivers",
]
