from __future__ import annotations

import platform
import subprocess
from pathlib import Path
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output, bound_text_result

STORAGE_IO_TOOL_ID = "storage.io.snapshot"
STORAGE_IO_DEVICE_LIMIT = 32
LINUX_DISKSTATS_PATH = Path("/proc/diskstats")

STORAGE_IO_TOOL_METADATA = (
    ToolMetadata(
        id=STORAGE_IO_TOOL_ID,
        platform="any",
        category="storage",
        keywords=(
            "disk io",
            "storage io",
            "disk busy",
            "disk activity",
            "slow disk",
            "o dia cham",
            "disk usage high",
            "ディスク I/O",
            "ディスク 使用率",
        ),
        cost="C1",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ).validate(),
)

_WINDOWS_STORAGE_IO_QUERY = (
    "Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -ErrorAction Stop | "
    "Where-Object { $_.Name -ne '_Total' } | "
    "Sort-Object Name | "
    f"Select-Object -First {STORAGE_IO_DEVICE_LIMIT} "
    "Name,DiskBytesPersec,DiskReadBytesPersec,DiskWriteBytesPersec,PercentDiskTime,AvgDiskQueueLength | "
    "ConvertTo-Json -Depth 3 -Compress"
)


def storage_io_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(STORAGE_IO_TOOL_METADATA)


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported storage-io platform: {value or 'unknown'}")


def build_windows_storage_io_plan() -> tuple[str, ...]:
    return (
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        _WINDOWS_STORAGE_IO_QUERY,
    )


def _read_linux_diskstats() -> tuple[str, ...]:
    try:
        text = LINUX_DISKSTATS_PATH.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ()
    rows = [line.strip() for line in text.splitlines() if line.strip()]
    bounded_rows: list[str] = []
    for row in rows[:STORAGE_IO_DEVICE_LIMIT]:
        bounded_rows.append(bound_text_result(row, max_bytes=2048).text)
    return tuple(bounded_rows)


def read_storage_io(
    *,
    authority: TaskCapabilityAuthority,
    platform_name: str | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Collect bounded local storage-I/O evidence without tuning disks or processes."""
    target_platform = _platform_key(platform_name)
    authority.require(
        STORAGE_IO_TOOL_ID,
        resource_kind="storage_io",
        resource_ref="local:storage:io",
        effect="read",
    )
    base: dict[str, Any] = {
        "tool_id": STORAGE_IO_TOOL_ID,
        "platform": target_platform,
        "scope": "local_storage_io",
        "device_limit": STORAGE_IO_DEVICE_LIMIT,
        "interpretation": "evidence_only",
        "root_cause_claimed": False,
    }
    if target_platform == "windows":
        completed = subprocess.run(
            build_windows_storage_io_plan(),
            capture_output=True,
            text=True,
            timeout=max(1.0, min(float(timeout), 20.0)),
            check=False,
            shell=False,
        )
        return {
            **base,
            "source": "Win32_PerfFormattedData_PerfDisk_PhysicalDisk",
            "returncode": completed.returncode,
            **bound_process_output(completed.stdout, completed.stderr),
        }
    return {
        **base,
        "source": "proc_diskstats",
        "rows": _read_linux_diskstats(),
        "counter_semantics": "cumulative_kernel_counters",
    }


__all__ = [
    "LINUX_DISKSTATS_PATH",
    "STORAGE_IO_DEVICE_LIMIT",
    "STORAGE_IO_TOOL_ID",
    "STORAGE_IO_TOOL_METADATA",
    "build_windows_storage_io_plan",
    "read_storage_io",
    "storage_io_micro_tool_registry",
]
