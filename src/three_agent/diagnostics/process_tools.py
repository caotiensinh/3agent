from __future__ import annotations

import platform
import subprocess
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output, bound_text_result

PROCESS_TOP_TOOL_ID = "process.top.snapshot"
PROCESS_TOP_LIMIT = 20

PROCESS_TOOL_METADATA = (
    ToolMetadata(
        id=PROCESS_TOP_TOOL_ID,
        platform="any",
        category="performance",
        keywords=(
            "top process",
            "high cpu process",
            "high memory process",
            "process list",
            "computer slow",
            "may cham",
            "process nao an cpu",
            "プロセス",
            "CPU 使用率",
            "メモリ 使用率",
        ),
        cost="C0",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ).validate(),
)

_WINDOWS_PROCESS_QUERY = (
    "Get-Process | "
    "Sort-Object CPU -Descending | "
    f"Select-Object -First {PROCESS_TOP_LIMIT} Name,Id,CPU,WorkingSet64,PrivateMemorySize64 | "
    "ConvertTo-Json -Depth 3 -Compress"
)


def process_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(PROCESS_TOOL_METADATA)


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported process-inventory platform: {value or 'unknown'}")


def build_process_top_plan(*, platform_name: str | None = None) -> tuple[str, ...]:
    if _platform_key(platform_name) == "windows":
        return (
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            _WINDOWS_PROCESS_QUERY,
        )
    return (
        "ps",
        "-eo",
        "pid=,comm=,%cpu=,%mem=,rss=,vsz=",
        "--sort=-%cpu",
    )


def read_top_processes(
    *,
    authority: TaskCapabilityAuthority,
    platform_name: str | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Collect a bounded local process snapshot without killing or changing processes."""
    target_platform = _platform_key(platform_name)
    authority.require(
        PROCESS_TOP_TOOL_ID,
        resource_kind="process_inventory",
        resource_ref="local:processes:top",
        effect="read",
    )
    completed = subprocess.run(
        build_process_top_plan(platform_name=target_platform),
        capture_output=True,
        text=True,
        timeout=max(1.0, min(float(timeout), 20.0)),
        check=False,
        shell=False,
    )

    base: dict[str, Any] = {
        "tool_id": PROCESS_TOP_TOOL_ID,
        "platform": target_platform,
        "scope": "local_top_processes",
        "requested_limit": PROCESS_TOP_LIMIT,
        "interpretation": "evidence_only",
        "root_cause_claimed": False,
        "returncode": completed.returncode,
    }
    if target_platform == "windows":
        return {**base, **bound_process_output(completed.stdout, completed.stderr)}

    lines = [line.rstrip() for line in str(completed.stdout or "").splitlines() if line.strip()]
    selected = "\n".join(lines[:PROCESS_TOP_LIMIT])
    stdout_result = bound_text_result(selected, max_bytes=32 * 1024)
    stderr_result = bound_text_result(completed.stderr, max_bytes=8 * 1024)
    return {
        **base,
        "selected_rows": min(len(lines), PROCESS_TOP_LIMIT),
        "stdout": stdout_result.text,
        "stderr": stderr_result.text,
        "output_boundary": {
            "stdout": stdout_result.metadata(),
            "stderr": stderr_result.metadata(),
        },
    }


__all__ = [
    "PROCESS_TOP_LIMIT",
    "PROCESS_TOP_TOOL_ID",
    "PROCESS_TOOL_METADATA",
    "build_process_top_plan",
    "process_micro_tool_registry",
    "read_top_processes",
]
