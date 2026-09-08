from __future__ import annotations

import platform
import subprocess
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output

WINDOWS_UPDATE_TOOL_ID = "windows.update.history"
WINDOWS_UPDATE_HISTORY_LIMIT = 50

WINDOWS_UPDATE_TOOL_METADATA = (
    ToolMetadata(
        id=WINDOWS_UPDATE_TOOL_ID,
        platform="windows",
        category="windows",
        keywords=(
            "windows update",
            "update history",
            "update failed",
            "recent update",
            "kb update",
            "cap nhat windows",
            "cập nhật windows",
            "Windows Update",
            "更新履歴",
        ),
        cost="C1",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ).validate(),
)

_WINDOWS_UPDATE_HISTORY_QUERY = (
    "$session = New-Object -ComObject Microsoft.Update.Session; "
    "$searcher = $session.CreateUpdateSearcher(); "
    f"$count = [Math]::Min($searcher.GetTotalHistoryCount(), {WINDOWS_UPDATE_HISTORY_LIMIT}); "
    "if ($count -le 0) { @() | ConvertTo-Json -Compress } else { "
    "$searcher.QueryHistory(0, $count) | "
    "Select-Object Date,Title,Operation,ResultCode,HResult | "
    "ConvertTo-Json -Depth 3 -Compress }"
)


def windows_update_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(WINDOWS_UPDATE_TOOL_METADATA)


def _require_windows(platform_name: str | None = None) -> None:
    value = str(platform_name or platform.system()).strip().lower()
    if not value.startswith("win"):
        raise RuntimeError(f"unsupported Windows update-evidence platform: {value or 'unknown'}")


def build_windows_update_history_plan() -> tuple[str, ...]:
    return (
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        _WINDOWS_UPDATE_HISTORY_QUERY,
    )


def read_windows_update_history(
    *,
    authority: TaskCapabilityAuthority,
    platform_name: str | None = None,
    timeout: float = 12.0,
) -> dict[str, Any]:
    """Read bounded Windows Update history without searching, downloading, or installing updates."""
    _require_windows(platform_name)
    authority.require(
        WINDOWS_UPDATE_TOOL_ID,
        resource_kind="windows_update_history",
        resource_ref="local:windows:update-history",
        effect="read",
    )
    completed = subprocess.run(
        build_windows_update_history_plan(),
        capture_output=True,
        text=True,
        timeout=max(1.0, min(float(timeout), 30.0)),
        check=False,
        shell=False,
    )
    return {
        "tool_id": WINDOWS_UPDATE_TOOL_ID,
        "platform": "windows",
        "scope": "local_windows_update_history",
        "history_limit": WINDOWS_UPDATE_HISTORY_LIMIT,
        "source": "Microsoft.Update.Session.QueryHistory",
        "interpretation": "evidence_only",
        "root_cause_claimed": False,
        "returncode": completed.returncode,
        **bound_process_output(completed.stdout, completed.stderr),
    }


__all__ = [
    "WINDOWS_UPDATE_HISTORY_LIMIT",
    "WINDOWS_UPDATE_TOOL_ID",
    "WINDOWS_UPDATE_TOOL_METADATA",
    "build_windows_update_history_plan",
    "read_windows_update_history",
    "windows_update_micro_tool_registry",
]
