from __future__ import annotations

import platform
import subprocess
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output

BACKUP_STATUS_TOOL_ID = "backup.local_state.snapshot"

BACKUP_STATUS_METADATA = (
    ToolMetadata(
        id=BACKUP_STATUS_TOOL_ID,
        platform="any",
        category="backup",
        keywords=(
            "backup status",
            "backup service",
            "backup timer",
            "local backup state",
            "trang thai backup",
            "dich vu backup",
            "バックアップ状態",
            "バックアップサービス",
        ),
        cost="C0",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ).validate(),
)


def backup_status_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(BACKUP_STATUS_METADATA)


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported backup-status platform: {value or 'unknown'}")


def build_backup_status_plan(*, platform_name: str | None = None) -> tuple[str, ...]:
    if _platform_key(platform_name) == "windows":
        return (
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-Service -Name wbengine,VSS -ErrorAction SilentlyContinue | "
            "Select-Object Name,Status,StartType | ConvertTo-Json -Compress",
        )
    return (
        "systemctl",
        "show",
        "--no-pager",
        "--property=Id,LoadState,ActiveState,SubState,UnitFileState",
        "restic-backup.timer",
        "borgmatic.timer",
        "backup.timer",
        "rsnapshot.timer",
    )


def read_backup_local_state(
    *,
    authority: TaskCapabilityAuthority,
    platform_name: str | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Collect bounded local backup-component state without touching backup data.

    This collector never reads backup payloads, contacts a backup target, starts a job,
    restores data, validates credentials, or claims backup success/freshness.
    """
    target_platform = _platform_key(platform_name)
    authority.require(
        BACKUP_STATUS_TOOL_ID,
        resource_kind="backup_local_state",
        resource_ref="local:backup:state",
        effect="read",
    )
    try:
        completed = subprocess.run(
            build_backup_status_plan(platform_name=target_platform),
            capture_output=True,
            text=True,
            timeout=max(1.0, min(float(timeout), 15.0)),
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        return {
            "tool_id": BACKUP_STATUS_TOOL_ID,
            "platform": target_platform,
            "scope": "local_backup_components_only",
            "collector_available": False,
            "collection_succeeded": False,
            "backup_success_claimed": False,
            "backup_freshness_claimed": False,
            "restore_viability_claimed": False,
            "remote_destination_health_claimed": False,
            "root_cause_claimed": False,
            "interpretation": "evidence_only",
        }

    bounded = bound_process_output(completed.stdout, completed.stderr)
    return {
        "tool_id": BACKUP_STATUS_TOOL_ID,
        "platform": target_platform,
        "scope": "local_backup_components_only",
        "collector_available": True,
        "collection_succeeded": completed.returncode == 0,
        "returncode": completed.returncode,
        "backup_success_claimed": False,
        "backup_freshness_claimed": False,
        "restore_viability_claimed": False,
        "remote_destination_health_claimed": False,
        "root_cause_claimed": False,
        "interpretation": "evidence_only",
        **bounded,
    }


__all__ = [
    "BACKUP_STATUS_METADATA",
    "BACKUP_STATUS_TOOL_ID",
    "backup_status_micro_tool_registry",
    "build_backup_status_plan",
    "read_backup_local_state",
]
