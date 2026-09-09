from __future__ import annotations

import platform
import subprocess
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output

CLOUD_FILES_STATUS_TOOL_ID = "cloud_files.client_state.snapshot"

CLOUD_FILES_STATUS_METADATA = (
    ToolMetadata(
        id=CLOUD_FILES_STATUS_TOOL_ID,
        platform="any",
        category="cloud_files",
        keywords=(
            "cloud files status",
            "sync client",
            "onedrive client",
            "dropbox client",
            "google drive client",
            "trang thai dong bo",
            "クラウド同期",
            "同期クライアント",
        ),
        cost="C0",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ).validate(),
)


def cloud_files_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(CLOUD_FILES_STATUS_METADATA)


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported cloud-files platform: {value or 'unknown'}")


def build_cloud_files_plan(*, platform_name: str | None = None) -> tuple[str, ...]:
    if _platform_key(platform_name) == "windows":
        return (
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-Process OneDrive,Dropbox,GoogleDriveFS -ErrorAction SilentlyContinue | "
            "Select-Object Name,Id,StartTime,Responding | ConvertTo-Json -Compress",
        )
    return (
        "ps",
        "-eo",
        "comm=",
    )


def read_cloud_files_client_state(
    *,
    authority: TaskCapabilityAuthority,
    platform_name: str | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Collect local sync-client process evidence only.

    No cloud API, network probe, account authentication, token access, sync forcing,
    sync-root mutation, or user-file content read is performed.
    """
    target_platform = _platform_key(platform_name)
    authority.require(
        CLOUD_FILES_STATUS_TOOL_ID,
        resource_kind="cloud_files_client_state",
        resource_ref="local:cloud-files:client-state",
        effect="read",
    )
    completed = subprocess.run(
        build_cloud_files_plan(platform_name=target_platform),
        capture_output=True,
        text=True,
        timeout=max(1.0, min(float(timeout), 15.0)),
        check=False,
        shell=False,
    )
    bounded = bound_process_output(completed.stdout, completed.stderr)
    return {
        "tool_id": CLOUD_FILES_STATUS_TOOL_ID,
        "platform": target_platform,
        "scope": "local_sync_client_process_state",
        "returncode": completed.returncode,
        "remote_provider_health_claimed": False,
        "authentication_claimed": False,
        "sync_success_claimed": False,
        "root_cause_claimed": False,
        "interpretation": "evidence_only",
        **bounded,
    }


__all__ = [
    "CLOUD_FILES_STATUS_METADATA",
    "CLOUD_FILES_STATUS_TOOL_ID",
    "build_cloud_files_plan",
    "cloud_files_micro_tool_registry",
    "read_cloud_files_client_state",
]
