from __future__ import annotations

import json
import platform
import subprocess
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_text_result

BACKUP_STATUS_TOOL_ID = "backup.status.snapshot"
BACKUP_EVENT_LIMIT = 16

BACKUP_STATUS_METADATA = (
    ToolMetadata(
        id=BACKUP_STATUS_TOOL_ID,
        platform="any",
        category="backup",
        keywords=(
            "backup status",
            "backup history",
            "last backup",
            "backup failed",
            "backup job",
            "trang thai backup",
            "sao luu",
            "バックアップ状態",
            "バックアップ履歴",
        ),
        cost="C0",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ).validate(),
)

_WINDOWS_QUERY = (
    "$log='Microsoft-Windows-Backup';"
    "Get-WinEvent -FilterHashtable @{LogName=$log} -ErrorAction SilentlyContinue | "
    f"Select-Object -First {BACKUP_EVENT_LIMIT} TimeCreated,Id,LevelDisplayName,ProviderName | "
    "ConvertTo-Json -Depth 3 -Compress"
)
_LINUX_UNITS = (
    "restic-backup.service",
    "borgbackup.service",
    "duplicity.service",
    "backup.service",
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
            _WINDOWS_QUERY,
        )
    return (
        "systemctl",
        "show",
        "--no-pager",
        "--property=Id,LoadState,ActiveState,SubState,Result,ExecMainStatus",
        *_LINUX_UNITS,
    )


def _parse_windows(stdout: str) -> list[dict[str, Any]]:
    text = str(stdout or "").strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    items = payload if isinstance(payload, list) else [payload]
    rows: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "time_created": str(item.get("TimeCreated") or "")[:128],
                "event_id": item.get("Id"),
                "level": str(item.get("LevelDisplayName") or "")[:64],
                "provider": str(item.get("ProviderName") or "")[:128],
            }
        )
        if len(rows) >= BACKUP_EVENT_LIMIT:
            break
    return rows


def _parse_linux(stdout: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for raw in str(stdout or "").splitlines() + [""]:
        line = raw.strip()
        if not line:
            if current:
                if current.get("Id") and current.get("LoadState") != "not-found":
                    rows.append(
                        {
                            "unit": str(current.get("Id") or "")[:128],
                            "load_state": str(current.get("LoadState") or "")[:32],
                            "active_state": str(current.get("ActiveState") or "")[:32],
                            "sub_state": str(current.get("SubState") or "")[:32],
                            "result": str(current.get("Result") or "")[:32],
                            "exec_main_status": str(current.get("ExecMainStatus") or "")[:32],
                        }
                    )
                current = {}
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            current[key] = value
    return rows


def _unavailable_result(*, target_platform: str) -> dict[str, Any]:
    return {
        "tool_id": BACKUP_STATUS_TOOL_ID,
        "platform": target_platform,
        "scope": "local_backup_evidence",
        "collector_available": False,
        "collection_succeeded": False,
        "observations": [],
        "backup_success_claimed": False,
        "backup_completeness_claimed": False,
        "remote_repository_health_claimed": False,
        "root_cause_claimed": False,
        "interpretation": "evidence_only",
    }


def read_backup_status(
    *,
    authority: TaskCapabilityAuthority,
    platform_name: str | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Collect bounded local backup-related evidence without accessing backup data.

    Windows reads local Backup event metadata only. Linux observes a small fixed list of
    common local backup service units. The collector never opens backup archives, reads
    repository paths, credentials, file contents, cloud state, or remote endpoints and
    never claims that a backup is complete, restorable, or the root cause of an issue.
    """
    target_platform = _platform_key(platform_name)
    authority.require(
        BACKUP_STATUS_TOOL_ID,
        resource_kind="backup_status",
        resource_ref="local:backup:status",
        effect="read",
    )
    try:
        completed = subprocess.run(
            build_backup_status_plan(platform_name=target_platform),
            capture_output=True,
            text=True,
            timeout=max(1.0, min(float(timeout), 20.0)),
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        return _unavailable_result(target_platform=target_platform)

    observations = _parse_windows(completed.stdout) if target_platform == "windows" else _parse_linux(completed.stdout)
    stderr = bound_text_result(completed.stderr, max_bytes=8 * 1024)
    return {
        "tool_id": BACKUP_STATUS_TOOL_ID,
        "platform": target_platform,
        "scope": "local_backup_evidence",
        "collector_available": True,
        "collection_succeeded": completed.returncode == 0,
        "returncode": completed.returncode,
        "observed_count": len(observations),
        "observations": observations,
        "stderr": stderr.text,
        "stderr_boundary": stderr.metadata(),
        "backup_success_claimed": False,
        "backup_completeness_claimed": False,
        "remote_repository_health_claimed": False,
        "root_cause_claimed": False,
        "interpretation": "evidence_only",
    }


__all__ = [
    "BACKUP_EVENT_LIMIT",
    "BACKUP_STATUS_METADATA",
    "BACKUP_STATUS_TOOL_ID",
    "backup_status_micro_tool_registry",
    "build_backup_status_plan",
    "read_backup_status",
]
