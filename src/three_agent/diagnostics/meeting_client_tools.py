from __future__ import annotations

import json
import platform
import subprocess
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_text_result

MEETING_CLIENT_TOOL_ID = "meeting.client.snapshot"
MEETING_CLIENT_LIMIT = 20

MEETING_CLIENT_TOOL_METADATA = (
    ToolMetadata(
        id=MEETING_CLIENT_TOOL_ID,
        platform="any",
        category="meeting",
        keywords=(
            "meeting client",
            "teams running",
            "zoom running",
            "webex running",
            "video meeting app",
            "ung dung hop",
            "teams co chay khong",
            "会議アプリ",
            "Teams 起動",
            "Zoom 起動",
            "Webex 起動",
        ),
        cost="C0",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ).validate(),
)

_WINDOWS_PROCESS_NAMES = (
    "Teams",
    "ms-teams",
    "Zoom",
    "Webex",
    "WebexHost",
    "CiscoCollabHost",
)

_CLIENT_FAMILIES = {
    "teams": "microsoft_teams",
    "ms-teams": "microsoft_teams",
    "msteams": "microsoft_teams",
    "zoom": "zoom",
    "zoomworkplace": "zoom",
    "webex": "webex",
    "webexhost": "webex",
    "ciscocollabhost": "webex",
    "ciscocollabhos": "webex",
}

_WINDOWS_PROCESS_LITERAL = ",".join(f"'{name}'" for name in _WINDOWS_PROCESS_NAMES)
_WINDOWS_QUERY = (
    "$names = @("
    + _WINDOWS_PROCESS_LITERAL
    + "); "
    "Get-Process | Where-Object { $names -contains $_.ProcessName } | "
    f"Select-Object -First {MEETING_CLIENT_LIMIT} ProcessName,Id | "
    "ConvertTo-Json -Depth 3 -Compress"
)


def meeting_client_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(MEETING_CLIENT_TOOL_METADATA)


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported meeting-client platform: {value or 'unknown'}")


def build_meeting_client_plan(*, platform_name: str | None = None) -> tuple[str, ...]:
    if _platform_key(platform_name) == "windows":
        return (
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            _WINDOWS_QUERY,
        )
    return ("ps", "-eo", "pid=,comm=")


def _normalize_process_name(value: str) -> str:
    text = str(value or "").strip().lower()
    if text.endswith(".exe"):
        text = text[:-4]
    return "".join(character for character in text if character.isalnum() or character == "-")


def _client_family(process_name: str) -> str | None:
    return _CLIENT_FAMILIES.get(_normalize_process_name(process_name))


def _row(process_name: str, pid: Any) -> dict[str, Any] | None:
    family = _client_family(process_name)
    if family is None:
        return None
    try:
        process_id = int(pid)
    except (TypeError, ValueError):
        return None
    if process_id <= 0:
        return None
    return {
        "client_family": family,
        "process_name": str(process_name).strip()[:128],
        "pid": process_id,
    }


def _parse_windows_rows(stdout: str) -> list[dict[str, Any]]:
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
        parsed = _row(item.get("ProcessName", ""), item.get("Id"))
        if parsed is not None:
            rows.append(parsed)
        if len(rows) >= MEETING_CLIENT_LIMIT:
            break
    return rows


def _parse_linux_rows(stdout: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in str(stdout or "").splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) != 2:
            continue
        parsed = _row(parts[1], parts[0])
        if parsed is not None:
            rows.append(parsed)
        if len(rows) >= MEETING_CLIENT_LIMIT:
            break
    return rows


def read_running_meeting_clients(
    *,
    authority: TaskCapabilityAuthority,
    platform_name: str | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Collect bounded local evidence about allowlisted *running* meeting clients.

    Absence is intentionally not interpreted as "not installed", "service down", or a
    root cause. The collector performs no network access and does not inspect process
    command lines, environment variables, files, credentials, or meeting content.
    """
    target_platform = _platform_key(platform_name)
    authority.require(
        MEETING_CLIENT_TOOL_ID,
        resource_kind="meeting_clients",
        resource_ref="local:meeting:clients",
        effect="read",
    )
    completed = subprocess.run(
        build_meeting_client_plan(platform_name=target_platform),
        capture_output=True,
        text=True,
        timeout=max(1.0, min(float(timeout), 20.0)),
        check=False,
        shell=False,
    )
    if target_platform == "windows":
        rows = _parse_windows_rows(completed.stdout)
    else:
        rows = _parse_linux_rows(completed.stdout)
    stderr = bound_text_result(completed.stderr, max_bytes=8 * 1024)
    return {
        "tool_id": MEETING_CLIENT_TOOL_ID,
        "platform": target_platform,
        "scope": "local_running_meeting_clients",
        "requested_limit": MEETING_CLIENT_LIMIT,
        "observed_count": len(rows),
        "observed_running_clients": rows,
        "collection_succeeded": completed.returncode == 0,
        "returncode": completed.returncode,
        "stderr": stderr.text,
        "stderr_boundary": stderr.metadata(),
        "observation_semantics": "running_processes_only",
        "installation_state_claimed": False,
        "service_health_claimed": False,
        "root_cause_claimed": False,
        "interpretation": "evidence_only",
    }


__all__ = [
    "MEETING_CLIENT_LIMIT",
    "MEETING_CLIENT_TOOL_ID",
    "MEETING_CLIENT_TOOL_METADATA",
    "build_meeting_client_plan",
    "meeting_client_micro_tool_registry",
    "read_running_meeting_clients",
]
