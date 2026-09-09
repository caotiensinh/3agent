from __future__ import annotations

import platform
import subprocess
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output

VOIP_CLIENT_STATE_TOOL_ID = "voip.client_state.snapshot"

VOIP_CLIENT_STATE_METADATA = (
    ToolMetadata(
        id=VOIP_CLIENT_STATE_TOOL_ID,
        platform="any",
        category="voip",
        keywords=("voip status", "softphone status", "teams call client", "jabber client", "zoom phone", "trang thai voip", "ソフトフォン状態", "VoIP 状態"),
        cost="C0",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ).validate(),
)


def voip_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(VOIP_CLIENT_STATE_METADATA)


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported voip platform: {value or 'unknown'}")


def build_voip_client_plan(*, platform_name: str | None = None) -> tuple[str, ...]:
    if _platform_key(platform_name) == "windows":
        return (
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            "Get-Process ms-teams,Teams,Jabber,Zoom -ErrorAction SilentlyContinue | Select-Object Name,Id,StartTime,Responding | ConvertTo-Json -Compress",
        )
    return ("ps", "-eo", "comm=")


def read_voip_client_state(*, authority: TaskCapabilityAuthority, platform_name: str | None = None, timeout: float = 5.0) -> dict[str, Any]:
    """Collect local softphone process evidence only; never register, place calls, or capture media."""
    target_platform = _platform_key(platform_name)
    authority.require(
        VOIP_CLIENT_STATE_TOOL_ID,
        resource_kind="voip_client_state",
        resource_ref="local:voip:client-state",
        effect="read",
    )
    completed = subprocess.run(
        build_voip_client_plan(platform_name=target_platform), capture_output=True, text=True,
        timeout=max(1.0, min(float(timeout), 15.0)), check=False, shell=False,
    )
    bounded = bound_process_output(completed.stdout, completed.stderr)
    return {
        "tool_id": VOIP_CLIENT_STATE_TOOL_ID,
        "platform": target_platform,
        "scope": "local_voip_client_process_state",
        "returncode": completed.returncode,
        "sip_registration_claimed": False,
        "remote_pbx_health_claimed": False,
        "media_capture_performed": False,
        "call_action_performed": False,
        "root_cause_claimed": False,
        "interpretation": "evidence_only",
        **bounded,
    }


__all__ = ["VOIP_CLIENT_STATE_METADATA", "VOIP_CLIENT_STATE_TOOL_ID", "build_voip_client_plan", "read_voip_client_state", "voip_micro_tool_registry"]
