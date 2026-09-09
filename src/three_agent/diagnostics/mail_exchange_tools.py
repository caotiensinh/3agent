from __future__ import annotations

import platform
import subprocess
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output

MAIL_EXCHANGE_STATUS_TOOL_ID = "mail_exchange.client_state.snapshot"

MAIL_EXCHANGE_STATUS_METADATA = (
    ToolMetadata(
        id=MAIL_EXCHANGE_STATUS_TOOL_ID,
        platform="any",
        category="mail_exchange",
        keywords=("mail client status", "outlook status", "exchange client", "email client", "trang thai outlook", "メールクライアント", "Outlook 状態"),
        cost="C0",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ).validate(),
)


def mail_exchange_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(MAIL_EXCHANGE_STATUS_METADATA)


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported mail-exchange platform: {value or 'unknown'}")


def build_mail_exchange_plan(*, platform_name: str | None = None) -> tuple[str, ...]:
    if _platform_key(platform_name) == "windows":
        return (
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            "Get-Process OUTLOOK,olk -ErrorAction SilentlyContinue | Select-Object Name,Id,StartTime,Responding | ConvertTo-Json -Compress",
        )
    return ("ps", "-eo", "comm=")


def read_mail_exchange_client_state(*, authority: TaskCapabilityAuthority, platform_name: str | None = None, timeout: float = 5.0) -> dict[str, Any]:
    """Collect local mail-client process evidence only; never access mailbox contents or remote mail services."""
    target_platform = _platform_key(platform_name)
    authority.require(
        MAIL_EXCHANGE_STATUS_TOOL_ID,
        resource_kind="mail_exchange_client_state",
        resource_ref="local:mail-exchange:client-state",
        effect="read",
    )
    completed = subprocess.run(
        build_mail_exchange_plan(platform_name=target_platform), capture_output=True, text=True,
        timeout=max(1.0, min(float(timeout), 15.0)), check=False, shell=False,
    )
    bounded = bound_process_output(completed.stdout, completed.stderr)
    return {
        "tool_id": MAIL_EXCHANGE_STATUS_TOOL_ID,
        "platform": target_platform,
        "scope": "local_mail_client_process_state",
        "returncode": completed.returncode,
        "mailbox_content_read": False,
        "authentication_claimed": False,
        "remote_exchange_health_claimed": False,
        "root_cause_claimed": False,
        "interpretation": "evidence_only",
        **bounded,
    }


__all__ = ["MAIL_EXCHANGE_STATUS_METADATA", "MAIL_EXCHANGE_STATUS_TOOL_ID", "build_mail_exchange_plan", "mail_exchange_micro_tool_registry", "read_mail_exchange_client_state"]
