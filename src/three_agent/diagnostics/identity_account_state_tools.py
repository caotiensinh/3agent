from __future__ import annotations

import getpass
import platform
import re
import subprocess
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output

IDENTITY_ACCOUNT_STATE_TOOL_ID = "identity.account_state.snapshot"

IDENTITY_ACCOUNT_STATE_METADATA = (
    ToolMetadata(
        id=IDENTITY_ACCOUNT_STATE_TOOL_ID,
        platform="any",
        category="identity",
        keywords=(
            "account state",
            "local account enabled",
            "account disabled",
            "password state",
            "trang thai tai khoan",
            "tai khoan local",
            "ローカルアカウント状態",
            "アカウント有効状態",
        ),
        cost="C0",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ).validate(),
)

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def identity_account_state_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(IDENTITY_ACCOUNT_STATE_METADATA)


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported identity-account-state platform: {value or 'unknown'}")


def build_identity_account_state_plan(
    *, platform_name: str | None = None, username: str | None = None
) -> tuple[str, ...]:
    target_platform = _platform_key(platform_name)
    if target_platform == "windows":
        return (
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$name=$env:USERNAME; Get-LocalUser -Name $name -ErrorAction SilentlyContinue | "
            "Select-Object Name,Enabled,PasswordExpires,UserMayChangePassword,PasswordRequired,LastLogon | "
            "ConvertTo-Json -Compress",
        )
    local_username = str(username or getpass.getuser()).strip()
    if not _USERNAME_RE.fullmatch(local_username):
        raise RuntimeError("local username is outside the bounded account-state contract")
    return ("passwd", "-S", local_username)


def read_identity_account_state(
    *,
    authority: TaskCapabilityAuthority,
    platform_name: str | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Collect bounded local account-state evidence without directory/network access.

    The result is evidence about the local account view only. It never proves Active
    Directory, Entra ID, LDAP, SSO, credential validity, remote lockout, or remote
    authentication health.
    """
    target_platform = _platform_key(platform_name)
    authority.require(
        IDENTITY_ACCOUNT_STATE_TOOL_ID,
        resource_kind="identity_account_state",
        resource_ref="local:identity:account-state",
        effect="read",
    )
    try:
        completed = subprocess.run(
            build_identity_account_state_plan(platform_name=target_platform),
            capture_output=True,
            text=True,
            timeout=max(1.0, min(float(timeout), 15.0)),
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        return {
            "tool_id": IDENTITY_ACCOUNT_STATE_TOOL_ID,
            "platform": target_platform,
            "scope": "local_account_state_only",
            "collector_available": False,
            "collection_succeeded": False,
            "directory_health_claimed": False,
            "authentication_claimed": False,
            "remote_lockout_claimed": False,
            "root_cause_claimed": False,
            "interpretation": "evidence_only",
        }

    bounded = bound_process_output(completed.stdout, completed.stderr)
    return {
        "tool_id": IDENTITY_ACCOUNT_STATE_TOOL_ID,
        "platform": target_platform,
        "scope": "local_account_state_only",
        "collector_available": True,
        "collection_succeeded": completed.returncode == 0,
        "returncode": completed.returncode,
        "directory_health_claimed": False,
        "authentication_claimed": False,
        "remote_lockout_claimed": False,
        "root_cause_claimed": False,
        "interpretation": "evidence_only",
        **bounded,
    }


__all__ = [
    "IDENTITY_ACCOUNT_STATE_METADATA",
    "IDENTITY_ACCOUNT_STATE_TOOL_ID",
    "build_identity_account_state_plan",
    "identity_account_state_micro_tool_registry",
    "read_identity_account_state",
]
