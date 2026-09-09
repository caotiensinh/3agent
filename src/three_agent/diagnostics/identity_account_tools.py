from __future__ import annotations

import getpass
import json
import platform
import subprocess
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_text_result

IDENTITY_ACCOUNT_STATUS_TOOL_ID = "identity.account_state.snapshot"

IDENTITY_ACCOUNT_STATUS_METADATA = (
    ToolMetadata(
        id=IDENTITY_ACCOUNT_STATUS_TOOL_ID,
        platform="any",
        category="identity",
        keywords=(
            "account state",
            "account disabled",
            "account locked",
            "password state",
            "local account status",
            "trang thai tai khoan",
            "tai khoan bi khoa",
            "アカウント状態",
            "アカウント無効",
            "ローカルアカウント",
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
    "$u=Get-LocalUser -Name $env:USERNAME -ErrorAction SilentlyContinue;"
    "if($null -eq $u){'{}'}else{$u|Select-Object Name,Enabled,PasswordExpires,"
    "UserMayChangePassword,PasswordRequired,LastLogon|ConvertTo-Json -Compress}"
)


def identity_account_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(IDENTITY_ACCOUNT_STATUS_METADATA)


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported identity-account platform: {value or 'unknown'}")


def build_identity_account_plan(*, platform_name: str | None = None) -> tuple[str, ...]:
    """Return one local-only argv plan for the current account.

    The caller cannot select another account. Linux resolves only the current process
    username locally; Windows uses the current process environment inside PowerShell.
    """
    if _platform_key(platform_name) == "windows":
        return (
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            _WINDOWS_QUERY,
        )
    return ("passwd", "-S", getpass.getuser())


def _parse_windows(stdout: str) -> dict[str, Any]:
    text = str(stdout or "").strip()
    if not text:
        return {"account_observed": False}
    try:
        payload = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {"account_observed": False}
    if not isinstance(payload, dict) or not payload:
        return {"account_observed": False}
    return {
        "account_observed": True,
        "account_name": str(payload.get("Name") or "")[:128],
        "enabled_observed": payload.get("Enabled") if isinstance(payload.get("Enabled"), bool) else None,
        "password_expires_observed": payload.get("PasswordExpires") if isinstance(payload.get("PasswordExpires"), bool) else None,
        "user_may_change_password_observed": payload.get("UserMayChangePassword") if isinstance(payload.get("UserMayChangePassword"), bool) else None,
        "password_required_observed": payload.get("PasswordRequired") if isinstance(payload.get("PasswordRequired"), bool) else None,
        "last_logon_observed": str(payload.get("LastLogon") or "")[:128],
    }


def _parse_linux(stdout: str) -> dict[str, Any]:
    parts = str(stdout or "").strip().split()
    if len(parts) < 2:
        return {"account_observed": False}
    status = parts[1].upper()
    return {
        "account_observed": True,
        "account_name": parts[0][:128],
        "password_status_code": status[:16],
        "password_locked_observed": status == "L",
        "password_present_observed": status == "P",
        "password_absent_observed": status == "NP",
    }


def _unavailable_result(*, target_platform: str) -> dict[str, Any]:
    return {
        "tool_id": IDENTITY_ACCOUNT_STATUS_TOOL_ID,
        "platform": target_platform,
        "scope": "current_local_account_state",
        "collector_available": False,
        "collection_succeeded": False,
        "observation": {"account_observed": False},
        "stderr": "",
        "stderr_boundary": bound_text_result("", max_bytes=8 * 1024).metadata(),
        "directory_health_claimed": False,
        "authentication_claimed": False,
        "root_cause_claimed": False,
        "interpretation": "evidence_only",
    }


def read_identity_account_state(
    *,
    authority: TaskCapabilityAuthority,
    platform_name: str | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Collect bounded local state for the current OS account only.

    No passwords, hashes, tokens, credential stores, remote directory objects, Entra ID,
    Active Directory, LDAP, authentication attempts, network probes, account changes, or
    password changes are performed. A local disabled/locked observation never proves a
    remote identity-service failure or the root cause of a user complaint.
    """
    target_platform = _platform_key(platform_name)
    authority.require(
        IDENTITY_ACCOUNT_STATUS_TOOL_ID,
        resource_kind="identity_account_state",
        resource_ref="local:identity:current-account",
        effect="read",
    )
    try:
        completed = subprocess.run(
            build_identity_account_plan(platform_name=target_platform),
            capture_output=True,
            text=True,
            timeout=max(1.0, min(float(timeout), 15.0)),
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        return _unavailable_result(target_platform=target_platform)

    observation = _parse_windows(completed.stdout) if target_platform == "windows" else _parse_linux(completed.stdout)
    stderr = bound_text_result(completed.stderr, max_bytes=8 * 1024)
    return {
        "tool_id": IDENTITY_ACCOUNT_STATUS_TOOL_ID,
        "platform": target_platform,
        "scope": "current_local_account_state",
        "collector_available": True,
        "collection_succeeded": completed.returncode == 0,
        "returncode": completed.returncode,
        "observation": observation,
        "stderr": stderr.text,
        "stderr_boundary": stderr.metadata(),
        "directory_health_claimed": False,
        "authentication_claimed": False,
        "root_cause_claimed": False,
        "interpretation": "evidence_only",
    }


__all__ = [
    "IDENTITY_ACCOUNT_STATUS_METADATA",
    "IDENTITY_ACCOUNT_STATUS_TOOL_ID",
    "build_identity_account_plan",
    "identity_account_micro_tool_registry",
    "read_identity_account_state",
]
