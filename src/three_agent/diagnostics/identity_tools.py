from __future__ import annotations

import platform
import subprocess
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output

IDENTITY_SESSION_TOOL_ID = "identity.session.snapshot"

IDENTITY_TOOL_METADATA = (
    ToolMetadata(
        id=IDENTITY_SESSION_TOOL_ID,
        platform="any",
        category="identity",
        keywords=(
            "current user",
            "logged in user",
            "login identity",
            "session identity",
            "whoami",
            "nguoi dung hien tai",
            "tai khoan dang dang nhap",
            "現在のユーザー",
            "ログインユーザー",
        ),
        cost="C0",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ).validate(),
)


def identity_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(IDENTITY_TOOL_METADATA)


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported identity-session platform: {value or 'unknown'}")


def build_identity_session_plan(*, platform_name: str | None = None) -> tuple[str, ...]:
    """Return one fixed local-only argv plan for the current process identity."""
    if _platform_key(platform_name) == "windows":
        return ("whoami.exe", "/user", "/fo", "csv", "/nh")
    return ("id",)


def read_identity_session(
    *,
    authority: TaskCapabilityAuthority,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Collect bounded evidence about the current logged-in identity only.

    This tool does not read passwords, tokens, credential stores, directory objects,
    group policy, Active Directory, Entra ID, or any remote identity service.
    """
    authority.require(
        IDENTITY_SESSION_TOOL_ID,
        resource_kind="identity_session",
        resource_ref="local:identity:current",
        effect="read",
    )
    plan = build_identity_session_plan()
    completed = subprocess.run(
        plan,
        capture_output=True,
        text=True,
        timeout=max(1.0, min(float(timeout), 15.0)),
        check=False,
        shell=False,
    )
    bounded = bound_process_output(completed.stdout, completed.stderr)
    return {
        "tool_id": IDENTITY_SESSION_TOOL_ID,
        "returncode": completed.returncode,
        "scope": "current_process_identity",
        "interpretation": "evidence_only",
        **bounded,
    }


__all__ = [
    "IDENTITY_SESSION_TOOL_ID",
    "IDENTITY_TOOL_METADATA",
    "build_identity_session_plan",
    "identity_micro_tool_registry",
    "read_identity_session",
]
