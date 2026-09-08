from __future__ import annotations

import subprocess
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output

GROUP_POLICY_TOOL_ID = "windows.group_policy.result"

GROUP_POLICY_TOOL_METADATA = (
    ToolMetadata(
        id=GROUP_POLICY_TOOL_ID,
        platform="windows",
        category="policy",
        keywords=(
            "group policy",
            "gpo",
            "gpresult",
            "policy not applied",
            "domain policy",
            "chinh sach nhom",
            "gpo khong ap dung",
            "グループポリシー",
            "GPO",
        ),
        cost="C1",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ).validate(),
)


def group_policy_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(GROUP_POLICY_TOOL_METADATA)


def build_group_policy_plan(*, scope: str = "user") -> tuple[str, ...]:
    normalized = str(scope).strip().lower()
    if normalized not in {"user", "computer", "all"}:
        raise ValueError("scope must be user, computer, or all")
    if normalized == "all":
        return ("gpresult.exe", "/R")
    return ("gpresult.exe", "/R", "/SCOPE", normalized.upper())


def read_group_policy_result(
    *,
    authority: TaskCapabilityAuthority,
    scope: str = "user",
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Read bounded effective Group Policy summary; never refresh or mutate policy."""
    plan = build_group_policy_plan(scope=scope)
    normalized_scope = str(scope).strip().lower()
    authority.require(
        GROUP_POLICY_TOOL_ID,
        resource_kind="group_policy",
        resource_ref=f"local:gpresult:{normalized_scope}",
        effect="read",
    )
    completed = subprocess.run(
        plan,
        capture_output=True,
        text=True,
        timeout=max(2.0, min(float(timeout), 30.0)),
        check=False,
        shell=False,
    )
    bounded = bound_process_output(completed.stdout, completed.stderr)
    return {
        "tool_id": GROUP_POLICY_TOOL_ID,
        "scope": normalized_scope,
        "returncode": completed.returncode,
        "interpretation": "evidence_only",
        **bounded,
    }


__all__ = [
    "GROUP_POLICY_TOOL_ID",
    "GROUP_POLICY_TOOL_METADATA",
    "build_group_policy_plan",
    "group_policy_micro_tool_registry",
    "read_group_policy_result",
]
