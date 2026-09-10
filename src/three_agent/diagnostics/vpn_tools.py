from __future__ import annotations

import json
import platform
import re
import subprocess
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_text_result

VPN_STATUS_TOOL_ID = "vpn.status.snapshot"
VPN_PROFILE_LIMIT = 32

VPN_STATUS_TOOL_METADATA = (
    ToolMetadata(
        id=VPN_STATUS_TOOL_ID,
        platform="any",
        category="vpn",
        keywords=(
            "vpn status",
            "vpn connection",
            "vpn connected",
            "remote access vpn",
            "vpn profile",
            "trang thai vpn",
            "ket noi vpn",
            "VPN 状態",
            "VPN 接続",
            "リモートアクセス VPN",
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
    "Get-VpnConnection -ErrorAction SilentlyContinue | "
    f"Select-Object -First {VPN_PROFILE_LIMIT} Name,ConnectionStatus,TunnelType,SplitTunneling | "
    "ConvertTo-Json -Depth 3 -Compress"
)
_LINUX_LINK_RE = re.compile(
    r"^\d+:\s+([^:@\s]+)(?:@[^:]+)?:\s+<([^>]*)>",
    re.IGNORECASE,
)
_LINUX_STATE_RE = re.compile(r"\bstate\s+(\S+)", re.IGNORECASE)
_LINUX_VPN_PREFIXES = ("tun", "tap", "wg", "ppp", "tailscale", "zt")


def vpn_status_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(VPN_STATUS_TOOL_METADATA)


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported vpn-status platform: {value or 'unknown'}")


def build_vpn_status_plan(*, platform_name: str | None = None) -> tuple[str, ...]:
    if _platform_key(platform_name) == "windows":
        return (
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            _WINDOWS_QUERY,
        )
    return ("ip", "-details", "link", "show")


def _bounded_text(value: Any, *, limit: int = 128) -> str:
    return str(value or "").strip()[:limit]


def _parse_windows_profiles(stdout: str) -> list[dict[str, Any]]:
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
        name = _bounded_text(item.get("Name"))
        if not name:
            continue
        rows.append(
            {
                "profile_name": name,
                "connection_status": _bounded_text(item.get("ConnectionStatus"), limit=64),
                "tunnel_type": _bounded_text(item.get("TunnelType"), limit=64),
                "split_tunneling": bool(item.get("SplitTunneling", False)),
            }
        )
        if len(rows) >= VPN_PROFILE_LIMIT:
            break
    return rows


def _looks_like_vpn_interface(name: str) -> bool:
    normalized = str(name or "").strip().lower()
    return any(normalized.startswith(prefix) for prefix in _LINUX_VPN_PREFIXES)


def _parse_linux_interfaces(stdout: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw_line in str(stdout or "").splitlines():
        line = raw_line.strip()
        match = _LINUX_LINK_RE.match(line)
        if match is None:
            continue
        name, flags = match.groups()
        if not _looks_like_vpn_interface(name):
            continue
        state_match = _LINUX_STATE_RE.search(line)
        state = state_match.group(1) if state_match is not None else ""
        flag_set = {item.strip().upper() for item in flags.split(",") if item.strip()}
        rows.append(
            {
                "interface_name": _bounded_text(name),
                "admin_up_observed": "UP" in flag_set,
                "oper_state": _bounded_text(state, limit=32).lower(),
                "classification": "vpn_candidate_by_interface_name",
            }
        )
        if len(rows) >= VPN_PROFILE_LIMIT:
            break
    return rows


def _unavailable_result(*, target_platform: str) -> dict[str, Any]:
    return {
        "tool_id": VPN_STATUS_TOOL_ID,
        "platform": target_platform,
        "scope": "local_vpn_status_evidence",
        "requested_limit": VPN_PROFILE_LIMIT,
        "observed_count": 0,
        "observations": [],
        "collector_available": False,
        "collection_succeeded": False,
        "returncode": None,
        "stderr": "",
        "stderr_boundary": bound_text_result("", max_bytes=8 * 1024).metadata(),
        "observation_semantics": "collector_unavailable",
        "vpn_health_claimed": False,
        "connectivity_claimed": False,
        "root_cause_claimed": False,
        "interpretation": "evidence_only",
    }


def read_vpn_status(
    *,
    authority: TaskCapabilityAuthority,
    platform_name: str | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Collect bounded local OS evidence related to VPN state without network access.

    Windows reports locally configured current-user VPN profile state. Linux reports
    only tunnel-like local interfaces visible to `ip link`. Missing rows never prove
    that VPN is unconfigured, disconnected, unavailable, or the root cause of a user
    complaint. No credentials, tokens, routes, DNS data, packet contents, remote hosts,
    or public-network probes are collected. A missing local collector is returned as
    structured evidence and is never interpreted as VPN failure.
    """
    target_platform = _platform_key(platform_name)
    authority.require(
        VPN_STATUS_TOOL_ID,
        resource_kind="vpn_status",
        resource_ref="local:vpn:status",
        effect="read",
    )
    try:
        completed = subprocess.run(
            build_vpn_status_plan(platform_name=target_platform),
            capture_output=True,
            text=True,
            timeout=max(1.0, min(float(timeout), 20.0)),
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        return _unavailable_result(target_platform=target_platform)

    if target_platform == "windows":
        observations = _parse_windows_profiles(completed.stdout)
        semantics = "current_user_vpn_profiles_only"
    else:
        observations = _parse_linux_interfaces(completed.stdout)
        semantics = "tunnel_candidate_interfaces_only"
    stderr = bound_text_result(completed.stderr, max_bytes=8 * 1024)
    return {
        "tool_id": VPN_STATUS_TOOL_ID,
        "platform": target_platform,
        "scope": "local_vpn_status_evidence",
        "requested_limit": VPN_PROFILE_LIMIT,
        "observed_count": len(observations),
        "observations": observations,
        "collector_available": True,
        "collection_succeeded": completed.returncode == 0,
        "returncode": completed.returncode,
        "stderr": stderr.text,
        "stderr_boundary": stderr.metadata(),
        "observation_semantics": semantics,
        "vpn_health_claimed": False,
        "connectivity_claimed": False,
        "root_cause_claimed": False,
        "interpretation": "evidence_only",
    }


__all__ = [
    "VPN_PROFILE_LIMIT",
    "VPN_STATUS_TOOL_ID",
    "VPN_STATUS_TOOL_METADATA",
    "build_vpn_status_plan",
    "read_vpn_status",
    "vpn_status_micro_tool_registry",
]
