from __future__ import annotations

import json
import platform
import subprocess
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_text_result

VPN_STATUS_TOOL_ID = "vpn.status.local"
VPN_STATUS_LIMIT = 32

VPN_TOOL_METADATA = (
    ToolMetadata(
        id=VPN_STATUS_TOOL_ID,
        platform="any",
        category="network",
        keywords=(
            "vpn status",
            "vpn connected",
            "vpn disconnected",
            "vpn tunnel",
            "remote access vpn",
            "vpn khong ket noi",
            "trang thai vpn",
            "VPN 状態",
            "VPN 接続",
            "VPN 切断",
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
    "$ErrorActionPreference='SilentlyContinue'; "
    "$profiles=@(); "
    "if (Get-Command Get-VpnConnection -ErrorAction SilentlyContinue) { "
    "$profiles += @(Get-VpnConnection | Select-Object -First 32 Name,ConnectionStatus,TunnelType,AllUserConnection); "
    "$profiles += @(Get-VpnConnection -AllUserConnection | Select-Object -First 32 Name,ConnectionStatus,TunnelType,AllUserConnection) }; "
    "$pattern='vpn|wireguard|tap|tun|anyconnect|globalprotect|fortinet|zscaler|openvpn'; "
    "$adapters=@(Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -match $pattern -or $_.InterfaceDescription -match $pattern } | "
    "Select-Object -First 32 Name,InterfaceDescription,Status,ifIndex); "
    "[pscustomobject]@{profiles=$profiles;adapters=$adapters} | ConvertTo-Json -Depth 5 -Compress"
)

_LINUX_TUNNEL_KINDS = frozenset(
    {"tun", "tap", "wireguard", "gre", "gretap", "ipip", "sit", "vti", "vti6", "xfrm", "erspan"}
)


def vpn_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(VPN_TOOL_METADATA)


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported vpn-status platform: {value or 'unknown'}")


def build_vpn_status_plan(*, platform_name: str | None = None) -> tuple[str, ...]:
    if _platform_key(platform_name) == "windows":
        return ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _WINDOWS_QUERY)
    return ("ip", "-j", "-d", "link", "show")


def _bounded_text(value: Any, *, max_chars: int = 256) -> str:
    return str(value or "").strip()[:max_chars]


def _windows_evidence(stdout: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    text = str(stdout or "").strip()
    if not text:
        return [], []
    try:
        payload = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return [], []
    if not isinstance(payload, dict):
        return [], []
    profiles: list[dict[str, Any]] = []
    raw_profiles = payload.get("profiles") or ()
    if isinstance(raw_profiles, dict):
        raw_profiles = (raw_profiles,)
    for item in raw_profiles:
        if not isinstance(item, dict):
            continue
        profiles.append({
            "name": _bounded_text(item.get("Name")),
            "connection_status": _bounded_text(item.get("ConnectionStatus")),
            "tunnel_type": _bounded_text(item.get("TunnelType")),
            "all_user_connection": bool(item.get("AllUserConnection", False)),
        })
        if len(profiles) >= VPN_STATUS_LIMIT:
            break
    adapters: list[dict[str, Any]] = []
    raw_adapters = payload.get("adapters") or ()
    if isinstance(raw_adapters, dict):
        raw_adapters = (raw_adapters,)
    for item in raw_adapters:
        if not isinstance(item, dict):
            continue
        try:
            if_index = int(item.get("ifIndex"))
        except (TypeError, ValueError):
            if_index = None
        adapters.append({
            "name": _bounded_text(item.get("Name")),
            "description": _bounded_text(item.get("InterfaceDescription")),
            "status": _bounded_text(item.get("Status")),
            "if_index": if_index,
        })
        if len(adapters) >= VPN_STATUS_LIMIT:
            break
    return profiles, adapters


def _linux_evidence(stdout: str) -> list[dict[str, Any]]:
    text = str(stdout or "").strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    if not isinstance(payload, list):
        return []
    evidence: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = _bounded_text(item.get("ifname"), max_chars=128)
        linkinfo = item.get("linkinfo")
        info_kind = ""
        if isinstance(linkinfo, dict):
            info_kind = _bounded_text(linkinfo.get("info_kind"), max_chars=64).lower()
        lower_name = name.lower()
        tunnel_like = info_kind in _LINUX_TUNNEL_KINDS or lower_name.startswith(("tun", "tap", "wg", "ppp"))
        if not tunnel_like:
            continue
        evidence.append({
            "interface": name,
            "operstate": _bounded_text(item.get("operstate"), max_chars=64),
            "link_type": _bounded_text(item.get("link_type"), max_chars=64),
            "info_kind": info_kind,
            "ifindex": item.get("ifindex") if isinstance(item.get("ifindex"), int) else None,
        })
        if len(evidence) >= VPN_STATUS_LIMIT:
            break
    return evidence


def read_local_vpn_status(*, authority: TaskCapabilityAuthority, platform_name: str | None = None, timeout: float = 8.0) -> dict[str, Any]:
    """Collect bounded local VPN/tunnel evidence without testing remote connectivity.

    Absence is not interpreted as "VPN not installed", "VPN down", or root cause.
    Third-party/browser/ZTNA clients may not expose a local tunnel visible here.
    """
    target_platform = _platform_key(platform_name)
    authority.require(VPN_STATUS_TOOL_ID, resource_kind="vpn_status", resource_ref="local:vpn:status", effect="read")
    completed = subprocess.run(
        build_vpn_status_plan(platform_name=target_platform),
        capture_output=True,
        text=True,
        timeout=max(1.0, min(float(timeout), 20.0)),
        check=False,
        shell=False,
    )
    stderr_result = bound_text_result(completed.stderr, max_bytes=8 * 1024)
    base: dict[str, Any] = {
        "tool_id": VPN_STATUS_TOOL_ID,
        "platform": target_platform,
        "scope": "local_vpn_tunnel_evidence",
        "returncode": completed.returncode,
        "collection_succeeded": completed.returncode == 0,
        "stderr": stderr_result.text,
        "stderr_boundary": stderr_result.metadata(),
        "remote_connectivity_tested": False,
        "vpn_health_claimed": False,
        "vpn_absence_claimed": False,
        "root_cause_claimed": False,
        "interpretation": "evidence_only",
    }
    if target_platform == "windows":
        profiles, adapters = _windows_evidence(completed.stdout)
        return {
            **base,
            "observation_semantics": "windows_builtin_profiles_and_tunnel_like_adapters",
            "profiles": profiles,
            "tunnel_like_adapters": adapters,
            "observed_evidence_count": len(profiles) + len(adapters),
        }
    interfaces = _linux_evidence(completed.stdout)
    return {
        **base,
        "observation_semantics": "linux_kernel_tunnel_like_interfaces",
        "tunnel_like_interfaces": interfaces,
        "observed_evidence_count": len(interfaces),
    }


__all__ = ["VPN_STATUS_LIMIT", "VPN_STATUS_TOOL_ID", "VPN_TOOL_METADATA", "build_vpn_status_plan", "read_local_vpn_status", "vpn_micro_tool_registry"]
