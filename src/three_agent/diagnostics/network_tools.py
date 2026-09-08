from __future__ import annotations

import ipaddress
import math
import platform
import subprocess
import time
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output

NETWORK_REACHABILITY_TOOL_ID = "network.reachability.internal"

NETWORK_TOOL_METADATA = (
    ToolMetadata(
        id=NETWORK_REACHABILITY_TOOL_ID,
        platform="any",
        category="network",
        keywords=(
            "reachability",
            "ping",
            "host unreachable",
            "device unreachable",
            "server unreachable",
            "khong ket noi duoc",
            "khong ping duoc",
            "到達できない",
            "pingできない",
        ),
        cost="C1",
        risk="sensitive_read",
        requires_admin=False,
        network_access="internal_only",
        sensitive_outputs=True,
        effect="network_read",
    ).validate(),
)


def network_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(NETWORK_TOOL_METADATA)


def is_internal_ip_literal(host: str) -> bool:
    """Accept only explicit non-public IP literals; never resolve hostnames here."""
    try:
        address = ipaddress.ip_address(str(host).strip())
    except ValueError:
        return False
    if address.is_loopback or address.is_link_local:
        return True
    if isinstance(address, ipaddress.IPv4Address):
        return any(
            address in network
            for network in (
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
            )
        )
    return address in ipaddress.ip_network("fc00::/7")


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported reachability platform: {value or 'unknown'}")


def build_internal_ping_plan(
    host: str,
    *,
    platform_name: str | None = None,
    count: int = 1,
    timeout_ms: int = 1000,
) -> tuple[str, ...]:
    target = str(host).strip()
    if not is_internal_ip_literal(target):
        raise ValueError("host must be an explicit internal/private IP literal")
    count = int(count)
    timeout_ms = int(timeout_ms)
    if not 1 <= count <= 4:
        raise ValueError("count must be within 1..4")
    if not 100 <= timeout_ms <= 5000:
        raise ValueError("timeout_ms must be within 100..5000")
    if _platform_key(platform_name) == "windows":
        return ("ping.exe", "-n", str(count), "-w", str(timeout_ms), target)
    timeout_seconds = max(1, int(math.ceil(timeout_ms / 1000.0)))
    return ("ping", "-n", "-c", str(count), "-W", str(timeout_seconds), target)


def probe_internal_reachability(
    host: str,
    *,
    authority: TaskCapabilityAuthority,
    count: int = 1,
    timeout_ms: int = 1000,
) -> dict[str, Any]:
    """Collect bounded ICMP evidence for one internal IP without diagnosing root cause."""
    target = str(host).strip()
    plan = build_internal_ping_plan(target, count=count, timeout_ms=timeout_ms)
    authority.require(
        NETWORK_REACHABILITY_TOOL_ID,
        resource_kind="network_endpoint",
        resource_ref=f"{target}:icmp",
        effect="network_read",
    )
    wall_timeout = min(25.0, max(2.0, (int(count) * int(timeout_ms) / 1000.0) + 2.0))
    started = time.monotonic()
    completed = subprocess.run(
        plan,
        capture_output=True,
        text=True,
        timeout=wall_timeout,
        check=False,
        shell=False,
    )
    bounded = bound_process_output(completed.stdout, completed.stderr)
    return {
        "tool_id": NETWORK_REACHABILITY_TOOL_ID,
        "target": target,
        "icmp_reply_observed": completed.returncode == 0,
        "returncode": completed.returncode,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
        "interpretation": "evidence_only",
        **bounded,
    }


__all__ = [
    "NETWORK_REACHABILITY_TOOL_ID",
    "NETWORK_TOOL_METADATA",
    "build_internal_ping_plan",
    "is_internal_ip_literal",
    "network_micro_tool_registry",
    "probe_internal_reachability",
]
