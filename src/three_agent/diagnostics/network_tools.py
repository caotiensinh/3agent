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
NETWORK_QUALITY_TOOL_ID = "network.quality.internal"

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
            "server is unreachable",
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
    ToolMetadata(
        id=NETWORK_QUALITY_TOOL_ID,
        platform="any",
        category="network",
        keywords=(
            "network quality",
            "latency",
            "packet loss",
            "jitter",
            "choppy audio",
            "robotic audio",
            "call drops",
            "mang chap chon",
            "mang lag",
            "do tre mang",
            "パケットロス",
            "遅延",
            "音声 途切れる",
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


def _run_internal_ping(
    tool_id: str,
    host: str,
    *,
    authority: TaskCapabilityAuthority,
    count: int,
    timeout_ms: int,
    resource_suffix: str,
) -> dict[str, Any]:
    target = str(host).strip()
    plan = build_internal_ping_plan(target, count=count, timeout_ms=timeout_ms)
    authority.require(
        tool_id,
        resource_kind="network_endpoint",
        resource_ref=f"{target}:{resource_suffix}",
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
        "tool_id": tool_id,
        "target": target,
        "returncode": completed.returncode,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
        "interpretation": "evidence_only",
        **bounded,
    }


def probe_internal_reachability(
    host: str,
    *,
    authority: TaskCapabilityAuthority,
    count: int = 1,
    timeout_ms: int = 1000,
) -> dict[str, Any]:
    """Collect bounded ICMP evidence for one internal IP without diagnosing root cause."""
    result = _run_internal_ping(
        NETWORK_REACHABILITY_TOOL_ID,
        host,
        authority=authority,
        count=count,
        timeout_ms=timeout_ms,
        resource_suffix="icmp",
    )
    result["icmp_reply_observed"] = result["returncode"] == 0
    return result


def sample_internal_network_quality(
    host: str,
    *,
    authority: TaskCapabilityAuthority,
    count: int = 4,
    timeout_ms: int = 1000,
) -> dict[str, Any]:
    """Collect a tiny point-in-time ICMP sample from one internal IP.

    The raw bounded ping output may contain platform-localized latency/loss fields.
    This function deliberately does not parse those fields into a quality verdict,
    does not claim application-level jitter, and does not diagnose root cause.
    """
    result = _run_internal_ping(
        NETWORK_QUALITY_TOOL_ID,
        host,
        authority=authority,
        count=count,
        timeout_ms=timeout_ms,
        resource_suffix="icmp-quality",
    )
    result.update(
        {
            "probe_kind": "bounded_icmp_samples",
            "sample_count_requested": int(count),
            "per_sample_timeout_ms": int(timeout_ms),
            "probe_command_succeeded": result["returncode"] == 0,
            "quality_verdict": None,
        }
    )
    return result


__all__ = [
    "NETWORK_QUALITY_TOOL_ID",
    "NETWORK_REACHABILITY_TOOL_ID",
    "NETWORK_TOOL_METADATA",
    "build_internal_ping_plan",
    "is_internal_ip_literal",
    "network_micro_tool_registry",
    "probe_internal_reachability",
    "sample_internal_network_quality",
]
