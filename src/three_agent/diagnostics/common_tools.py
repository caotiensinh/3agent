from __future__ import annotations

import ctypes
import os
import platform
import re
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

from ..capability_authority import TaskCapabilityAuthority
from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..tool_result_boundary import bound_process_output

_SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
_WINDOWS_SYSTEM_DRIVE_RE = re.compile(r"^[A-Za-z]:$")

_COMMON_TOOLS = (
    ToolMetadata(
        id="system.platform.identify",
        platform="any",
        category="system",
        keywords=("platform", "operating system", "os version", "windows version", "linux version", "he dieu hanh", "OS バージョン"),
        cost="C0",
        risk="read_only",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=False,
        effect="read",
    ),
    ToolMetadata(
        id="system.resource.snapshot",
        platform="any",
        category="performance",
        keywords=("slow", "cpu", "memory", "ram", "load", "performance", "may cham", "パソコン 遅い"),
        cost="C0",
        risk="read_only",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=False,
        effect="read",
    ),
    ToolMetadata(
        id="system.storage.capacity",
        platform="any",
        category="storage",
        keywords=("disk full", "storage full", "free space", "disk space", "het dung luong", "空き容量"),
        cost="C0",
        risk="read_only",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=False,
        effect="read",
    ),
    ToolMetadata(
        id="network.interface.snapshot",
        platform="any",
        category="network",
        keywords=("network adapter", "interface", "ethernet", "wifi adapter", "nic", "card mang", "ネットワークアダプター"),
        cost="C0",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ),
    ToolMetadata(
        id="network.ipconfig.snapshot",
        platform="any",
        category="network",
        keywords=("ip address", "ip config", "dhcp", "gateway", "169.254", "dia chi ip", "IP アドレス"),
        cost="C1",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ),
    ToolMetadata(
        id="network.route.snapshot",
        platform="any",
        category="network",
        keywords=("route", "routing table", "gateway", "vpn route", "duong di mang", "ルーティング"),
        cost="C1",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ),
    ToolMetadata(
        id="network.dns.snapshot",
        platform="any",
        category="network",
        keywords=("dns", "name resolution", "dns server", "resolve", "phan giai ten", "DNS"),
        cost="C1",
        risk="sensitive_read",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=True,
        effect="read",
    ),
    ToolMetadata(
        id="time.sync.status",
        platform="any",
        category="time",
        keywords=("time sync", "clock", "ntp", "kerberos time", "gio he thong", "時刻同期", "NTP"),
        cost="C1",
        risk="read_only",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=False,
        effect="read",
    ),
    ToolMetadata(
        id="service.status.read",
        platform="any",
        category="service",
        keywords=("service status", "service stopped", "daemon", "windows service", "dich vu", "サービス 状態"),
        cost="C1",
        risk="read_only",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=False,
        effect="read",
    ),
)
COMMON_TOOL_BY_ID = {tool.id: tool.validate() for tool in _COMMON_TOOLS}


def common_tool_metadata() -> tuple[ToolMetadata, ...]:
    return tuple(COMMON_TOOL_BY_ID[tool.id] for tool in _COMMON_TOOLS)


def common_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(common_tool_metadata())


def _require_authority(
    authority: TaskCapabilityAuthority,
    tool_id: str,
    *,
    resource_kind: str,
    resource_ref: str,
) -> None:
    tool = COMMON_TOOL_BY_ID[tool_id]
    authority.require(
        tool_id,
        resource_kind=resource_kind,
        resource_ref=resource_ref,
        effect=tool.effect,
    )


def _platform_key(platform_name: str | None = None) -> str:
    value = str(platform_name or platform.system()).strip().lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported local diagnostic platform: {value or 'unknown'}")


def _validate_service_name(service_name: str) -> str:
    value = str(service_name).strip()
    if not _SERVICE_NAME_RE.fullmatch(value):
        raise ValueError("service_name contains unsupported characters")
    return value


def build_common_read_plan(
    tool_id: str,
    *,
    platform_name: str | None = None,
    service_name: str | None = None,
) -> tuple[str, ...]:
    platform_key = _platform_key(platform_name)
    if tool_id == "network.ipconfig.snapshot":
        return ("ipconfig.exe", "/all") if platform_key == "windows" else ("ip", "-j", "address", "show")
    if tool_id == "network.route.snapshot":
        return ("route.exe", "print") if platform_key == "windows" else ("ip", "-j", "route", "show", "table", "all")
    if tool_id == "network.dns.snapshot":
        if platform_key == "windows":
            script = (
                "Get-DnsClientServerAddress -ErrorAction Stop | "
                "Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,ServerAddresses | "
                "ConvertTo-Json -Depth 4 -Compress"
            )
            return ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
        raise ValueError("Linux DNS snapshot is read directly from local resolver files")
    if tool_id == "time.sync.status":
        if platform_key == "windows":
            return ("w32tm.exe", "/query", "/status")
        return (
            "timedatectl",
            "show",
            "--no-pager",
            "--property=NTPSynchronized",
            "--property=NTP",
            "--property=Timezone",
        )
    if tool_id == "service.status.read":
        if service_name is None:
            raise ValueError("service_name is required")
        service = _validate_service_name(service_name)
        if platform_key == "windows":
            return ("sc.exe", "query", service)
        return (
            "systemctl",
            "show",
            service,
            "--no-pager",
            "--property=Id",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=UnitFileState",
        )
    raise ValueError(f"tool does not use a subprocess read plan: {tool_id}")


def _linux_memory_snapshot() -> dict[str, int | None]:
    values: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" not in line:
                continue
            key, raw = line.split(":", 1)
            parts = raw.strip().split()
            if not parts:
                continue
            try:
                amount = int(parts[0])
            except ValueError:
                continue
            if len(parts) > 1 and parts[1].lower() == "kb":
                amount *= 1024
            values[key] = amount
    except OSError:
        pass
    return {
        "memory_total_bytes": values.get("MemTotal"),
        "memory_available_bytes": values.get("MemAvailable"),
    }


def _windows_memory_snapshot() -> dict[str, int | None]:
    class MemoryStatusEx(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = MemoryStatusEx()
    status.dwLength = ctypes.sizeof(MemoryStatusEx)
    try:
        ok = bool(ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)))  # type: ignore[attr-defined]
    except Exception:
        ok = False
    if not ok:
        return {"memory_total_bytes": None, "memory_available_bytes": None}
    return {
        "memory_total_bytes": int(status.ullTotalPhys),
        "memory_available_bytes": int(status.ullAvailPhys),
    }


def _resource_snapshot() -> dict[str, Any]:
    platform_key = _platform_key()
    result: dict[str, Any] = {
        "cpu_count_logical": os.cpu_count(),
        "load_average_1m": None,
        "load_average_5m": None,
        "load_average_15m": None,
    }
    if hasattr(os, "getloadavg"):
        try:
            load1, load5, load15 = os.getloadavg()
            result.update(
                {
                    "load_average_1m": round(float(load1), 4),
                    "load_average_5m": round(float(load5), 4),
                    "load_average_15m": round(float(load15), 4),
                }
            )
        except OSError:
            pass
    result.update(_windows_memory_snapshot() if platform_key == "windows" else _linux_memory_snapshot())
    return result


def _default_storage_path() -> str:
    if platform.system().lower().startswith("win"):
        system_drive = str(os.environ.get("SystemDrive", "C:")).strip()
        if not _WINDOWS_SYSTEM_DRIVE_RE.fullmatch(system_drive):
            system_drive = "C:"
        return f"{system_drive}\\"
    return "/"


def _run_plan(plan: tuple[str, ...], *, timeout: float) -> dict[str, Any]:
    completed = subprocess.run(
        plan,
        capture_output=True,
        text=True,
        timeout=max(1.0, min(float(timeout), 30.0)),
        check=False,
        shell=False,
    )
    bounded = bound_process_output(completed.stdout, completed.stderr)
    return {"returncode": completed.returncode, **bounded}


def execute_common_read(
    tool_id: str,
    *,
    authority: TaskCapabilityAuthority,
    service_name: str | None = None,
    storage_path: str | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    if tool_id not in COMMON_TOOL_BY_ID:
        raise ValueError(f"unknown common diagnostic tool: {tool_id}")

    if tool_id == "system.platform.identify":
        _require_authority(authority, tool_id, resource_kind="system_inventory", resource_ref="local:platform")
        return {
            "tool_id": tool_id,
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python_version": platform.python_version(),
        }

    if tool_id == "system.resource.snapshot":
        _require_authority(authority, tool_id, resource_kind="performance_snapshot", resource_ref="local:resources")
        return {"tool_id": tool_id, **_resource_snapshot()}

    if tool_id == "system.storage.capacity":
        if storage_path is not None:
            raise ValueError("storage_path is not supported; default local system volume only")
        path = _default_storage_path()
        _require_authority(
            authority,
            tool_id,
            resource_kind="filesystem_capacity",
            resource_ref="local:storage:default",
        )
        usage = shutil.disk_usage(path)
        return {
            "tool_id": tool_id,
            "scope": "default_local_system_volume",
            "path": path,
            "total_bytes": int(usage.total),
            "used_bytes": int(usage.used),
            "free_bytes": int(usage.free),
        }

    if tool_id == "network.interface.snapshot":
        _require_authority(authority, tool_id, resource_kind="network_config", resource_ref="local:interfaces")
        interfaces = tuple(
            {"index": int(index), "name": str(name)}
            for index, name in socket.if_nameindex()
        )
        return {"tool_id": tool_id, "interfaces": interfaces}

    if tool_id == "network.dns.snapshot" and _platform_key() == "linux":
        _require_authority(authority, tool_id, resource_kind="network_config", resource_ref="local:dns")
        sources: list[dict[str, Any]] = []
        for path in (Path("/etc/resolv.conf"), Path("/run/systemd/resolve/resolv.conf")):
            if not path.exists():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                sources.append({"path": str(path), "error_type": type(exc).__name__})
                continue
            bounded = bound_process_output(text, "")
            sources.append({"path": str(path), **bounded})
        return {"tool_id": tool_id, "sources": tuple(sources)}

    if tool_id == "service.status.read":
        if service_name is None:
            raise ValueError("service_name is required")
        service = _validate_service_name(service_name)
        resource_ref = f"local:service:{service}"
        _require_authority(authority, tool_id, resource_kind="service", resource_ref=resource_ref)
        plan = build_common_read_plan(tool_id, service_name=service)
        return {"tool_id": tool_id, "service_name": service, **_run_plan(plan, timeout=timeout)}

    resource_refs = {
        "network.ipconfig.snapshot": ("network_config", "local:ipconfig"),
        "network.route.snapshot": ("network_config", "local:routes"),
        "network.dns.snapshot": ("network_config", "local:dns"),
        "time.sync.status": ("time_config", "local:time-sync"),
    }
    try:
        resource_kind, resource_ref = resource_refs[tool_id]
    except KeyError as exc:
        raise ValueError(f"unsupported common read execution: {tool_id}") from exc
    _require_authority(authority, tool_id, resource_kind=resource_kind, resource_ref=resource_ref)
    plan = build_common_read_plan(tool_id)
    return {"tool_id": tool_id, **_run_plan(plan, timeout=timeout)}


__all__ = [
    "COMMON_TOOL_BY_ID",
    "build_common_read_plan",
    "common_micro_tool_registry",
    "common_tool_metadata",
    "execute_common_read",
]
