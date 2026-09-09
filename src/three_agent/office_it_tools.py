from __future__ import annotations

import ipaddress
import platform
import socket
import subprocess
import time
import unicodedata
from dataclasses import asdict, dataclass
from typing import Any, Iterable

from .capability_authority import TaskCapabilityAuthority
from .tool_result_boundary import bound_process_output

OFFICE_IT_TOOL_REGISTRY_SCHEMA = "workspace-office-it-tool-registry/v1"
_COST_ORDER = {"C0": 0, "C1": 1, "C2": 2, "C3": 3, "C4": 4, "C5": 5}
_EVENT_CHANNELS = {
    "windows.event.system": "System",
    "windows.event.application": "Application",
    "windows.event.security": "Security",
}
_FIXED_PORTS = {
    "network.ssh.probe": 22,
    "network.rtsp.probe": 554,
    "network.smb.probe": 445,
    "network.printer.ipp_probe": 631,
    "network.printer.raw_probe": 9100,
}


@dataclass(frozen=True)
class OfficeITToolSpec:
    id: str
    platform: str
    category: str
    keywords: tuple[str, ...]
    cost: str
    risk: str
    requires_admin: bool
    network_access: str
    sensitive_outputs: bool
    effect: str
    fixed_port: int | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["schema_version"] = OFFICE_IT_TOOL_REGISTRY_SCHEMA
        return payload


_TOOL_SPECS = (
    OfficeITToolSpec(
        "windows.event.system",
        "windows",
        "event",
        ("event viewer", "system event", "reboot", "restart", "shutdown", "bsod", "kernel power", "mat nguon", "khoi dong lai"),
        "C1",
        "read_only",
        False,
        "none",
        False,
        "read",
    ),
    OfficeITToolSpec(
        "windows.event.application",
        "windows",
        "event",
        ("application event", "app crash", "application error", "wer", "phan mem loi", "ung dung loi"),
        "C1",
        "read_only",
        False,
        "none",
        False,
        "read",
    ),
    OfficeITToolSpec(
        "windows.event.security",
        "windows",
        "event",
        ("security event", "logon", "login", "authentication", "account", "audit", "dang nhap", "bao mat"),
        "C2",
        "read_only",
        True,
        "none",
        True,
        "read",
    ),
    OfficeITToolSpec(
        "windows.printer.queue",
        "windows",
        "printer",
        ("printer", "print queue", "print job", "spooler", "may in", "khong in", "hang doi in"),
        "C1",
        "read_only",
        False,
        "none",
        False,
        "read",
    ),
    OfficeITToolSpec(
        "network.ssh.probe",
        "any",
        "network",
        ("ssh", "port 22", "remote shell", "server ssh"),
        "C1",
        "read_only",
        False,
        "internal_only",
        False,
        "network_read",
        22,
    ),
    OfficeITToolSpec(
        "network.rtsp.probe",
        "any",
        "network",
        ("rtsp", "rtsp stream", "camera stream", "rtsp khong xem duoc", "rtsp unavailable", "rtsp 見られない"),
        "C1",
        "read_only",
        False,
        "internal_only",
        True,
        "network_read",
        554,
    ),
    OfficeITToolSpec(
        "network.smb.probe",
        "any",
        "network",
        ("smb", "file share", "shared folder", "port 445", "network share", "thu muc chia se"),
        "C1",
        "read_only",
        False,
        "internal_only",
        False,
        "network_read",
        445,
    ),
    OfficeITToolSpec(
        "network.printer.ipp_probe",
        "any",
        "printer",
        ("ipp", "port 631", "network printer", "printer", "may in mang", "khong in"),
        "C1",
        "read_only",
        False,
        "internal_only",
        False,
        "network_read",
        631,
    ),
    OfficeITToolSpec(
        "network.printer.raw_probe",
        "any",
        "printer",
        ("jetdirect", "raw printer", "port 9100", "network printer", "printer", "may in mang", "khong in"),
        "C1",
        "read_only",
        False,
        "internal_only",
        False,
        "network_read",
        9100,
    ),
)
TOOL_SPECS = {spec.id: spec for spec in _TOOL_SPECS}


def _normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", str(value).lower())
    return " ".join("".join(ch for ch in normalized if not unicodedata.combining(ch)).split())


def get_tool_spec(tool_id: str) -> OfficeITToolSpec:
    try:
        return TOOL_SPECS[str(tool_id)]
    except KeyError as exc:
        raise ValueError(f"unknown Office IT tool: {tool_id}") from exc


def select_tools(
    query: str,
    *,
    platform_name: str | None = None,
    max_tools: int = 4,
) -> tuple[OfficeITToolSpec, ...]:
    """Select the cheapest relevant micro-tools without expanding to a full workflow."""
    if max_tools < 1 or max_tools > len(TOOL_SPECS):
        raise ValueError("max_tools is out of bounds")
    text = _normalize_text(query)
    requested_platform = _normalize_text(platform_name or platform.system())
    scored: list[tuple[int, int, str, OfficeITToolSpec]] = []
    for spec in _TOOL_SPECS:
        if spec.platform != "any" and requested_platform and spec.platform not in requested_platform:
            continue
        score = sum(1 for keyword in spec.keywords if _normalize_text(keyword) in text)
        if score:
            scored.append((-score, _COST_ORDER[spec.cost], spec.id, spec))
    scored.sort(key=lambda item: (item[0], item[1], item[2]))
    return tuple(item[3] for item in scored[:max_tools])


def _bounded_event_args(hours: int, max_events: int) -> tuple[int, int]:
    hours = int(hours)
    max_events = int(max_events)
    if not 1 <= hours <= 168:
        raise ValueError("hours must be within 1..168")
    if not 1 <= max_events <= 1000:
        raise ValueError("max_events must be within 1..1000")
    return hours, max_events


def build_windows_event_plan(
    tool_id: str,
    *,
    hours: int = 24,
    max_events: int = 200,
) -> tuple[str, ...]:
    """Build a fixed-channel PowerShell argv plan; no arbitrary script input is accepted."""
    try:
        channel = _EVENT_CHANNELS[tool_id]
    except KeyError as exc:
        raise ValueError(f"not a Windows event tool: {tool_id}") from exc
    hours, max_events = _bounded_event_args(hours, max_events)
    script = (
        f"Get-WinEvent -FilterHashtable @{{LogName='{channel}'; "
        f"StartTime=(Get-Date).AddHours(-{hours})}} -MaxEvents {max_events} "
        "-ErrorAction Stop | ForEach-Object { $_.ToXml() }"
    )
    return ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)


def build_windows_printer_queue_plan() -> tuple[str, ...]:
    script = (
        "Get-Printer -ErrorAction Stop | "
        "Select-Object Name,PrinterStatus,DriverName,PortName,Shared | "
        "ConvertTo-Json -Depth 3 -Compress"
    )
    return ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)


def is_internal_ip_literal(host: str) -> bool:
    """Permit only explicit local/private address literals; DNS and public targets are rejected."""
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


def _require_authority(
    authority: TaskCapabilityAuthority,
    tool_id: str,
    *,
    resource_kind: str,
    resource_ref: str,
) -> None:
    spec = get_tool_spec(tool_id)
    authority.require(
        tool_id,
        resource_kind=resource_kind,
        resource_ref=resource_ref,
        effect=spec.effect,
    )


def probe_tcp(
    tool_id: str,
    host: str,
    *,
    authority: TaskCapabilityAuthority,
    timeout: float = 1.5,
    max_banner_bytes: int = 256,
) -> dict[str, Any]:
    """Perform one bounded connect-only internal probe; SSH may passively read its server banner."""
    spec = get_tool_spec(tool_id)
    port = _FIXED_PORTS.get(tool_id)
    if port is None or spec.fixed_port != port:
        raise ValueError(f"not a fixed-port network probe: {tool_id}")
    if not is_internal_ip_literal(host):
        raise ValueError("host must be an internal/private IP literal")
    timeout = float(timeout)
    max_banner_bytes = int(max_banner_bytes)
    if not 0.1 <= timeout <= 5.0:
        raise ValueError("timeout must be within 0.1..5.0 seconds")
    if not 0 <= max_banner_bytes <= 1024:
        raise ValueError("max_banner_bytes must be within 0..1024")
    endpoint = f"{host}:{port}"
    _require_authority(authority, tool_id, resource_kind="network_endpoint", resource_ref=endpoint)
    started = time.monotonic()
    result: dict[str, Any] = {
        "tool_id": tool_id,
        "host": host,
        "port": port,
        "connected": False,
        "banner": None,
    }
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            result["connected"] = True
            if tool_id == "network.ssh.probe" and max_banner_bytes:
                sock.settimeout(min(timeout, 1.0))
                try:
                    banner = sock.recv(max_banner_bytes)
                    result["banner"] = banner.decode("utf-8", errors="replace").strip() or None
                except (TimeoutError, socket.timeout):
                    pass
    except OSError as exc:
        result["error_type"] = type(exc).__name__
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return result


def probe_rtsp_service(
    host: str,
    *,
    authority: TaskCapabilityAuthority,
    timeout_seconds: float = 2.0,
) -> dict[str, Any]:
    """Collect bounded RTSP service evidence from one explicit internal IP without credentials."""
    tool_id = "network.rtsp.probe"
    spec = get_tool_spec(tool_id)
    port = _FIXED_PORTS[tool_id]
    target = str(host).strip()
    if spec.fixed_port != port:
        raise ValueError("RTSP probe fixed-port metadata mismatch")
    if not is_internal_ip_literal(target):
        raise ValueError("host must be an internal/private IP literal")
    timeout = float(timeout_seconds)
    if not 0.1 <= timeout <= 5.0:
        raise ValueError("timeout_seconds must be within 0.1..5.0 seconds")

    endpoint = f"{target}:{port}"
    _require_authority(authority, tool_id, resource_kind="network_endpoint", resource_ref=endpoint)
    request = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: 3agent-diagnostic\r\n\r\n"
    started = time.monotonic()
    result: dict[str, Any] = {
        "tool_id": tool_id,
        "target": target,
        "port": port,
        "connected": False,
        "response_received": False,
        "rtsp_service_observed": False,
        "authentication_challenge_observed": False,
        "rtsp_status_line": None,
        "interpretation": "evidence_only",
    }
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            result["connected"] = True
            sock.sendall(request)
            try:
                response = sock.recv(4096)
            except (TimeoutError, socket.timeout):
                response = b""
            if response:
                result["response_received"] = True
                first_line = response.split(b"\r\n", 1)[0][:512].decode("ascii", errors="replace").strip()
                if first_line.upper().startswith("RTSP/"):
                    result["rtsp_service_observed"] = True
                    result["rtsp_status_line"] = first_line
                    parts = first_line.split()
                    if len(parts) >= 2 and parts[1] == "401":
                        result["authentication_challenge_observed"] = True
    except OSError as exc:
        result["error_type"] = type(exc).__name__
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return result


def execute_local_read(
    tool_id: str,
    *,
    authority: TaskCapabilityAuthority,
    hours: int = 24,
    max_events: int = 200,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Execute one bounded local Windows read-only collector through an authorized argv plan."""
    if platform.system().lower() != "windows":
        raise RuntimeError("Windows local Office IT tools require Windows")
    if tool_id in _EVENT_CHANNELS:
        plan = build_windows_event_plan(tool_id, hours=hours, max_events=max_events)
        resource_ref = f"windows:event:{_EVENT_CHANNELS[tool_id]}"
        resource_kind = "event_channel"
    elif tool_id == "windows.printer.queue":
        plan = build_windows_printer_queue_plan()
        resource_ref = "windows:printer:queue"
        resource_kind = "print_queue"
    else:
        raise ValueError(f"not a local Office IT read tool: {tool_id}")
    _require_authority(authority, tool_id, resource_kind=resource_kind, resource_ref=resource_ref)
    completed = subprocess.run(
        plan,
        capture_output=True,
        text=True,
        timeout=max(1.0, min(float(timeout), 30.0)),
        check=False,
        shell=False,
    )
    bounded_output = bound_process_output(completed.stdout, completed.stderr)
    return {
        "tool_id": tool_id,
        "returncode": completed.returncode,
        **bounded_output,
    }


def registry_metadata() -> tuple[dict[str, Any], ...]:
    return tuple(spec.to_dict() for spec in _TOOL_SPECS)


def tool_ids() -> tuple[str, ...]:
    return tuple(spec.id for spec in _TOOL_SPECS)


def iter_specs() -> Iterable[OfficeITToolSpec]:
    return iter(_TOOL_SPECS)
