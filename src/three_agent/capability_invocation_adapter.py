from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .capability_authority import (
    TaskCapabilityAuthority,
    _EXACT_RESOURCE_POLICIES,
    _GROUP_POLICY_REFS,
    _NETWORK_RESOURCE_SUFFIXES,
    _SERVICE_RESOURCE_RE,
    _is_internal_ip_literal,
)
from .capability_registry_snapshot import snapshot_micro_tool_registry
from .diagnostics.audio_tools import AUDIO_DEVICES_TOOL_ID, read_audio_devices
from .diagnostics.backup_status_tools import BACKUP_STATUS_TOOL_ID, read_backup_local_state
from .diagnostics.camera_device_tools import CAMERA_DEVICES_TOOL_ID, read_camera_devices
from .diagnostics.cloud_files_tools import CLOUD_FILES_STATUS_TOOL_ID, read_cloud_files_client_state
from .diagnostics.common_tools import COMMON_TOOL_BY_ID, execute_common_read
from .diagnostics.display_tools import DISPLAY_TOOL_ID, read_display_snapshot
from .diagnostics.dock_tools import DOCK_TOOL_ID, read_dock_snapshot
from .diagnostics.driver_inventory_tools import DRIVER_INVENTORY_TOOL_ID, read_driver_inventory
from .diagnostics.identity_account_state_tools import (
    IDENTITY_ACCOUNT_STATE_TOOL_ID,
    read_identity_account_state,
)
from .diagnostics.identity_tools import IDENTITY_SESSION_TOOL_ID, read_identity_session
from .diagnostics.mail_exchange_tools import MAIL_EXCHANGE_STATUS_TOOL_ID, read_mail_exchange_client_state
from .diagnostics.meeting_client_tools import MEETING_CLIENT_TOOL_ID, read_running_meeting_clients
from .diagnostics.network_tools import (
    NETWORK_QUALITY_TOOL_ID,
    NETWORK_REACHABILITY_TOOL_ID,
    probe_internal_reachability,
    sample_internal_network_quality,
)
from .diagnostics.print_driver_tools import PRINT_DRIVER_TOOL_ID, read_print_drivers
from .diagnostics.process_tools import PROCESS_TOP_TOOL_ID, read_top_processes
from .diagnostics.runtime_registry import runtime_micro_tool_registry
from .diagnostics.storage_io_tools import STORAGE_IO_TOOL_ID, read_storage_io
from .diagnostics.usb_tools import USB_DEVICES_TOOL_ID, read_usb_devices
from .diagnostics.voip_tools import VOIP_CLIENT_STATE_TOOL_ID, read_voip_client_state
from .diagnostics.vpn_tools import VPN_STATUS_TOOL_ID, read_vpn_status
from .diagnostics.windows_boot_tools import WINDOWS_BOOT_TOOL_ID, read_windows_boot
from .diagnostics.windows_policy_tools import GROUP_POLICY_TOOL_ID, read_group_policy_result
from .diagnostics.windows_update_tools import WINDOWS_UPDATE_TOOL_ID, read_windows_update_history
from .invocation_decision_receipt import InvocationDecisionReceipt, receipt_from_capability_decision
from .office_it_tools import execute_local_read, probe_rtsp_service, probe_tcp
from .tool_result_boundary import BoundedTextResult, bound_text_result

CAPABILITY_INVOCATION_REQUEST_SCHEMA = "workspace-capability-invocation-request/v1"
CAPABILITY_INVOCATION_RESULT_SCHEMA = "workspace-capability-invocation-result/v1"

_TOOL_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PARAMETER_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
_EVENT_TOOLS = frozenset(
    {
        "windows.event.system",
        "windows.event.application",
        "windows.event.security",
    }
)
_RTSP_SERVICE_PROBE = "network.rtsp.probe"
_FIXED_PORT_PROBES = frozenset(
    {
        "network.ssh.probe",
        "network.smb.probe",
        "network.printer.ipp_probe",
        "network.printer.raw_probe",
    }
)
_COMMON_TOOL_IDS = frozenset(COMMON_TOOL_BY_ID)
_WAVE1_REVIEWED_HANDLER_IDS = frozenset(
    {
        BACKUP_STATUS_TOOL_ID,
        CLOUD_FILES_STATUS_TOOL_ID,
        IDENTITY_ACCOUNT_STATE_TOOL_ID,
        MAIL_EXCHANGE_STATUS_TOOL_ID,
        VOIP_CLIENT_STATE_TOOL_ID,
    }
)
_TIMEOUT_ONLY_TOOLS = frozenset(
    {
        IDENTITY_SESSION_TOOL_ID,
        AUDIO_DEVICES_TOOL_ID,
        MEETING_CLIENT_TOOL_ID,
        PROCESS_TOP_TOOL_ID,
        USB_DEVICES_TOOL_ID,
        DISPLAY_TOOL_ID,
        DOCK_TOOL_ID,
        DRIVER_INVENTORY_TOOL_ID,
        CAMERA_DEVICES_TOOL_ID,
        STORAGE_IO_TOOL_ID,
        PRINT_DRIVER_TOOL_ID,
        WINDOWS_BOOT_TOOL_ID,
        WINDOWS_UPDATE_TOOL_ID,
        VPN_STATUS_TOOL_ID,
    }
)
_FORBIDDEN_PARAMETER_NAMES = frozenset(
    {
        "argv",
        "callable",
        "command",
        "executable",
        "handler",
        "module",
        "path",
        "script",
        "shell",
    }
)


class CapabilityInvocationAdapterError(RuntimeError):
    """A requested invocation cannot cross the reviewed runtime invocation boundary."""


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CapabilityInvocationAdapterError("INVOCATION_REQUEST_NOT_CANONICAL_JSON") from exc


def _require_sha256(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise CapabilityInvocationAdapterError(f"INVALID_{field.upper()}")
    return value


def _require_tool_id(value: str) -> str:
    if not isinstance(value, str) or not _TOOL_ID_RE.fullmatch(value):
        raise CapabilityInvocationAdapterError("INVALID_TOOL_ID")
    return value


@dataclass(frozen=True)
class CapabilityInvocationRequest:
    task_id: str
    tool_id: str
    snapshot_fingerprint: str
    descriptor_fingerprint: str
    parameters: tuple[tuple[str, object], ...] = ()
    schema_version: str = CAPABILITY_INVOCATION_REQUEST_SCHEMA

    @classmethod
    def create(
        cls,
        *,
        task_id: str,
        tool_id: str,
        snapshot_fingerprint: str,
        descriptor_fingerprint: str,
        parameters: Mapping[str, object] | None = None,
    ) -> "CapabilityInvocationRequest":
        if parameters is None:
            items: tuple[tuple[str, object], ...] = ()
        elif not isinstance(parameters, Mapping):
            raise CapabilityInvocationAdapterError("INVOCATION_PARAMETERS_MUST_BE_MAPPING")
        else:
            items = tuple(sorted((str(key), value) for key, value in parameters.items()))
        return cls(
            task_id=str(task_id),
            tool_id=str(tool_id),
            snapshot_fingerprint=str(snapshot_fingerprint),
            descriptor_fingerprint=str(descriptor_fingerprint),
            parameters=items,
        ).validate()

    def validate(self) -> "CapabilityInvocationRequest":
        if self.schema_version != CAPABILITY_INVOCATION_REQUEST_SCHEMA:
            raise CapabilityInvocationAdapterError("INVOCATION_REQUEST_SCHEMA_MISMATCH")
        if not isinstance(self.task_id, str) or not self.task_id or self.task_id != self.task_id.strip():
            raise CapabilityInvocationAdapterError("INVALID_TASK_ID")
        if len(self.task_id) > 128 or "://" in self.task_id or any(ch.isspace() for ch in self.task_id):
            raise CapabilityInvocationAdapterError("INVALID_TASK_ID")
        _require_tool_id(self.tool_id)
        _require_sha256(self.snapshot_fingerprint, field="snapshot_fingerprint")
        _require_sha256(self.descriptor_fingerprint, field="descriptor_fingerprint")
        if type(self.parameters) is not tuple:
            raise CapabilityInvocationAdapterError("INVOCATION_PARAMETERS_NOT_CANONICAL")
        names: list[str] = []
        for item in self.parameters:
            if type(item) is not tuple or len(item) != 2:
                raise CapabilityInvocationAdapterError("INVOCATION_PARAMETERS_NOT_CANONICAL")
            name, value = item
            if not isinstance(name, str) or not _PARAMETER_NAME_RE.fullmatch(name):
                raise CapabilityInvocationAdapterError("INVALID_INVOCATION_PARAMETER_NAME")
            if name in _FORBIDDEN_PARAMETER_NAMES:
                raise CapabilityInvocationAdapterError("ARBITRARY_EXECUTION_PARAMETER_FORBIDDEN")
            if callable(value):
                raise CapabilityInvocationAdapterError("CALLABLE_INVOCATION_PARAMETER_FORBIDDEN")
            names.append(name)
        if names != sorted(names) or len(names) != len(set(names)):
            raise CapabilityInvocationAdapterError("INVOCATION_PARAMETERS_NOT_CANONICAL")
        _canonical_json(self.canonical_dict(include_schema=False))
        return self

    def parameter_dict(self) -> dict[str, object]:
        self.validate()
        return dict(self.parameters)

    def canonical_dict(self, *, include_schema: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "task_id": self.task_id,
            "tool_id": self.tool_id,
            "snapshot_fingerprint": self.snapshot_fingerprint,
            "descriptor_fingerprint": self.descriptor_fingerprint,
            "parameters": {key: value for key, value in self.parameters},
        }
        if include_schema:
            payload["schema_version"] = self.schema_version
        return payload

    @property
    def fingerprint(self) -> str:
        return _sha256_text(_canonical_json(self.canonical_dict()))


@dataclass(frozen=True)
class CapabilityInvocationResult:
    tool_id: str
    descriptor_fingerprint: str
    snapshot_fingerprint: str
    decision_receipt: InvocationDecisionReceipt
    bounded_payload: BoundedTextResult
    schema_version: str = CAPABILITY_INVOCATION_RESULT_SCHEMA

    def canonical_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "tool_id": self.tool_id,
            "descriptor_fingerprint": self.descriptor_fingerprint,
            "snapshot_fingerprint": self.snapshot_fingerprint,
            "decision_receipt": self.decision_receipt.canonical_dict(),
            "decision_receipt_fingerprint": self.decision_receipt.fingerprint,
            "payload_text": self.bounded_payload.text,
            "payload_boundary": self.bounded_payload.metadata(),
            "payload_complete": not self.bounded_payload.truncated,
        }


def reviewed_runtime_handler_ids() -> tuple[str, ...]:
    """Return the closed source-reviewed handler coverage for the canonical runtime registry."""
    ids = (
        set(_EVENT_TOOLS)
        | {"windows.printer.queue", _RTSP_SERVICE_PROBE}
        | set(_FIXED_PORT_PROBES)
        | set(_COMMON_TOOL_IDS)
        | {NETWORK_REACHABILITY_TOOL_ID, NETWORK_QUALITY_TOOL_ID, GROUP_POLICY_TOOL_ID}
        | set(_TIMEOUT_ONLY_TOOLS)
    )
    return tuple(sorted(ids))


def _is_reviewed_runtime_handler(tool_id: str) -> bool:
    return tool_id in reviewed_runtime_handler_ids() or tool_id in _WAVE1_REVIEWED_HANDLER_IDS


def current_runtime_invocation_identity(tool_id: str) -> tuple[str, str]:
    """Return current immutable snapshot/descriptor fingerprints for one reviewed runtime tool."""
    registry = runtime_micro_tool_registry()
    tool = registry.get(_require_tool_id(tool_id))
    if not tool.implemented:
        raise CapabilityInvocationAdapterError("TOOL_NOT_IMPLEMENTED")
    if not _is_reviewed_runtime_handler(tool.id):
        raise CapabilityInvocationAdapterError("UNREVIEWED_RUNTIME_HANDLER")
    snapshot = snapshot_micro_tool_registry(registry)
    descriptor = next((item for item in snapshot.descriptors if item.id == tool.id), None)
    if descriptor is None:
        raise CapabilityInvocationAdapterError("TOOL_DESCRIPTOR_MISSING")
    return snapshot.fingerprint, descriptor.fingerprint


def _allowed_parameter_names(tool_id: str) -> frozenset[str]:
    if tool_id in _EVENT_TOOLS:
        return frozenset({"hours", "max_events", "timeout"})
    if tool_id == "windows.printer.queue":
        return frozenset({"timeout"})
    if tool_id == _RTSP_SERVICE_PROBE:
        return frozenset({"host", "timeout"})
    if tool_id in _FIXED_PORT_PROBES:
        return frozenset({"host", "timeout", "max_banner_bytes"})
    if tool_id in {
        "system.platform.identify",
        "system.resource.snapshot",
        "system.storage.capacity",
        "network.interface.snapshot",
    }:
        return frozenset()
    if tool_id in {
        "network.ipconfig.snapshot",
        "network.route.snapshot",
        "network.dns.snapshot",
        "time.sync.status",
    }:
        return frozenset({"timeout"})
    if tool_id == "service.status.read":
        return frozenset({"service_name", "timeout"})
    if tool_id in {NETWORK_REACHABILITY_TOOL_ID, NETWORK_QUALITY_TOOL_ID}:
        return frozenset({"host", "count", "timeout_ms"})
    if tool_id == GROUP_POLICY_TOOL_ID:
        return frozenset({"scope", "timeout"})
    if tool_id in _TIMEOUT_ONLY_TOOLS or tool_id in _WAVE1_REVIEWED_HANDLER_IDS:
        return frozenset({"timeout"})
    raise CapabilityInvocationAdapterError("UNREVIEWED_RUNTIME_HANDLER")


def _bounded_int(value: object, *, field: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise CapabilityInvocationAdapterError(f"INVALID_{field.upper()}")
    return value


def _bounded_float(value: object, *, field: str, low: float, high: float) -> float:
    if type(value) not in {int, float}:
        raise CapabilityInvocationAdapterError(f"INVALID_{field.upper()}")
    number = float(value)
    if not low <= number <= high:
        raise CapabilityInvocationAdapterError(f"INVALID_{field.upper()}")
    return number


def _normalized_parameters(tool_id: str, raw: Mapping[str, object]) -> dict[str, object]:
    allowed = _allowed_parameter_names(tool_id)
    unknown = set(raw) - allowed
    if unknown:
        raise CapabilityInvocationAdapterError(
            "UNSUPPORTED_INVOCATION_PARAMETERS:" + ",".join(sorted(unknown))
        )
    params: dict[str, object] = {}

    if "timeout" in raw:
        timeout_high = 5.0 if tool_id in _FIXED_PORT_PROBES or tool_id == _RTSP_SERVICE_PROBE else 30.0
        params["timeout"] = _bounded_float(raw["timeout"], field="timeout", low=0.1, high=timeout_high)
    if "hours" in raw:
        params["hours"] = _bounded_int(raw["hours"], field="hours", low=1, high=168)
    if "max_events" in raw:
        params["max_events"] = _bounded_int(raw["max_events"], field="max_events", low=1, high=1000)
    if "max_banner_bytes" in raw:
        params["max_banner_bytes"] = _bounded_int(
            raw["max_banner_bytes"], field="max_banner_bytes", low=0, high=1024
        )
    if "count" in raw:
        params["count"] = _bounded_int(raw["count"], field="count", low=1, high=4)
    if "timeout_ms" in raw:
        params["timeout_ms"] = _bounded_int(raw["timeout_ms"], field="timeout_ms", low=100, high=5000)

    if tool_id in _FIXED_PORT_PROBES or tool_id == _RTSP_SERVICE_PROBE or tool_id in {
        NETWORK_REACHABILITY_TOOL_ID,
        NETWORK_QUALITY_TOOL_ID,
    }:
        host = raw.get("host")
        if not isinstance(host, str) or not _is_internal_ip_literal(host.strip()):
            raise CapabilityInvocationAdapterError("INTERNAL_IP_LITERAL_REQUIRED")
        params["host"] = host.strip()

    if tool_id == "service.status.read":
        service_name = raw.get("service_name")
        if not isinstance(service_name, str):
            raise CapabilityInvocationAdapterError("SERVICE_NAME_REQUIRED")
        service_name = service_name.strip()
        if not _SERVICE_NAME_RE.fullmatch(service_name):
            raise CapabilityInvocationAdapterError("INVALID_SERVICE_NAME")
        params["service_name"] = service_name

    if tool_id == GROUP_POLICY_TOOL_ID:
        scope = raw.get("scope", "user")
        if not isinstance(scope, str):
            raise CapabilityInvocationAdapterError("INVALID_GROUP_POLICY_SCOPE")
        scope = scope.strip().lower()
        if f"local:gpresult:{scope}" not in _GROUP_POLICY_REFS:
            raise CapabilityInvocationAdapterError("INVALID_GROUP_POLICY_SCOPE")
        params["scope"] = scope

    return params


def _reviewed_resource_target(tool_id: str, parameters: Mapping[str, object]) -> tuple[str, str]:
    # These objects are imported from capability_authority instead of duplicated here,
    # so resource admission remains one source-reviewed policy surface.
    exact = _EXACT_RESOURCE_POLICIES.get(tool_id)
    if exact is not None:
        return exact
    if tool_id == "service.status.read":
        service_name = str(parameters["service_name"])
        resource_ref = f"local:service:{service_name}"
        if not _SERVICE_RESOURCE_RE.fullmatch(resource_ref):
            raise CapabilityInvocationAdapterError("INVALID_SERVICE_RESOURCE")
        return "service", resource_ref
    if tool_id == GROUP_POLICY_TOOL_ID:
        resource_ref = f"local:gpresult:{parameters.get('scope', 'user')}"
        if resource_ref not in _GROUP_POLICY_REFS:
            raise CapabilityInvocationAdapterError("INVALID_GROUP_POLICY_RESOURCE")
        return "group_policy", resource_ref
    suffix = _NETWORK_RESOURCE_SUFFIXES.get(tool_id)
    if suffix is not None:
        host = str(parameters["host"])
        if not _is_internal_ip_literal(host):
            raise CapabilityInvocationAdapterError("INTERNAL_IP_LITERAL_REQUIRED")
        return "network_endpoint", f"{host}{suffix}"
    raise CapabilityInvocationAdapterError("UNREVIEWED_RUNTIME_RESOURCE_POLICY")


def _invoke_reviewed_handler(
    tool_id: str,
    *,
    authority: TaskCapabilityAuthority,
    parameters: Mapping[str, object],
) -> dict[str, Any]:
    kwargs = dict(parameters)

    if tool_id in _EVENT_TOOLS or tool_id == "windows.printer.queue":
        return execute_local_read(tool_id, authority=authority, **kwargs)
    if tool_id == _RTSP_SERVICE_PROBE:
        host = str(kwargs.pop("host"))
        timeout = kwargs.pop("timeout", None)
        if timeout is None:
            return probe_rtsp_service(host, authority=authority)
        return probe_rtsp_service(host, authority=authority, timeout_seconds=float(timeout))
    if tool_id in _FIXED_PORT_PROBES:
        host = str(kwargs.pop("host"))
        return probe_tcp(tool_id, host, authority=authority, **kwargs)
    if tool_id in _COMMON_TOOL_IDS:
        return execute_common_read(tool_id, authority=authority, **kwargs)
    if tool_id == NETWORK_REACHABILITY_TOOL_ID:
        host = str(kwargs.pop("host"))
        return probe_internal_reachability(host, authority=authority, **kwargs)
    if tool_id == NETWORK_QUALITY_TOOL_ID:
        host = str(kwargs.pop("host"))
        return sample_internal_network_quality(host, authority=authority, **kwargs)
    if tool_id == GROUP_POLICY_TOOL_ID:
        return read_group_policy_result(authority=authority, **kwargs)
    if tool_id == IDENTITY_SESSION_TOOL_ID:
        return read_identity_session(authority=authority, **kwargs)
    if tool_id == AUDIO_DEVICES_TOOL_ID:
        return read_audio_devices(authority=authority, **kwargs)
    if tool_id == MEETING_CLIENT_TOOL_ID:
        return read_running_meeting_clients(authority=authority, **kwargs)
    if tool_id == PROCESS_TOP_TOOL_ID:
        return read_top_processes(authority=authority, **kwargs)
    if tool_id == USB_DEVICES_TOOL_ID:
        return read_usb_devices(authority=authority, **kwargs)
    if tool_id == DISPLAY_TOOL_ID:
        return read_display_snapshot(authority=authority, **kwargs)
    if tool_id == DOCK_TOOL_ID:
        return read_dock_snapshot(authority=authority, **kwargs)
    if tool_id == DRIVER_INVENTORY_TOOL_ID:
        return read_driver_inventory(authority=authority, **kwargs)
    if tool_id == CAMERA_DEVICES_TOOL_ID:
        return read_camera_devices(authority=authority, **kwargs)
    if tool_id == STORAGE_IO_TOOL_ID:
        return read_storage_io(authority=authority, **kwargs)
    if tool_id == PRINT_DRIVER_TOOL_ID:
        return read_print_drivers(authority=authority, **kwargs)
    if tool_id == WINDOWS_BOOT_TOOL_ID:
        return read_windows_boot(authority=authority, **kwargs)
    if tool_id == WINDOWS_UPDATE_TOOL_ID:
        return read_windows_update_history(authority=authority, **kwargs)
    if tool_id == VPN_STATUS_TOOL_ID:
        return read_vpn_status(authority=authority, **kwargs)
    if tool_id == CLOUD_FILES_STATUS_TOOL_ID:
        return read_cloud_files_client_state(authority=authority, **kwargs)
    if tool_id == MAIL_EXCHANGE_STATUS_TOOL_ID:
        return read_mail_exchange_client_state(authority=authority, **kwargs)
    if tool_id == VOIP_CLIENT_STATE_TOOL_ID:
        return read_voip_client_state(authority=authority, **kwargs)
    if tool_id == IDENTITY_ACCOUNT_STATE_TOOL_ID:
        return read_identity_account_state(authority=authority, **kwargs)
    if tool_id == BACKUP_STATUS_TOOL_ID:
        return read_backup_local_state(authority=authority, **kwargs)
    raise CapabilityInvocationAdapterError("UNREVIEWED_RUNTIME_HANDLER")


def invoke_runtime_tool(
    request: CapabilityInvocationRequest,
    *,
    authority: TaskCapabilityAuthority,
) -> CapabilityInvocationResult:
    """Invoke one canonical runtime tool through reviewed identity, authority and result boundaries.

    The caller supplies identity fingerprints and bounded data parameters only. No
    callable, module, executable, argv, script, shell or path is accepted as an
    invocation surface. Handler choice remains source-reviewed in this module.
    """
    if not isinstance(request, CapabilityInvocationRequest):
        raise CapabilityInvocationAdapterError("INVALID_INVOCATION_REQUEST")
    request.validate()
    if not isinstance(authority, TaskCapabilityAuthority):
        raise CapabilityInvocationAdapterError("TASK_CAPABILITY_AUTHORITY_REQUIRED")

    registry = runtime_micro_tool_registry()
    try:
        tool = registry.get(request.tool_id)
    except Exception as exc:
        raise CapabilityInvocationAdapterError("UNKNOWN_RUNTIME_TOOL_ID") from exc
    if not tool.implemented:
        raise CapabilityInvocationAdapterError("TOOL_NOT_IMPLEMENTED")
    if not _is_reviewed_runtime_handler(tool.id):
        raise CapabilityInvocationAdapterError("UNREVIEWED_RUNTIME_HANDLER")

    snapshot = snapshot_micro_tool_registry(registry)
    descriptor = next((item for item in snapshot.descriptors if item.id == tool.id), None)
    if descriptor is None:
        raise CapabilityInvocationAdapterError("TOOL_DESCRIPTOR_MISSING")
    descriptor.validate()
    if request.snapshot_fingerprint != snapshot.fingerprint:
        raise CapabilityInvocationAdapterError("STALE_CAPABILITY_REGISTRY_SNAPSHOT")
    if request.descriptor_fingerprint != descriptor.fingerprint:
        raise CapabilityInvocationAdapterError("STALE_CAPABILITY_DESCRIPTOR")
    if descriptor.effect != tool.effect:
        raise CapabilityInvocationAdapterError("DESCRIPTOR_EFFECT_MISMATCH")
    if authority.task_id != request.task_id:
        raise CapabilityInvocationAdapterError("TASK_AUTHORITY_MISMATCH")

    parameters = _normalized_parameters(tool.id, request.parameter_dict())
    resource_kind, resource_ref = _reviewed_resource_target(tool.id, parameters)
    decision = authority.require(
        tool.id,
        resource_kind=resource_kind,
        resource_ref=resource_ref,
        effect=tool.effect,
    )
    receipt = receipt_from_capability_decision(
        decision=decision,
        task_ref_sha256=_sha256_text(request.task_id),
        request_ref_sha256=request.fingerprint,
        tool_id=tool.id,
        descriptor_fingerprint=descriptor.fingerprint,
        snapshot_fingerprint=snapshot.fingerprint,
    )

    raw_result = _invoke_reviewed_handler(
        tool.id,
        authority=authority,
        parameters=parameters,
    )
    if not isinstance(raw_result, dict):
        raise CapabilityInvocationAdapterError("HANDLER_RESULT_MUST_BE_MAPPING")
    payload = bound_text_result(
        _canonical_json(raw_result),
        max_bytes=descriptor.result_size_limit_bytes,
    )
    return CapabilityInvocationResult(
        tool_id=tool.id,
        descriptor_fingerprint=descriptor.fingerprint,
        snapshot_fingerprint=snapshot.fingerprint,
        decision_receipt=receipt,
        bounded_payload=payload,
    )


__all__ = [
    "CAPABILITY_INVOCATION_REQUEST_SCHEMA",
    "CAPABILITY_INVOCATION_RESULT_SCHEMA",
    "CapabilityInvocationAdapterError",
    "CapabilityInvocationRequest",
    "CapabilityInvocationResult",
    "current_runtime_invocation_identity",
    "invoke_runtime_tool",
    "reviewed_runtime_handler_ids",
]
