from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from .task_contract import INTERNAL_NETWORK_TOOLS, TOOLS, TaskContract

CAPABILITY_DECISION_SCHEMA = "workspace-capability-decision/v1"
CAPABILITY_AUTHORITY_SCHEMA = "workspace-task-capability-authority/v1"
_EFFECTS = {
    "read_file": "read",
    "search_repo": "read",
    "search_docs": "read",
    "query_db_readonly": "read",
    "calculator": "compute",
    "run_linter": "execute",
    "run_tests": "execute",
    "write_staging": "write",
    "apply_patch": "write",
    "web_gateway": "network_read",
    "windows.event.system": "read",
    "windows.event.application": "read",
    "windows.event.security": "read",
    "windows.printer.queue": "read",
    "network.ssh.probe": "network_read",
    "network.smb.probe": "network_read",
    "network.printer.ipp_probe": "network_read",
    "network.printer.raw_probe": "network_read",
    "system.platform.identify": "read",
    "system.resource.snapshot": "read",
    "system.storage.capacity": "read",
    "network.interface.snapshot": "read",
    "network.ipconfig.snapshot": "read",
    "network.route.snapshot": "read",
    "network.dns.snapshot": "read",
    "time.sync.status": "read",
    "service.status.read": "read",
    "windows.group_policy.result": "read",
    "identity.session.snapshot": "read",
    "audio.devices.snapshot": "read",
    "meeting.client.snapshot": "read",
    "process.top.snapshot": "read",
    "hardware.usb.snapshot": "read",
    "camera.devices.snapshot": "read",
    "storage.io.snapshot": "read",
    "windows.print.driver.snapshot": "read",
    "vpn.status.local": "read",
    "windows.boot.snapshot": "read",
    "windows.update.history": "read",
    "network.reachability.internal": "network_read",
    "network.quality.internal": "network_read",
}
_UNKNOWN_EFFECT_TOOLS = TOOLS - set(_EFFECTS)
_STALE_EFFECT_TOOLS = set(_EFFECTS) - TOOLS
if _UNKNOWN_EFFECT_TOOLS or _STALE_EFFECT_TOOLS:
    raise RuntimeError(
        "capability effect vocabulary mismatch: "
        f"missing={sorted(_UNKNOWN_EFFECT_TOOLS)} stale={sorted(_STALE_EFFECT_TOOLS)}"
    )

_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-=]{0,255}$")
_SERVICE_RESOURCE_RE = re.compile(r"^local:service:[A-Za-z0-9_.@-]{1,128}$")
_NETWORK_SCOPES = frozenset({"deny", "internal_only", "allowlisted_egress"})

# These are authorization policy bindings, not a second runtime registry. Every entry
# mirrors a resource identifier emitted by reviewed bounded tool implementation code.
_EXACT_RESOURCE_POLICIES = {
    "windows.event.system": ("event_channel", "windows:event:System"),
    "windows.event.application": ("event_channel", "windows:event:Application"),
    "windows.event.security": ("event_channel", "windows:event:Security"),
    "windows.printer.queue": ("print_queue", "windows:printer:queue"),
    "system.platform.identify": ("system_inventory", "local:platform"),
    "system.resource.snapshot": ("performance_snapshot", "local:resources"),
    "system.storage.capacity": ("filesystem_capacity", "local:storage:default"),
    "network.interface.snapshot": ("network_config", "local:interfaces"),
    "network.ipconfig.snapshot": ("network_config", "local:ipconfig"),
    "network.route.snapshot": ("network_config", "local:routes"),
    "network.dns.snapshot": ("network_config", "local:dns"),
    "time.sync.status": ("time_config", "local:time-sync"),
    "identity.session.snapshot": ("identity_session", "local:identity:current"),
    "audio.devices.snapshot": ("audio_devices", "local:audio:devices"),
    "meeting.client.snapshot": ("meeting_clients", "local:meeting:clients"),
    "process.top.snapshot": ("process_inventory", "local:processes:top"),
    "hardware.usb.snapshot": ("usb_devices", "local:usb:devices"),
    "camera.devices.snapshot": ("camera_devices", "local:camera:devices"),
    "storage.io.snapshot": ("storage_io", "local:storage:io"),
    "windows.print.driver.snapshot": ("printer_drivers", "local:printer:drivers"),
    "vpn.status.local": ("vpn_status", "local:vpn:status"),
    "windows.boot.snapshot": ("boot_state", "local:windows:boot"),
    "windows.update.history": ("windows_update_history", "local:windows:update-history"),
}
_GROUP_POLICY_REFS = frozenset(
    {
        "local:gpresult:user",
        "local:gpresult:computer",
        "local:gpresult:all",
    }
)
_NETWORK_RESOURCE_SUFFIXES = {
    "network.ssh.probe": ":22",
    "network.smb.probe": ":445",
    "network.printer.ipp_probe": ":631",
    "network.printer.raw_probe": ":9100",
    "network.reachability.internal": ":icmp",
    "network.quality.internal": ":icmp-quality",
}


class CapabilityAuthorityDenied(PermissionError):
    """A capability/resource/effect request exceeds immutable TaskContract authority."""

    def __init__(self, reason_code: str, decision: "CapabilityDecision | None" = None):
        self.reason_code = reason_code
        self.decision = decision
        super().__init__(reason_code)


def _compact(value: str, field: str, *, max_len: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or not _COMPACT_RE.fullmatch(text):
        raise ValueError(f"{field} must be a compact identifier")
    if "://" in text:
        raise ValueError(f"{field} must not contain a raw URL")
    return text


def _safe_path(value: str, field: str) -> str:
    text = _compact(value, field)
    path = PurePosixPath(text.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{field} must be a safe relative path")
    normalized = path.as_posix().strip("/")
    if not normalized or normalized == ".":
        raise ValueError(f"{field} must identify a bounded path")
    return normalized


def _normalize_write_scope(
    value: str | tuple[str, ...],
    field: str,
) -> str | tuple[str, ...]:
    if isinstance(value, str):
        if value == "none":
            return "none"
        return _safe_path(value, field)
    if not value:
        raise ValueError(f"{field} must not be empty; use 'none' to deny writes")
    normalized = tuple(dict.fromkeys(_safe_path(str(item), field) for item in value))
    return normalized


def _write_scope_is_subset(
    child: str | tuple[str, ...],
    parent: str | tuple[str, ...],
) -> bool:
    if child == "none":
        return True
    if parent == "none":
        return False
    child_scopes = child if isinstance(child, tuple) else (child,)
    parent_scopes = parent if isinstance(parent, tuple) else (parent,)
    return all(
        any(scope == parent_scope or scope.startswith(parent_scope + "/") for parent_scope in parent_scopes)
        for scope in child_scopes
    )


def _is_internal_ip_literal(value: str) -> bool:
    try:
        address = ipaddress.ip_address(str(value).strip())
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


def _resource_policy_denial(
    capability: str,
    resource_kind: str,
    resource_ref: str,
) -> str | None:
    exact = _EXACT_RESOURCE_POLICIES.get(capability)
    if exact is not None:
        expected_kind, expected_ref = exact
        if resource_kind != expected_kind:
            return "RESOURCE_KIND_NOT_AUTHORIZED"
        if resource_ref != expected_ref:
            return "RESOURCE_REF_NOT_AUTHORIZED"
        return None

    if capability == "service.status.read":
        if resource_kind != "service":
            return "RESOURCE_KIND_NOT_AUTHORIZED"
        if not _SERVICE_RESOURCE_RE.fullmatch(resource_ref):
            return "RESOURCE_REF_NOT_AUTHORIZED"
        return None

    if capability == "windows.group_policy.result":
        if resource_kind != "group_policy":
            return "RESOURCE_KIND_NOT_AUTHORIZED"
        if resource_ref not in _GROUP_POLICY_REFS:
            return "RESOURCE_REF_NOT_AUTHORIZED"
        return None

    suffix = _NETWORK_RESOURCE_SUFFIXES.get(capability)
    if suffix is not None:
        if resource_kind != "network_endpoint":
            return "RESOURCE_KIND_NOT_AUTHORIZED"
        if not resource_ref.endswith(suffix):
            return "RESOURCE_REF_NOT_AUTHORIZED"
        host = resource_ref[: -len(suffix)]
        if not host or not _is_internal_ip_literal(host):
            return "RESOURCE_REF_NOT_AUTHORIZED"
        return None

    return None


def _fingerprint_payload(
    *,
    task_id: str,
    sensitivity: str,
    allowed_sources: tuple[str, ...],
    allowed_tools: tuple[str, ...],
    write_scope: str | tuple[str, ...],
    network_scope: str,
) -> str:
    payload = {
        "task_id": task_id,
        "sensitivity": sensitivity,
        "allowed_sources": list(allowed_sources),
        "allowed_tools": list(allowed_tools),
        "write_scope": list(write_scope) if isinstance(write_scope, tuple) else write_scope,
        "network_scope": network_scope,
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True)
class CapabilityDecision:
    task_id: str
    capability: str
    resource_kind: str
    resource_ref: str
    effect: str
    allowed: bool
    reason_code: str
    authority_fingerprint: str
    schema_version: str = CAPABILITY_DECISION_SCHEMA

    def metadata(self) -> dict[str, str | bool]:
        """Return audit-safe metadata without raw path/URL/command content."""
        resource_digest = hashlib.sha256(self.resource_ref.encode("utf-8")).hexdigest()
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "capability": self.capability,
            "resource_kind": self.resource_kind,
            "resource_sha256": "sha256:" + resource_digest,
            "effect": self.effect,
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "authority_fingerprint": self.fingerprint,
        }


@dataclass(frozen=True)
class TaskCapabilityAuthority:
    """Deny-by-default capability envelope projected from immutable task authority."""

    task_id: str
    sensitivity: str
    allowed_sources: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    write_scope: str | tuple[str, ...]
    network_scope: str
    fingerprint: str

    @classmethod
    def _build(
        cls,
        *,
        task_id: str,
        sensitivity: str,
        allowed_sources: tuple[str, ...],
        allowed_tools: tuple[str, ...],
        write_scope: str | tuple[str, ...],
        network_scope: str,
    ) -> "TaskCapabilityAuthority":
        return cls(
            task_id=task_id,
            sensitivity=sensitivity,
            allowed_sources=allowed_sources,
            allowed_tools=allowed_tools,
            write_scope=write_scope,
            network_scope=network_scope,
            fingerprint=_fingerprint_payload(
                task_id=task_id,
                sensitivity=sensitivity,
                allowed_sources=allowed_sources,
                allowed_tools=allowed_tools,
                write_scope=write_scope,
                network_scope=network_scope,
            ),
        )

    @classmethod
    def from_contract(cls, contract: TaskContract) -> "TaskCapabilityAuthority":
        contract.validate()
        write_scope: str | tuple[str, ...] = (
            tuple(contract.write_scope)
            if isinstance(contract.write_scope, tuple)
            else str(contract.write_scope)
        )
        return cls._build(
            task_id=contract.task_id,
            sensitivity=contract.sensitivity,
            allowed_sources=tuple(contract.allowed_sources),
            allowed_tools=tuple(contract.allowed_tools),
            write_scope=write_scope,
            network_scope=contract.network_scope,
        )

    @classmethod
    def from_model_authority(cls, authority: Any) -> "TaskCapabilityAuthority":
        """Project the capability subset from bridge-bound TaskModelAuthority."""
        write_scope: str | tuple[str, ...] = (
            tuple(authority.write_scope)
            if isinstance(authority.write_scope, tuple)
            else str(authority.write_scope)
        )
        return cls._build(
            task_id=str(authority.task_id),
            sensitivity=str(authority.sensitivity),
            allowed_sources=tuple(authority.allowed_sources),
            allowed_tools=tuple(authority.allowed_tools),
            write_scope=write_scope,
            network_scope=str(authority.network_scope),
        )

    def derive_child(
        self,
        *,
        task_id: str,
        allowed_sources: tuple[str, ...] | None = None,
        allowed_tools: tuple[str, ...] | None = None,
        write_scope: str | tuple[str, ...] | None = None,
        network_scope: str | None = None,
    ) -> "TaskCapabilityAuthority":
        """Create a fail-closed child authority that cannot exceed this authority.

        Delegation may only preserve or reduce the parent's sources, tools, write
        paths and network authority. Sensitivity is inherited exactly so a child
        cannot declassify data. Cross-network-scope conversion is rejected; the
        only universally narrower network scope is ``deny``.
        """
        child_task_id = _compact(task_id, "child_task_id", max_len=128)

        if allowed_sources is None:
            child_sources = self.allowed_sources
        else:
            child_sources = tuple(
                dict.fromkeys(
                    _compact(str(source), "child_allowed_source", max_len=128)
                    for source in allowed_sources
                )
            )
            if not set(child_sources).issubset(self.allowed_sources):
                raise CapabilityAuthorityDenied("CHILD_SOURCE_SCOPE_ESCALATION")

        if allowed_tools is None:
            child_tools = self.allowed_tools
        else:
            child_tools = tuple(
                dict.fromkeys(
                    _compact(str(tool), "child_allowed_tool", max_len=64)
                    for tool in allowed_tools
                )
            )
            if not set(child_tools).issubset(self.allowed_tools):
                raise CapabilityAuthorityDenied("CHILD_CAPABILITY_ESCALATION")

        parent_write_scope = _normalize_write_scope(self.write_scope, "parent_write_scope")
        requested_write_scope = self.write_scope if write_scope is None else write_scope
        child_write_scope = _normalize_write_scope(requested_write_scope, "child_write_scope")
        if not _write_scope_is_subset(child_write_scope, parent_write_scope):
            raise CapabilityAuthorityDenied("CHILD_WRITE_SCOPE_ESCALATION")

        child_network_scope = (
            self.network_scope
            if network_scope is None
            else _compact(network_scope, "child_network_scope", max_len=64)
        )
        if child_network_scope not in _NETWORK_SCOPES:
            raise ValueError(f"unsupported child_network_scope: {child_network_scope}")
        if child_network_scope != self.network_scope and child_network_scope != "deny":
            raise CapabilityAuthorityDenied("CHILD_NETWORK_SCOPE_ESCALATION")

        return self._build(
            task_id=child_task_id,
            sensitivity=self.sensitivity,
            allowed_sources=child_sources,
            allowed_tools=child_tools,
            write_scope=child_write_scope,
            network_scope=child_network_scope,
        )

    def _decision(
        self,
        capability: str,
        resource_kind: str,
        resource_ref: str,
        effect: str,
        *,
        allowed: bool,
        reason_code: str,
    ) -> CapabilityDecision:
        return CapabilityDecision(
            task_id=self.task_id,
            capability=capability,
            resource_kind=resource_kind,
            resource_ref=resource_ref,
            effect=effect,
            allowed=allowed,
            reason_code=reason_code,
            authority_fingerprint=self.fingerprint,
        )

    def _write_allowed(self, resource_ref: str) -> bool:
        if self.write_scope == "none":
            return False
        try:
            resource = _safe_path(resource_ref, "resource_ref")
        except ValueError:
            return False
        scopes = self.write_scope if isinstance(self.write_scope, tuple) else (self.write_scope,)
        for raw_scope in scopes:
            try:
                scope = _safe_path(str(raw_scope), "write_scope")
            except ValueError:
                continue
            if resource == scope or resource.startswith(scope + "/"):
                return True
        return False

    def authorize(
        self,
        capability: str,
        *,
        resource_kind: str,
        resource_ref: str,
        effect: str,
    ) -> CapabilityDecision:
        cap = _compact(capability, "capability", max_len=64)
        kind = _compact(resource_kind, "resource_kind", max_len=64)
        ref = _compact(resource_ref, "resource_ref")
        eff = _compact(effect, "effect", max_len=64)

        if cap not in TOOLS:
            return self._decision(cap, kind, ref, eff, allowed=False, reason_code="CAPABILITY_UNKNOWN")
        if cap not in self.allowed_tools:
            return self._decision(cap, kind, ref, eff, allowed=False, reason_code="CAPABILITY_NOT_ALLOWED")
        expected_effect = _EFFECTS.get(cap)
        if expected_effect != eff:
            return self._decision(cap, kind, ref, eff, allowed=False, reason_code="CAPABILITY_EFFECT_NOT_ALLOWED")

        resource_denial = _resource_policy_denial(cap, kind, ref)
        if resource_denial is not None:
            return self._decision(cap, kind, ref, eff, allowed=False, reason_code=resource_denial)

        if cap == "web_gateway":
            if self.sensitivity != "public" or self.network_scope != "allowlisted_egress":
                return self._decision(cap, kind, ref, eff, allowed=False, reason_code="NETWORK_SCOPE_NOT_AUTHORIZED")
        elif cap in INTERNAL_NETWORK_TOOLS:
            if self.network_scope != "internal_only":
                return self._decision(cap, kind, ref, eff, allowed=False, reason_code="NETWORK_SCOPE_NOT_AUTHORIZED")
            if kind != "network_endpoint":
                return self._decision(cap, kind, ref, eff, allowed=False, reason_code="RESOURCE_KIND_NOT_AUTHORIZED")
        elif eff.startswith("network"):
            return self._decision(cap, kind, ref, eff, allowed=False, reason_code="NETWORK_CAPABILITY_NOT_AUTHORIZED")

        if eff == "write" and not self._write_allowed(ref):
            return self._decision(cap, kind, ref, eff, allowed=False, reason_code="WRITE_SCOPE_NOT_AUTHORIZED")

        return self._decision(cap, kind, ref, eff, allowed=True, reason_code="CAPABILITY_AUTHORIZED")

    def require(
        self,
        capability: str,
        *,
        resource_kind: str,
        resource_ref: str,
        effect: str,
    ) -> CapabilityDecision:
        decision = self.authorize(
            capability,
            resource_kind=resource_kind,
            resource_ref=resource_ref,
            effect=effect,
        )
        if not decision.allowed:
            raise CapabilityAuthorityDenied(decision.reason_code, decision)
        return decision

    def metadata(self) -> dict[str, str]:
        return {
            "schema_version": CAPABILITY_AUTHORITY_SCHEMA,
            "task_id": self.task_id,
            "authority_fingerprint": self.fingerprint,
        }
