from __future__ import annotations

import hashlib
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
    "network.reachability.internal": "network_read",
}
_UNKNOWN_EFFECT_TOOLS = TOOLS - set(_EFFECTS)
_STALE_EFFECT_TOOLS = set(_EFFECTS) - TOOLS
if _UNKNOWN_EFFECT_TOOLS or _STALE_EFFECT_TOOLS:
    raise RuntimeError(
        "capability effect vocabulary mismatch: "
        f"missing={sorted(_UNKNOWN_EFFECT_TOOLS)} stale={sorted(_STALE_EFFECT_TOOLS)}"
    )

_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-=]{0,255}$")
_NETWORK_SCOPES = frozenset({"deny", "internal_only", "allowlisted_egress"})


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
            "authority_fingerprint": self.authority_fingerprint,
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
