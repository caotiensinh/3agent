from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from .task_contract import TOOLS, TaskContract

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
}
_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-=]{0,255}$")


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
