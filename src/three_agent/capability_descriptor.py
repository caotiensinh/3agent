from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

from .micro_tool_registry import (
    EFFECTS,
    NETWORK_ACCESS,
    RISK_ORDER,
    MicroToolRegistry,
    RegistryValidationError,
    ToolMetadata,
)
from .tool_result_boundary import DEFAULT_STDOUT_LIMIT_BYTES, MAX_RESULT_FIELD_BYTES

CAPABILITY_DESCRIPTOR_SCHEMA = "workspace-capability-descriptor/v1"
CAPABILITY_KINDS = frozenset({"tool", "program", "gateway", "agent", "provider", "adapter"})
DEFAULT_TOOL_NAMESPACE = "builtin.tool"
MICRO_TOOL_PROVENANCE_SOURCE = "micro_tool_registry"

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_NAMESPACE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_PLATFORM_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_PROVENANCE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class CapabilityDescriptorValidationError(ValueError):
    """A capability descriptor cannot be accepted as a reviewed metadata projection."""


def _stable_sha256(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _normalize_env_names(names: Iterable[str]) -> tuple[str, ...]:
    if isinstance(names, (str, bytes)):
        raise CapabilityDescriptorValidationError(
            "required_env_names must be a sequence of environment variable names"
        )
    raw = tuple(names)
    if len(raw) > 32:
        raise CapabilityDescriptorValidationError("required_env_names exceeds 32 entries")
    if any(type(name) is not str for name in raw):
        raise CapabilityDescriptorValidationError(
            "required_env_names entries must be strings containing names only"
        )
    normalized = tuple(sorted(name.strip() for name in raw))
    if any(not _ENV_NAME_RE.fullmatch(name) for name in normalized):
        raise CapabilityDescriptorValidationError(
            "required_env_names may contain names only, never assignments or values"
        )
    if len(set(normalized)) != len(normalized):
        raise CapabilityDescriptorValidationError("required_env_names must not contain duplicates")
    return normalized


def _require_token(value: Any, *, field: str, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or not pattern.fullmatch(value):
        raise CapabilityDescriptorValidationError(f"invalid {field}: {value!r}")
    return value


@dataclass(frozen=True)
class CapabilityDescriptor:
    """Immutable, non-authorizing runtime capability metadata.

    A descriptor is a reviewed projection of a canonical capability source. It can
    describe what a capability is and what result/evidence policy is expected, but
    it cannot grant TaskCapabilityAuthority, approval, credentials, or execution.
    """

    id: str
    kind: str
    namespace: str
    platform: str
    effect: str
    risk: str
    network_access: str
    requires_admin: bool
    sensitive_outputs: bool
    result_size_limit_bytes: int
    evidence_required: bool
    required_env_names: tuple[str, ...]
    provenance_source: str
    provenance_version: str
    source_fingerprint: str
    fingerprint: str
    schema_version: str = CAPABILITY_DESCRIPTOR_SCHEMA

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "id": self.id,
            "kind": self.kind,
            "namespace": self.namespace,
            "platform": self.platform,
            "effect": self.effect,
            "risk": self.risk,
            "network_access": self.network_access,
            "requires_admin": self.requires_admin,
            "sensitive_outputs": self.sensitive_outputs,
            "result_size_limit_bytes": self.result_size_limit_bytes,
            "evidence_required": self.evidence_required,
            "required_env_names": list(self.required_env_names),
            "provenance_source": self.provenance_source,
            "provenance_version": self.provenance_version,
            "source_fingerprint": self.source_fingerprint,
        }

    def validate(self) -> "CapabilityDescriptor":
        if self.schema_version != CAPABILITY_DESCRIPTOR_SCHEMA:
            raise CapabilityDescriptorValidationError(
                f"unsupported descriptor schema: {self.schema_version}"
            )
        _require_token(self.id, field="capability id", pattern=_ID_RE)
        if type(self.kind) is not str or self.kind not in CAPABILITY_KINDS:
            raise CapabilityDescriptorValidationError(f"unsupported capability kind: {self.kind}")
        _require_token(self.namespace, field="namespace", pattern=_NAMESPACE_RE)
        _require_token(self.platform, field="platform", pattern=_PLATFORM_RE)
        if type(self.effect) is not str or self.effect not in EFFECTS:
            raise CapabilityDescriptorValidationError(f"unknown effect: {self.effect}")
        if type(self.risk) is not str or self.risk not in RISK_ORDER:
            raise CapabilityDescriptorValidationError(f"unknown risk: {self.risk}")
        if type(self.network_access) is not str or self.network_access not in NETWORK_ACCESS:
            raise CapabilityDescriptorValidationError(
                f"unknown network access class: {self.network_access}"
            )
        if type(self.requires_admin) is not bool:
            raise CapabilityDescriptorValidationError("requires_admin must be boolean")
        if type(self.sensitive_outputs) is not bool:
            raise CapabilityDescriptorValidationError("sensitive_outputs must be boolean")
        if type(self.evidence_required) is not bool:
            raise CapabilityDescriptorValidationError("evidence_required must be boolean")
        if type(self.result_size_limit_bytes) is not int or type(self.result_size_limit_bytes) is bool:
            raise CapabilityDescriptorValidationError("result_size_limit_bytes must be an integer")
        if not 1 <= self.result_size_limit_bytes <= MAX_RESULT_FIELD_BYTES:
            raise CapabilityDescriptorValidationError(
                f"result_size_limit_bytes must be within 1..{MAX_RESULT_FIELD_BYTES}"
            )
        if type(self.required_env_names) is not tuple:
            raise CapabilityDescriptorValidationError("required_env_names must use tuple canonical form")
        if self.required_env_names != _normalize_env_names(self.required_env_names):
            raise CapabilityDescriptorValidationError(
                "required_env_names must use deterministic sorted canonical form"
            )
        _require_token(
            self.provenance_source,
            field="provenance_source",
            pattern=_PROVENANCE_TOKEN_RE,
        )
        _require_token(
            self.provenance_version,
            field="provenance_version",
            pattern=_PROVENANCE_TOKEN_RE,
        )
        _require_token(
            self.source_fingerprint,
            field="source_fingerprint",
            pattern=_SHA256_RE,
        )
        _require_token(self.fingerprint, field="fingerprint", pattern=_SHA256_RE)
        expected = _stable_sha256(self._identity_payload())
        if self.fingerprint != expected:
            raise CapabilityDescriptorValidationError("descriptor fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        payload = self._identity_payload()
        payload["fingerprint"] = self.fingerprint
        return payload


def project_tool_metadata(
    tool: ToolMetadata,
    *,
    required_env_names: Iterable[str] = (),
    result_size_limit_bytes: int = DEFAULT_STDOUT_LIMIT_BYTES,
    evidence_required: bool = True,
) -> CapabilityDescriptor:
    """Project one validated canonical ToolMetadata record into CapabilityDescriptor.

    This adapter does not register, select, authorize, invoke, or expose credentials.
    Environment declarations are variable names only. The exact source metadata is
    content-addressed separately so descriptor identity changes when reviewed source
    metadata changes.
    """

    if not isinstance(tool, ToolMetadata):
        raise CapabilityDescriptorValidationError("tool must be validated ToolMetadata")
    try:
        validated = tool.validate()
    except RegistryValidationError as exc:
        raise CapabilityDescriptorValidationError(str(exc)) from exc

    env_names = _normalize_env_names(required_env_names)
    if type(result_size_limit_bytes) is not int or type(result_size_limit_bytes) is bool:
        raise CapabilityDescriptorValidationError("result_size_limit_bytes must be an integer")
    limit = result_size_limit_bytes
    if not 1 <= limit <= MAX_RESULT_FIELD_BYTES:
        raise CapabilityDescriptorValidationError(
            f"result_size_limit_bytes must be within 1..{MAX_RESULT_FIELD_BYTES}"
        )
    if type(evidence_required) is not bool:
        raise CapabilityDescriptorValidationError("evidence_required must be boolean")

    source_fingerprint = _stable_sha256(validated.to_dict())
    identity = {
        "schema_version": CAPABILITY_DESCRIPTOR_SCHEMA,
        "id": validated.id,
        "kind": "tool",
        "namespace": DEFAULT_TOOL_NAMESPACE,
        "platform": validated.platform,
        "effect": validated.effect,
        "risk": validated.risk,
        "network_access": validated.network_access,
        "requires_admin": validated.requires_admin,
        "sensitive_outputs": validated.sensitive_outputs,
        "result_size_limit_bytes": limit,
        "evidence_required": evidence_required,
        "required_env_names": list(env_names),
        "provenance_source": MICRO_TOOL_PROVENANCE_SOURCE,
        "provenance_version": validated.schema_version,
        "source_fingerprint": source_fingerprint,
    }
    descriptor = CapabilityDescriptor(
        id=validated.id,
        kind="tool",
        namespace=DEFAULT_TOOL_NAMESPACE,
        platform=validated.platform,
        effect=validated.effect,
        risk=validated.risk,
        network_access=validated.network_access,
        requires_admin=validated.requires_admin,
        sensitive_outputs=validated.sensitive_outputs,
        result_size_limit_bytes=limit,
        evidence_required=evidence_required,
        required_env_names=env_names,
        provenance_source=MICRO_TOOL_PROVENANCE_SOURCE,
        provenance_version=validated.schema_version,
        source_fingerprint=source_fingerprint,
        fingerprint=_stable_sha256(identity),
    )
    return descriptor.validate()


def project_micro_tool_registry(
    registry: MicroToolRegistry,
) -> tuple[CapabilityDescriptor, ...]:
    """Return a deterministic immutable descriptor view over the canonical registry.

    The MicroToolRegistry remains the source of reviewed tool metadata. This function
    deliberately creates no second registry and grants no execution authority.
    """

    if not isinstance(registry, MicroToolRegistry):
        raise CapabilityDescriptorValidationError("registry must be canonical MicroToolRegistry")
    descriptors = tuple(
        project_tool_metadata(ToolMetadata.from_mapping(item))
        for item in registry.metadata_view()
    )
    return tuple(sorted(descriptors, key=lambda item: (item.namespace, item.id)))
