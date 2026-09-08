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
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
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
    normalized = tuple(sorted(str(name).strip() for name in names))
    if len(normalized) > 32:
        raise CapabilityDescriptorValidationError("required_env_names exceeds 32 entries")
    if any(not _ENV_NAME_RE.fullmatch(name) for name in normalized):
        raise CapabilityDescriptorValidationError(
            "required_env_names may contain names only, never assignments or values"
        )
    if len(set(normalized)) != len(normalized):
        raise CapabilityDescriptorValidationError("required_env_names must not contain duplicates")
    return normalized


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
        if not _ID_RE.fullmatch(self.id):
            raise CapabilityDescriptorValidationError(f"invalid capability id: {self.id!r}")
        if self.kind not in CAPABILITY_KINDS:
            raise CapabilityDescriptorValidationError(f"unsupported capability kind: {self.kind}")
        if not _NAMESPACE_RE.fullmatch(self.namespace):
            raise CapabilityDescriptorValidationError(f"invalid namespace: {self.namespace!r}")
        if self.effect not in EFFECTS:
            raise CapabilityDescriptorValidationError(f"unknown effect: {self.effect}")
        if self.risk not in RISK_ORDER:
            raise CapabilityDescriptorValidationError(f"unknown risk: {self.risk}")
        if self.network_access not in NETWORK_ACCESS:
            raise CapabilityDescriptorValidationError(
                f"unknown network access class: {self.network_access}"
            )
        if type(self.requires_admin) is not bool:
            raise CapabilityDescriptorValidationError("requires_admin must be boolean")
        if type(self.sensitive_outputs) is not bool:
            raise CapabilityDescriptorValidationError("sensitive_outputs must be boolean")
        if type(self.evidence_required) is not bool:
            raise CapabilityDescriptorValidationError("evidence_required must be boolean")
        if not 1 <= int(self.result_size_limit_bytes) <= MAX_RESULT_FIELD_BYTES:
            raise CapabilityDescriptorValidationError(
                f"result_size_limit_bytes must be within 1..{MAX_RESULT_FIELD_BYTES}"
            )
        if self.required_env_names != _normalize_env_names(self.required_env_names):
            raise CapabilityDescriptorValidationError(
                "required_env_names must use deterministic sorted canonical form"
            )
        if not str(self.provenance_source).strip():
            raise CapabilityDescriptorValidationError("provenance_source is required")
        if not str(self.provenance_version).strip():
            raise CapabilityDescriptorValidationError("provenance_version is required")
        if not _SHA256_RE.fullmatch(self.source_fingerprint):
            raise CapabilityDescriptorValidationError("source_fingerprint must be sha256-prefixed")
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

    try:
        validated = tool.validate()
    except RegistryValidationError as exc:
        raise CapabilityDescriptorValidationError(str(exc)) from exc

    env_names = _normalize_env_names(required_env_names)
    limit = int(result_size_limit_bytes)
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

    descriptors = tuple(
        project_tool_metadata(ToolMetadata.from_mapping(item))
        for item in registry.metadata_view()
    )
    return tuple(sorted(descriptors, key=lambda item: (item.namespace, item.id)))
