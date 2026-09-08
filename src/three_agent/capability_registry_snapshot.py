from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

from .capability_descriptor import (
    CAPABILITY_KINDS,
    CapabilityDescriptor,
    CapabilityDescriptorValidationError,
    project_micro_tool_registry,
)
from .micro_tool_registry import MicroToolRegistry

CAPABILITY_NAMESPACE_POLICY_SCHEMA = "workspace-capability-namespace-policy/v1"
CAPABILITY_REGISTRY_SNAPSHOT_SCHEMA = "workspace-capability-registry-snapshot/v1"

_NAMESPACE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_PROVENANCE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class CapabilityRegistrySnapshotValidationError(ValueError):
    """The projected capability registry snapshot is malformed or unreviewed."""


def _stable_sha256(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _require_token(value: Any, *, field: str, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or not pattern.fullmatch(value):
        raise CapabilityRegistrySnapshotValidationError(f"invalid {field}: {value!r}")
    return value


@dataclass(frozen=True)
class ReviewedCapabilityNamespace:
    """Immutable source-reviewed namespace policy.

    Instances are structurally validated here, but runtime admission is additionally
    restricted to the closed source allowlist in REVIEWED_NAMESPACE_POLICIES.
    """

    namespace: str
    kind: str
    provenance_source: str
    external: bool
    fingerprint: str
    schema_version: str = CAPABILITY_NAMESPACE_POLICY_SCHEMA

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "namespace": self.namespace,
            "kind": self.kind,
            "provenance_source": self.provenance_source,
            "external": self.external,
        }

    def validate(self) -> "ReviewedCapabilityNamespace":
        if self.schema_version != CAPABILITY_NAMESPACE_POLICY_SCHEMA:
            raise CapabilityRegistrySnapshotValidationError(
                f"unsupported namespace policy schema: {self.schema_version}"
            )
        _require_token(self.namespace, field="namespace", pattern=_NAMESPACE_RE)
        if type(self.kind) is not str or self.kind not in CAPABILITY_KINDS:
            raise CapabilityRegistrySnapshotValidationError(
                f"unsupported capability kind: {self.kind}"
            )
        _require_token(
            self.provenance_source,
            field="provenance_source",
            pattern=_PROVENANCE_TOKEN_RE,
        )
        if type(self.external) is not bool:
            raise CapabilityRegistrySnapshotValidationError("external must be boolean")
        if self.external:
            raise CapabilityRegistrySnapshotValidationError(
                "external namespaces are not reviewed for runtime exposure in v0.1"
            )
        _require_token(self.fingerprint, field="fingerprint", pattern=_SHA256_RE)
        expected = _stable_sha256(self._identity_payload())
        if self.fingerprint != expected:
            raise CapabilityRegistrySnapshotValidationError(
                "namespace policy fingerprint mismatch"
            )
        return self

    def to_dict(self) -> dict[str, Any]:
        payload = self._identity_payload()
        payload["fingerprint"] = self.fingerprint
        return payload


def _namespace_policy(
    *,
    namespace: str,
    kind: str,
    provenance_source: str,
    external: bool = False,
) -> ReviewedCapabilityNamespace:
    """Build a policy constant for source review; not a runtime approval surface."""

    identity = {
        "schema_version": CAPABILITY_NAMESPACE_POLICY_SCHEMA,
        "namespace": namespace,
        "kind": kind,
        "provenance_source": provenance_source,
        "external": external,
    }
    return ReviewedCapabilityNamespace(
        namespace=namespace,
        kind=kind,
        provenance_source=provenance_source,
        external=external,
        fingerprint=_stable_sha256(identity),
    ).validate()


BUILTIN_TOOL_NAMESPACE = _namespace_policy(
    namespace="builtin.tool",
    kind="tool",
    provenance_source="micro_tool_registry",
    external=False,
)

# Closed source allowlist. Runtime callers cannot mint another reviewed namespace by
# constructing a structurally valid policy object; new entries require a reviewed code
# change that updates this tuple.
REVIEWED_NAMESPACE_POLICIES = (BUILTIN_TOOL_NAMESPACE,)
_REVIEWED_POLICY_BY_NAMESPACE = {
    item.namespace: item for item in REVIEWED_NAMESPACE_POLICIES
}


def _validated_reviewed_namespaces(
    namespaces: Iterable[ReviewedCapabilityNamespace],
) -> tuple[ReviewedCapabilityNamespace, ...]:
    if isinstance(namespaces, (str, bytes)):
        raise CapabilityRegistrySnapshotValidationError(
            "namespaces must be an iterable of reviewed namespace policies"
        )
    raw = tuple(namespaces)
    if not raw:
        raise CapabilityRegistrySnapshotValidationError(
            "at least one reviewed namespace is required"
        )

    validated: list[ReviewedCapabilityNamespace] = []
    seen: set[str] = set()
    for item in raw:
        if type(item) is not ReviewedCapabilityNamespace:
            raise CapabilityRegistrySnapshotValidationError(
                "namespaces must contain ReviewedCapabilityNamespace values only"
            )
        candidate = item.validate()
        canonical = _REVIEWED_POLICY_BY_NAMESPACE.get(candidate.namespace)
        if canonical is None or candidate != canonical:
            raise CapabilityRegistrySnapshotValidationError(
                f"namespace policy is not source-reviewed: {candidate.namespace}"
            )
        if candidate.namespace in seen:
            raise CapabilityRegistrySnapshotValidationError(
                "duplicate reviewed namespaces"
            )
        seen.add(candidate.namespace)
        validated.append(candidate)

    return tuple(sorted(validated, key=lambda item: (item.namespace, item.kind)))


@dataclass(frozen=True)
class CapabilityRegistrySnapshot:
    """Immutable, content-addressed view over reviewed capability descriptors.

    This is a projection receipt, not a mutable registry and not an authority source.
    """

    descriptors: tuple[CapabilityDescriptor, ...]
    namespaces: tuple[ReviewedCapabilityNamespace, ...]
    fingerprint: str
    schema_version: str = CAPABILITY_REGISTRY_SNAPSHOT_SCHEMA

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "namespaces": [item.to_dict() for item in self.namespaces],
            "descriptors": [
                {
                    "namespace": item.namespace,
                    "id": item.id,
                    "kind": item.kind,
                    "fingerprint": item.fingerprint,
                }
                for item in self.descriptors
            ],
        }

    def validate(self) -> "CapabilityRegistrySnapshot":
        if self.schema_version != CAPABILITY_REGISTRY_SNAPSHOT_SCHEMA:
            raise CapabilityRegistrySnapshotValidationError(
                f"unsupported registry snapshot schema: {self.schema_version}"
            )
        if type(self.descriptors) is not tuple:
            raise CapabilityRegistrySnapshotValidationError(
                "descriptors must use tuple canonical form"
            )
        if type(self.namespaces) is not tuple:
            raise CapabilityRegistrySnapshotValidationError(
                "namespaces must use tuple canonical form"
            )
        if not self.descriptors:
            raise CapabilityRegistrySnapshotValidationError(
                "at least one capability descriptor is required"
            )

        canonical_namespaces = _validated_reviewed_namespaces(self.namespaces)
        if self.namespaces != canonical_namespaces:
            raise CapabilityRegistrySnapshotValidationError(
                "namespaces must use deterministic canonical order"
            )
        policy_by_namespace = {
            item.namespace: item for item in canonical_namespaces
        }

        validated_descriptors: list[CapabilityDescriptor] = []
        descriptor_ids: list[str] = []
        for descriptor in self.descriptors:
            if type(descriptor) is not CapabilityDescriptor:
                raise CapabilityRegistrySnapshotValidationError(
                    "descriptors must contain CapabilityDescriptor values only"
                )
            try:
                validated = descriptor.validate()
            except CapabilityDescriptorValidationError as exc:
                raise CapabilityRegistrySnapshotValidationError(str(exc)) from exc

            policy = policy_by_namespace.get(validated.namespace)
            if policy is None:
                raise CapabilityRegistrySnapshotValidationError(
                    f"unreviewed capability namespace: {validated.namespace}"
                )
            if policy.kind != validated.kind:
                raise CapabilityRegistrySnapshotValidationError(
                    f"namespace kind mismatch: {validated.namespace}"
                )
            if policy.provenance_source != validated.provenance_source:
                raise CapabilityRegistrySnapshotValidationError(
                    f"namespace provenance mismatch: {validated.namespace}"
                )
            descriptor_ids.append(validated.id)
            validated_descriptors.append(validated)

        if len(set(descriptor_ids)) != len(descriptor_ids):
            raise CapabilityRegistrySnapshotValidationError(
                "duplicate capability ids are not allowed"
            )
        canonical_descriptors = tuple(
            sorted(
                validated_descriptors,
                key=lambda item: (item.namespace, item.id, item.fingerprint),
            )
        )
        if self.descriptors != canonical_descriptors:
            raise CapabilityRegistrySnapshotValidationError(
                "descriptors must use deterministic canonical order"
            )

        _require_token(self.fingerprint, field="fingerprint", pattern=_SHA256_RE)
        expected = _stable_sha256(self._identity_payload())
        if self.fingerprint != expected:
            raise CapabilityRegistrySnapshotValidationError(
                "registry snapshot fingerprint mismatch"
            )
        return self

    def to_dict(self) -> dict[str, Any]:
        payload = self._identity_payload()
        payload["fingerprint"] = self.fingerprint
        return payload


def build_capability_registry_snapshot(
    descriptors: Iterable[CapabilityDescriptor],
    *,
    namespaces: Iterable[ReviewedCapabilityNamespace] = REVIEWED_NAMESPACE_POLICIES,
) -> CapabilityRegistrySnapshot:
    """Build a deterministic non-authorizing snapshot from reviewed descriptors."""

    if isinstance(descriptors, (str, bytes)):
        raise CapabilityRegistrySnapshotValidationError(
            "descriptors must be an iterable of CapabilityDescriptor values"
        )
    descriptor_tuple = tuple(descriptors)
    if not descriptor_tuple:
        raise CapabilityRegistrySnapshotValidationError(
            "at least one capability descriptor is required"
        )

    canonical_namespaces = _validated_reviewed_namespaces(namespaces)

    validated_descriptors: list[CapabilityDescriptor] = []
    for descriptor in descriptor_tuple:
        if type(descriptor) is not CapabilityDescriptor:
            raise CapabilityRegistrySnapshotValidationError(
                "descriptors must contain CapabilityDescriptor values only"
            )
        try:
            validated_descriptors.append(descriptor.validate())
        except CapabilityDescriptorValidationError as exc:
            raise CapabilityRegistrySnapshotValidationError(str(exc)) from exc

    canonical_descriptors = tuple(
        sorted(
            validated_descriptors,
            key=lambda item: (item.namespace, item.id, item.fingerprint),
        )
    )
    identity = {
        "schema_version": CAPABILITY_REGISTRY_SNAPSHOT_SCHEMA,
        "namespaces": [item.to_dict() for item in canonical_namespaces],
        "descriptors": [
            {
                "namespace": item.namespace,
                "id": item.id,
                "kind": item.kind,
                "fingerprint": item.fingerprint,
            }
            for item in canonical_descriptors
        ],
    }
    return CapabilityRegistrySnapshot(
        descriptors=canonical_descriptors,
        namespaces=canonical_namespaces,
        fingerprint=_stable_sha256(identity),
    ).validate()


def snapshot_micro_tool_registry(
    registry: MicroToolRegistry,
) -> CapabilityRegistrySnapshot:
    """Project the canonical MicroToolRegistry into an immutable reviewed snapshot."""

    if not isinstance(registry, MicroToolRegistry):
        raise CapabilityRegistrySnapshotValidationError(
            "registry must be canonical MicroToolRegistry"
        )
    return build_capability_registry_snapshot(project_micro_tool_registry(registry))
