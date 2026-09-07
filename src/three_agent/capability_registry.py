from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Iterable

from .capability_authority import TaskCapabilityAuthority, _EFFECTS
from .task_contract import TOOLS, TaskContract

CAPABILITY_REGISTRY_SCHEMA = "workspace-capability-registry/v1"
CAPABILITY_DESCRIPTOR_SCHEMA = "workspace-capability-descriptor/v1"


class CapabilityRegistryError(ValueError):
    """Capability metadata or discovery would violate the canonical runtime contract."""


@dataclass(frozen=True)
class CapabilityDescriptor:
    capability_id: str
    effect: str
    resource_kind: str
    side_effect_class: str
    trust_tier: str
    concurrency_mode: str
    cost_class: str
    evidence_default: bool
    description: str
    schema_version: str = CAPABILITY_DESCRIPTOR_SCHEMA

    def metadata(self) -> dict[str, object]:
        """Return planner-safe metadata; never endpoints, commands, or credentials."""
        return asdict(self)


_DEFAULT_DESCRIPTORS = (
    CapabilityDescriptor(
        "read_file",
        "read",
        "path",
        "none",
        "native",
        "parallel_safe",
        "free_native",
        True,
        "Read a bounded local file resource.",
    ),
    CapabilityDescriptor(
        "search_repo",
        "read",
        "repo",
        "none",
        "native",
        "parallel_safe",
        "free_native",
        True,
        "Search repository content within the authorized source scope.",
    ),
    CapabilityDescriptor(
        "search_docs",
        "read",
        "knowledge",
        "none",
        "native",
        "parallel_safe",
        "free_native",
        True,
        "Search approved local or indexed documentation.",
    ),
    CapabilityDescriptor(
        "query_db_readonly",
        "read",
        "database",
        "none",
        "native",
        "parallel_safe",
        "free_native",
        True,
        "Run a bounded read-only database query through the approved adapter.",
    ),
    CapabilityDescriptor(
        "calculator",
        "compute",
        "compute",
        "none",
        "native",
        "parallel_safe",
        "free_native",
        False,
        "Perform deterministic local calculation.",
    ),
    CapabilityDescriptor(
        "run_linter",
        "execute",
        "repo",
        "local_execute",
        "native",
        "parallel_safe",
        "free_native",
        True,
        "Run the reviewed repository linter adapter.",
    ),
    CapabilityDescriptor(
        "run_tests",
        "execute",
        "repo",
        "local_execute",
        "native",
        "parallel_safe",
        "free_native",
        True,
        "Run the reviewed test adapter within the task execution budget.",
    ),
    CapabilityDescriptor(
        "write_staging",
        "write",
        "path",
        "write",
        "native",
        "serialized",
        "free_native",
        True,
        "Write only inside the task-authorized staging path.",
    ),
    CapabilityDescriptor(
        "apply_patch",
        "write",
        "path",
        "write",
        "native",
        "serialized",
        "free_native",
        True,
        "Apply a bounded patch only inside the authorized write scope.",
    ),
    CapabilityDescriptor(
        "web_gateway",
        "network_read",
        "network",
        "network_read",
        "gateway",
        "parallel_safe",
        "policy_bounded_external",
        True,
        "Perform sanitized allowlisted read-only Internet research through the gateway.",
    ),
)


class CapabilityRegistry:
    """Canonical capability discovery above immutable task authority.

    ``TaskContract.TOOLS`` remains the stable compatibility ID set. The registry
    adds reviewed semantics and returns only capabilities that are eligible to be
    disclosed for the current authority. Resource-specific authorization still
    happens later at execution-plan admission and gateway invocation.
    """

    def __init__(self, descriptors: Iterable[CapabilityDescriptor] = _DEFAULT_DESCRIPTORS):
        rows = tuple(descriptors)
        if not rows:
            raise CapabilityRegistryError("capability registry cannot be empty")
        by_id: dict[str, CapabilityDescriptor] = {}
        for descriptor in rows:
            capability_id = str(descriptor.capability_id).strip()
            if capability_id in by_id:
                raise CapabilityRegistryError(f"duplicate capability descriptor: {capability_id}")
            if capability_id not in TOOLS:
                raise CapabilityRegistryError(f"descriptor is not a canonical tool: {capability_id}")
            expected_effect = _EFFECTS.get(capability_id)
            if descriptor.effect != expected_effect:
                raise CapabilityRegistryError(
                    f"effect drift for {capability_id}: expected {expected_effect}, got {descriptor.effect}"
                )
            if descriptor.concurrency_mode not in {"parallel_safe", "serialized"}:
                raise CapabilityRegistryError(f"invalid concurrency mode: {capability_id}")
            if descriptor.trust_tier not in {"native", "gateway"}:
                raise CapabilityRegistryError(f"invalid trust tier: {capability_id}")
            if not descriptor.description or len(descriptor.description) > 240:
                raise CapabilityRegistryError(f"invalid capability description: {capability_id}")
            by_id[capability_id] = descriptor
        if set(by_id) != set(TOOLS):
            missing = sorted(set(TOOLS) - set(by_id))
            extra = sorted(set(by_id) - set(TOOLS))
            raise CapabilityRegistryError(
                f"registry must cover canonical tools exactly; missing={missing} extra={extra}"
            )
        self._by_id = by_id

    @classmethod
    def default(cls) -> "CapabilityRegistry":
        return cls(_DEFAULT_DESCRIPTORS)

    @property
    def fingerprint(self) -> str:
        payload = [self._by_id[key].metadata() for key in sorted(self._by_id)]
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def descriptor(self, capability_id: str) -> CapabilityDescriptor:
        key = str(capability_id).strip()
        try:
            return self._by_id[key]
        except KeyError as exc:
            raise CapabilityRegistryError(f"unknown capability: {key}") from exc

    @staticmethod
    def _eligible(descriptor: CapabilityDescriptor, authority: TaskCapabilityAuthority) -> bool:
        if descriptor.capability_id not in authority.allowed_tools:
            return False
        if descriptor.effect == "write" and authority.write_scope == "none":
            return False
        if descriptor.effect == "network_read":
            if authority.sensitivity == "secret":
                return False
            if authority.network_scope != "allowlisted_egress":
                return False
        return True

    def discover(self, authority: TaskCapabilityAuthority) -> tuple[CapabilityDescriptor, ...]:
        """Return only planner-disclosable capabilities for the current authority."""
        return tuple(
            self._by_id[key]
            for key in sorted(self._by_id)
            if self._eligible(self._by_id[key], authority)
        )

    def discover_for_contract(self, contract: TaskContract) -> tuple[CapabilityDescriptor, ...]:
        return self.discover(TaskCapabilityAuthority.from_contract(contract))

    def select(
        self,
        authority: TaskCapabilityAuthority,
        capability_ids: Iterable[str],
    ) -> tuple[CapabilityDescriptor, ...]:
        """Resolve a requested subset without allowing discovery-time authority widening."""
        available = {item.capability_id: item for item in self.discover(authority)}
        selected: list[CapabilityDescriptor] = []
        for raw in capability_ids:
            key = str(raw).strip()
            if key not in available:
                raise CapabilityRegistryError(f"capability is not discoverable for this task: {key}")
            if available[key] not in selected:
                selected.append(available[key])
        return tuple(selected)

    def planner_metadata(self, authority: TaskCapabilityAuthority) -> dict[str, object]:
        """Build bounded, authority-filtered metadata suitable for planner context."""
        capabilities = self.discover(authority)
        return {
            "schema_version": CAPABILITY_REGISTRY_SCHEMA,
            "registry_fingerprint": self.fingerprint,
            "authority_fingerprint": authority.fingerprint,
            "capabilities": [item.metadata() for item in capabilities],
        }
