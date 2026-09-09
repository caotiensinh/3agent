from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ..micro_tool_registry import MicroToolRegistry
from .runtime_registry import runtime_micro_tool_registry

EVIDENCE_PRIMITIVE_SCHEMA = "workspace-evidence-primitive/v1"


@dataclass(frozen=True)
class EvidencePrimitive:
    """Planning-only reusable evidence definition over existing runtime tools.

    A primitive describes a narrow evidence shape that multiple diagnostic capabilities
    may reuse. It never grants TaskCapabilityAuthority, selects a tool for execution, or
    widens network/write permissions.
    """

    primitive_id: str
    tool_ids: tuple[str, ...]
    scope: str
    execution_enabled: bool = False
    selection_authority: str = "none"
    schema_version: str = EVIDENCE_PRIMITIVE_SCHEMA

    def validate(self, registry: MicroToolRegistry) -> "EvidencePrimitive":
        if self.schema_version != EVIDENCE_PRIMITIVE_SCHEMA:
            raise ValueError(f"unsupported evidence primitive schema: {self.schema_version}")
        if not self.primitive_id.strip():
            raise ValueError("primitive_id is required")
        if not self.scope.strip():
            raise ValueError("scope is required")
        if not self.tool_ids:
            raise ValueError("tool_ids is required")
        if len(set(self.tool_ids)) != len(self.tool_ids):
            raise ValueError("tool_ids cannot contain duplicates")
        if self.execution_enabled is not False:
            raise ValueError("evidence primitives cannot enable execution")
        if self.selection_authority != "none":
            raise ValueError("evidence primitives cannot grant selection authority")

        for tool_id in self.tool_ids:
            metadata = registry.get(tool_id)
            if metadata.network_access != "none":
                raise ValueError(
                    f"evidence primitive {self.primitive_id} cannot include network-access tool {tool_id}"
                )
            if metadata.effect != "read":
                raise ValueError(
                    f"evidence primitive {self.primitive_id} requires read-only tool {tool_id}"
                )
        return self


_DEFAULT_PRIMITIVES = (
    EvidencePrimitive(
        primitive_id="system.resource_snapshot",
        tool_ids=("system.resource.snapshot",),
        scope="local_system_resource_counters",
    ),
    EvidencePrimitive(
        primitive_id="storage.capacity_snapshot",
        tool_ids=("system.storage.capacity",),
        scope="local_storage_capacity",
    ),
    EvidencePrimitive(
        primitive_id="process.snapshot",
        tool_ids=("process.top.snapshot",),
        scope="local_process_resource_snapshot",
    ),
    EvidencePrimitive(
        primitive_id="service.snapshot",
        tool_ids=("service.status.read",),
        scope="local_service_status",
    ),
    EvidencePrimitive(
        primitive_id="network.interface_snapshot",
        tool_ids=("network.interface.snapshot",),
        scope="local_network_interface_state",
    ),
    EvidencePrimitive(
        primitive_id="route.snapshot",
        tool_ids=("network.route.snapshot",),
        scope="local_route_table",
    ),
    EvidencePrimitive(
        primitive_id="dns.snapshot",
        tool_ids=("network.dns.snapshot",),
        scope="local_dns_configuration",
    ),
    EvidencePrimitive(
        primitive_id="identity.session_snapshot",
        tool_ids=("identity.session.snapshot",),
        scope="current_process_identity",
    ),
    EvidencePrimitive(
        primitive_id="vpn.local_status_snapshot",
        tool_ids=("vpn.status.snapshot",),
        scope="local_vpn_status_evidence",
    ),
)


def default_evidence_primitives(
    registry: MicroToolRegistry | None = None,
) -> tuple[EvidencePrimitive, ...]:
    """Return validated reusable local read-only evidence definitions.

    Validation is performed against the production runtime registry so a primitive
    cannot silently reference a missing, network-capable, or mutating tool.
    """

    active_registry = registry or runtime_micro_tool_registry()
    items = tuple(item.validate(active_registry) for item in _DEFAULT_PRIMITIVES)
    ids = tuple(item.primitive_id for item in items)
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate evidence primitive ids")
    return tuple(sorted(items, key=lambda item: item.primitive_id))


def evidence_primitive_by_id(
    primitive_id: str,
    *,
    registry: MicroToolRegistry | None = None,
) -> EvidencePrimitive:
    target = str(primitive_id).strip()
    for item in default_evidence_primitives(registry):
        if item.primitive_id == target:
            return item
    raise KeyError(target)


__all__ = [
    "EVIDENCE_PRIMITIVE_SCHEMA",
    "EvidencePrimitive",
    "default_evidence_primitives",
    "evidence_primitive_by_id",
]
