from __future__ import annotations

from functools import lru_cache
from typing import Iterable

from ..micro_tool_registry import MicroToolRegistry, ToolMetadata
from ..office_it_tools import iter_specs
from .capability_promotion import CapabilityBinding, default_office_it_bindings
from .common_tools import common_tool_metadata
from .network_tools import NETWORK_TOOL_METADATA, NETWORK_REACHABILITY_TOOL_ID


def _office_it_metadata() -> tuple[ToolMetadata, ...]:
    return tuple(ToolMetadata.from_spec(spec) for spec in iter_specs())


def runtime_tool_metadata() -> tuple[ToolMetadata, ...]:
    """Return the implemented diagnostic metadata known to the current runtime.

    This function does not grant TaskCapabilityAuthority and does not execute tools.
    """
    items = _office_it_metadata() + common_tool_metadata() + NETWORK_TOOL_METADATA
    ids = tuple(item.id for item in items)
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate runtime diagnostic tool ids")
    return tuple(sorted(items, key=lambda item: item.id))


@lru_cache(maxsize=1)
def runtime_micro_tool_registry() -> MicroToolRegistry:
    return MicroToolRegistry(runtime_tool_metadata())


def default_runtime_capability_bindings() -> tuple[CapabilityBinding, ...]:
    """Map abstract route capabilities only to tools that currently exist.

    Deliberately absent mappings remain unresolved and therefore fail closed during
    promotion. Generic internal reachability is bound only to its dedicated bounded
    ICMP evidence tool, never approximated with fixed-port SSH/SMB/printer probes.
    """
    bindings: list[CapabilityBinding] = list(default_office_it_bindings())
    bindings.extend(
        (
            CapabilityBinding("system.resources", ("system.resource.snapshot",)),
            CapabilityBinding("server.resources", ("system.resource.snapshot",)),
            CapabilityBinding("system.storage", ("system.storage.capacity",)),
            CapabilityBinding("storage.capacity", ("system.storage.capacity",)),
            CapabilityBinding("network.interface", ("network.interface.snapshot",)),
            CapabilityBinding("network.ip", ("network.ipconfig.snapshot",)),
            CapabilityBinding("network.dhcp", ("network.ipconfig.snapshot",)),
            CapabilityBinding("network.route", ("network.route.snapshot",)),
            CapabilityBinding("network.dns", ("network.dns.snapshot",)),
            CapabilityBinding("network.reachability", (NETWORK_REACHABILITY_TOOL_ID,)),
            CapabilityBinding("time.sync", ("time.sync.status",)),
            CapabilityBinding("service.status", ("service.status.read",)),
        )
    )
    seen: set[str] = set()
    ordered: list[CapabilityBinding] = []
    for binding in bindings:
        binding.validate()
        if binding.capability_tag in seen:
            raise ValueError(f"duplicate runtime capability binding: {binding.capability_tag}")
        seen.add(binding.capability_tag)
        ordered.append(binding)
    return tuple(ordered)


def unresolved_capability_backlog(
    capability_counts: Iterable[tuple[str, int]],
    *,
    limit: int | None = None,
) -> tuple[tuple[str, int], ...]:
    """Return deterministic highest-reuse missing capabilities for implementation planning."""
    items = tuple((str(tag), int(count)) for tag, count in capability_counts if int(count) > 0)
    ordered = tuple(sorted(items, key=lambda item: (-item[1], item[0])))
    if limit is None:
        return ordered
    if not 1 <= int(limit) <= 1000:
        raise ValueError("limit must be within 1..1000")
    return ordered[: int(limit)]


__all__ = [
    "default_runtime_capability_bindings",
    "runtime_micro_tool_registry",
    "runtime_tool_metadata",
    "unresolved_capability_backlog",
]
