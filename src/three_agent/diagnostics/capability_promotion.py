from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Mapping

from ..micro_tool_registry import MicroToolRegistry
from .catalog_compiler import PlannedDiagnosticRoute

PROMOTION_SCHEMA = "workspace-diagnostic-route-promotion/v1"
_DIAGNOSTIC_EFFECTS = frozenset({"read", "network_read", "compute"})


@dataclass(frozen=True)
class CapabilityBinding:
    capability_tag: str
    tool_ids: tuple[str, ...]

    def validate(self) -> "CapabilityBinding":
        if not self.capability_tag.strip():
            raise ValueError("capability tag is required")
        if not self.tool_ids or any(not tool_id.strip() for tool_id in self.tool_ids):
            raise ValueError("capability binding requires one or more tool ids")
        if len(set(self.tool_ids)) != len(self.tool_ids):
            raise ValueError("capability binding tool ids must be unique")
        return self


@dataclass(frozen=True)
class RejectedBinding:
    capability_tag: str
    tool_id: str
    reason_code: str


@dataclass(frozen=True)
class RoutePromotionResult:
    route_id: str
    promotable: bool
    selected_tool_ids: tuple[str, ...]
    covered_capability_tags: tuple[str, ...]
    unresolved_capability_tags: tuple[str, ...]
    rejected_bindings: tuple[RejectedBinding, ...]
    schema_version: str = PROMOTION_SCHEMA


@dataclass(frozen=True)
class CapabilityCoverageReport:
    total_routes: int
    fully_promotable_routes: int
    partially_covered_routes: int
    uncovered_routes: int
    unresolved_capability_counts: tuple[tuple[str, int], ...]
    selected_tool_counts: tuple[tuple[str, int], ...]
    schema_version: str = PROMOTION_SCHEMA


def default_office_it_bindings() -> tuple[CapabilityBinding, ...]:
    """Bind only capabilities that the current Office IT v0.1 tools actually provide."""
    return (
        CapabilityBinding(
            "windows.events",
            ("windows.event.system", "windows.event.application"),
        ),
        CapabilityBinding(
            "print.queue",
            ("windows.printer.queue",),
        ),
        CapabilityBinding(
            "print.port",
            ("network.printer.ipp_probe", "network.printer.raw_probe"),
        ),
    )


def _binding_map(bindings: Iterable[CapabilityBinding]) -> Mapping[str, CapabilityBinding]:
    result: dict[str, CapabilityBinding] = {}
    for binding in bindings:
        binding.validate()
        if binding.capability_tag in result:
            raise ValueError(f"duplicate capability binding: {binding.capability_tag}")
        result[binding.capability_tag] = binding
    return result


def promote_planned_route(
    route: PlannedDiagnosticRoute,
    registry: MicroToolRegistry,
    *,
    bindings: Iterable[CapabilityBinding],
    allow_external_network: bool = False,
) -> RoutePromotionResult:
    """Project a planned route onto implemented diagnostic tools without executing them.

    Promotion is fail-closed. Every required capability tag must resolve to one or more
    implemented diagnostic tools. Unknown, mutating, unavailable, or external-egress
    bindings block promotion. The returned tool ids are still only capabilities;
    TaskCapabilityAuthority remains mandatory at execution time.
    """
    route.validate()
    if type(allow_external_network) is not bool:
        raise ValueError("allow_external_network must be boolean")
    mapping = _binding_map(bindings)

    selected: list[str] = []
    covered: list[str] = []
    unresolved: list[str] = []
    rejected: list[RejectedBinding] = []

    for tag in route.evidence_capability_tags:
        binding = mapping.get(tag)
        if binding is None:
            unresolved.append(tag)
            continue
        safe_for_tag: list[str] = []
        for tool_id in binding.tool_ids:
            try:
                tool = registry.get(tool_id)
            except Exception:
                rejected.append(RejectedBinding(tag, tool_id, "UNKNOWN_TOOL"))
                continue
            if not tool.implemented:
                rejected.append(RejectedBinding(tag, tool_id, "TOOL_UNAVAILABLE"))
                continue
            if tool.effect not in _DIAGNOSTIC_EFFECTS:
                rejected.append(RejectedBinding(tag, tool_id, "NON_DIAGNOSTIC_EFFECT"))
                continue
            if tool.network_access == "allowlisted_egress" and not allow_external_network:
                rejected.append(RejectedBinding(tag, tool_id, "EXTERNAL_EGRESS_DISABLED"))
                continue
            safe_for_tag.append(tool.id)
        if safe_for_tag:
            covered.append(tag)
            selected.extend(safe_for_tag)
        else:
            unresolved.append(tag)

    selected_unique = tuple(dict.fromkeys(selected))
    covered_unique = tuple(dict.fromkeys(covered))
    unresolved_unique = tuple(dict.fromkeys(unresolved))
    rejected_tuple = tuple(rejected)
    promotable = not unresolved_unique and not rejected_tuple
    return RoutePromotionResult(
        route_id=route.route_id,
        promotable=promotable,
        selected_tool_ids=selected_unique,
        covered_capability_tags=covered_unique,
        unresolved_capability_tags=unresolved_unique,
        rejected_bindings=rejected_tuple,
    )


def build_coverage_report(
    routes: Iterable[PlannedDiagnosticRoute],
    registry: MicroToolRegistry,
    *,
    bindings: Iterable[CapabilityBinding],
    allow_external_network: bool = False,
) -> CapabilityCoverageReport:
    bindings_tuple = tuple(bindings)
    route_items = tuple(routes)
    full = 0
    partial = 0
    uncovered = 0
    unresolved_counter: Counter[str] = Counter()
    selected_counter: Counter[str] = Counter()

    for route in route_items:
        result = promote_planned_route(
            route,
            registry,
            bindings=bindings_tuple,
            allow_external_network=allow_external_network,
        )
        if result.promotable:
            full += 1
        elif result.selected_tool_ids:
            partial += 1
        else:
            uncovered += 1
        unresolved_counter.update(result.unresolved_capability_tags)
        selected_counter.update(result.selected_tool_ids)

    return CapabilityCoverageReport(
        total_routes=len(route_items),
        fully_promotable_routes=full,
        partially_covered_routes=partial,
        uncovered_routes=uncovered,
        unresolved_capability_counts=tuple(sorted(unresolved_counter.items(), key=lambda item: (-item[1], item[0]))),
        selected_tool_counts=tuple(sorted(selected_counter.items(), key=lambda item: (-item[1], item[0]))),
    )


__all__ = [
    "PROMOTION_SCHEMA",
    "CapabilityBinding",
    "CapabilityCoverageReport",
    "RejectedBinding",
    "RoutePromotionResult",
    "build_coverage_report",
    "default_office_it_bindings",
    "promote_planned_route",
]
