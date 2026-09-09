from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Iterable

from ..micro_tool_registry import MicroToolRegistry
from .capability_promotion import (
    CapabilityBinding,
    build_coverage_report,
    promote_planned_route,
)
from .catalog_compiler import PlannedDiagnosticRoute

CAPABILITY_BURNDOWN_SCHEMA = "workspace-diagnostic-capability-burndown/v1"


@dataclass(frozen=True)
class CapabilityBurndownItem:
    """Planning-only view of one unresolved diagnostic capability.

    Counts describe route-coverage opportunity only. They do not imply that a safe
    implementation exists and never grant tool, network, write, or execution authority.
    """

    capability_tag: str
    unresolved_route_count: int
    one_step_unlock_routes: int
    minimum_unresolved_capabilities: int
    affected_domain_ids: tuple[str, ...]
    one_step_domain_ids: tuple[str, ...]
    execution_enabled: bool = False
    schema_version: str = CAPABILITY_BURNDOWN_SCHEMA

    def validate(self) -> "CapabilityBurndownItem":
        if self.schema_version != CAPABILITY_BURNDOWN_SCHEMA:
            raise ValueError(f"unsupported capability burn-down schema: {self.schema_version}")
        if not self.capability_tag.strip():
            raise ValueError("capability_tag is required")
        if self.unresolved_route_count < 1:
            raise ValueError("unresolved_route_count must be positive")
        if not 0 <= self.one_step_unlock_routes <= self.unresolved_route_count:
            raise ValueError("one_step_unlock_routes must be within unresolved route count")
        if self.minimum_unresolved_capabilities < 1:
            raise ValueError("minimum_unresolved_capabilities must be positive")
        if not self.affected_domain_ids:
            raise ValueError("affected_domain_ids is required")
        if not set(self.one_step_domain_ids).issubset(self.affected_domain_ids):
            raise ValueError("one_step_domain_ids must be a subset of affected_domain_ids")
        if self.execution_enabled is not False:
            raise ValueError("capability burn-down items cannot enable execution")
        return self


@dataclass(frozen=True)
class CapabilityBundleBurndownItem:
    """Planning-only view of an exact unresolved capability bundle.

    Every counted route has exactly this unresolved capability set and no rejected
    binding. Implementing the entire bundle would therefore make those routes eligible
    for promotion under the same registry/binding inputs. The item does not select an
    implementation, grant authority, or claim that the bundle is safe to build.
    """

    capability_tags: tuple[str, ...]
    route_unlock_count: int
    affected_domain_ids: tuple[str, ...]
    execution_enabled: bool = False
    selection_authority: str = "none"
    schema_version: str = CAPABILITY_BURNDOWN_SCHEMA

    def validate(self) -> "CapabilityBundleBurndownItem":
        if self.schema_version != CAPABILITY_BURNDOWN_SCHEMA:
            raise ValueError(f"unsupported capability burn-down schema: {self.schema_version}")
        if len(self.capability_tags) < 2:
            raise ValueError("capability bundle must contain at least two capabilities")
        if tuple(sorted(set(self.capability_tags))) != self.capability_tags:
            raise ValueError("capability bundle tags must be unique and sorted")
        if not all(tag.strip() for tag in self.capability_tags):
            raise ValueError("capability bundle tags cannot be blank")
        if self.route_unlock_count < 1:
            raise ValueError("route_unlock_count must be positive")
        if not self.affected_domain_ids:
            raise ValueError("affected_domain_ids is required")
        if self.execution_enabled is not False:
            raise ValueError("capability bundle items cannot enable execution")
        if self.selection_authority != "none":
            raise ValueError("capability bundle items cannot grant selection authority")
        return self

    @property
    def capability_count(self) -> int:
        return len(self.capability_tags)

    @property
    def closure_efficiency(self) -> Fraction:
        """Exact routes-closed-per-capability ratio for deterministic ranking."""

        return Fraction(self.route_unlock_count, self.capability_count)


@dataclass(frozen=True)
class CapabilityBurndownPlan:
    """Deterministic route-closure backlog over the current diagnostic runtime."""

    total_routes: int
    fully_promotable_routes: int
    partially_covered_routes: int
    uncovered_routes: int
    items: tuple[CapabilityBurndownItem, ...]
    execution_enabled: bool = False
    selection_authority: str = "none"
    schema_version: str = CAPABILITY_BURNDOWN_SCHEMA

    def validate(self) -> "CapabilityBurndownPlan":
        if self.schema_version != CAPABILITY_BURNDOWN_SCHEMA:
            raise ValueError(f"unsupported capability burn-down schema: {self.schema_version}")
        if min(
            self.total_routes,
            self.fully_promotable_routes,
            self.partially_covered_routes,
            self.uncovered_routes,
        ) < 0:
            raise ValueError("route counts cannot be negative")
        if (
            self.fully_promotable_routes
            + self.partially_covered_routes
            + self.uncovered_routes
            != self.total_routes
        ):
            raise ValueError("coverage route counts must sum to total_routes")
        if self.execution_enabled is not False:
            raise ValueError("capability burn-down plans cannot enable execution")
        if self.selection_authority != "none":
            raise ValueError("capability burn-down plans cannot grant selection authority")
        seen: set[str] = set()
        for item in self.items:
            item.validate()
            if item.capability_tag in seen:
                raise ValueError(f"duplicate burn-down capability: {item.capability_tag}")
            seen.add(item.capability_tag)
        return self


@dataclass
class _Accumulator:
    unresolved_route_count: int = 0
    one_step_unlock_routes: int = 0
    minimum_unresolved_capabilities: int | None = None
    affected_domain_ids: set[str] | None = None
    one_step_domain_ids: set[str] | None = None

    def __post_init__(self) -> None:
        if self.affected_domain_ids is None:
            self.affected_domain_ids = set()
        if self.one_step_domain_ids is None:
            self.one_step_domain_ids = set()


@dataclass
class _BundleAccumulator:
    route_unlock_count: int = 0
    affected_domain_ids: set[str] | None = None

    def __post_init__(self) -> None:
        if self.affected_domain_ids is None:
            self.affected_domain_ids = set()


def build_capability_burndown_plan(
    routes: Iterable[PlannedDiagnosticRoute],
    registry: MicroToolRegistry,
    *,
    bindings: Iterable[CapabilityBinding],
    allow_external_network: bool = False,
) -> CapabilityBurndownPlan:
    """Rank unresolved capabilities by deterministic route-closure leverage.

    Priority deliberately differs from raw occurrence count. A capability receives
    one-step unlock credit only when it is the route's sole unresolved capability and
    the route has no rejected binding. This prevents a high-frequency capability from
    looking valuable when other blockers would still keep every affected route closed.

    The result is planning metadata only. It does not prove implementation safety,
    choose a concrete tool, enable external egress, or grant TaskCapabilityAuthority.
    """

    if type(allow_external_network) is not bool:
        raise ValueError("allow_external_network must be boolean")

    route_items = tuple(routes)
    bindings_tuple = tuple(bindings)
    coverage = build_coverage_report(
        route_items,
        registry,
        bindings=bindings_tuple,
        allow_external_network=allow_external_network,
    )

    accumulators: dict[str, _Accumulator] = {}
    for route in route_items:
        result = promote_planned_route(
            route,
            registry,
            bindings=bindings_tuple,
            allow_external_network=allow_external_network,
        )
        if result.promotable:
            continue

        unresolved = tuple(result.unresolved_capability_tags)
        unresolved_count = len(unresolved)
        if unresolved_count == 0:
            # A route blocked only by rejected bindings has no missing capability to
            # implement. It belongs in binding/policy RCA, not implementation backlog.
            continue
        one_step_candidate = unresolved_count == 1 and not result.rejected_bindings

        for capability_tag in unresolved:
            item = accumulators.setdefault(capability_tag, _Accumulator())
            item.unresolved_route_count += 1
            if (
                item.minimum_unresolved_capabilities is None
                or unresolved_count < item.minimum_unresolved_capabilities
            ):
                item.minimum_unresolved_capabilities = unresolved_count
            assert item.affected_domain_ids is not None
            item.affected_domain_ids.add(route.domain_id)
            if one_step_candidate:
                item.one_step_unlock_routes += 1
                assert item.one_step_domain_ids is not None
                item.one_step_domain_ids.add(route.domain_id)

    items: list[CapabilityBurndownItem] = []
    for capability_tag, accumulator in accumulators.items():
        minimum = accumulator.minimum_unresolved_capabilities
        if minimum is None:
            raise RuntimeError(f"missing unresolved-capability minimum: {capability_tag}")
        assert accumulator.affected_domain_ids is not None
        assert accumulator.one_step_domain_ids is not None
        items.append(
            CapabilityBurndownItem(
                capability_tag=capability_tag,
                unresolved_route_count=accumulator.unresolved_route_count,
                one_step_unlock_routes=accumulator.one_step_unlock_routes,
                minimum_unresolved_capabilities=minimum,
                affected_domain_ids=tuple(sorted(accumulator.affected_domain_ids)),
                one_step_domain_ids=tuple(sorted(accumulator.one_step_domain_ids)),
            ).validate()
        )

    # Route closure is the primary metric. Minimum remaining gap comes second.
    # Raw frequency is only a tiebreaker; alphabetical order makes output stable.
    ordered = tuple(
        sorted(
            items,
            key=lambda item: (
                -item.one_step_unlock_routes,
                item.minimum_unresolved_capabilities,
                -item.unresolved_route_count,
                item.capability_tag,
            ),
        )
    )
    return CapabilityBurndownPlan(
        total_routes=coverage.total_routes,
        fully_promotable_routes=coverage.fully_promotable_routes,
        partially_covered_routes=coverage.partially_covered_routes,
        uncovered_routes=coverage.uncovered_routes,
        items=ordered,
    ).validate()


def build_capability_bundle_candidates(
    routes: Iterable[PlannedDiagnosticRoute],
    registry: MicroToolRegistry,
    *,
    bindings: Iterable[CapabilityBinding],
    allow_external_network: bool = False,
) -> tuple[CapabilityBundleBurndownItem, ...]:
    """Rank exact multi-capability gaps by deterministic closure efficiency.

    Only routes with two or more unresolved capabilities and no rejected bindings are
    counted. Routes are grouped by their exact sorted unresolved set. That makes every
    `route_unlock_count` an auditable statement: implementing the complete bundle would
    remove the capability gap for exactly those routes under the same planning inputs.

    Ranking uses the exact `route_unlock_count / capability_count` ratio, then fewer
    capabilities, then higher raw route closure, then lexical tags for stable output.
    This is planning metadata only and grants no execution or selection authority.
    """

    if type(allow_external_network) is not bool:
        raise ValueError("allow_external_network must be boolean")

    bindings_tuple = tuple(bindings)
    accumulators: dict[tuple[str, ...], _BundleAccumulator] = {}
    for route in tuple(routes):
        result = promote_planned_route(
            route,
            registry,
            bindings=bindings_tuple,
            allow_external_network=allow_external_network,
        )
        if result.promotable or result.rejected_bindings:
            continue
        unresolved = tuple(sorted(set(result.unresolved_capability_tags)))
        if len(unresolved) < 2:
            continue
        item = accumulators.setdefault(unresolved, _BundleAccumulator())
        item.route_unlock_count += 1
        assert item.affected_domain_ids is not None
        item.affected_domain_ids.add(route.domain_id)

    items: list[CapabilityBundleBurndownItem] = []
    for capability_tags, accumulator in accumulators.items():
        assert accumulator.affected_domain_ids is not None
        items.append(
            CapabilityBundleBurndownItem(
                capability_tags=capability_tags,
                route_unlock_count=accumulator.route_unlock_count,
                affected_domain_ids=tuple(sorted(accumulator.affected_domain_ids)),
            ).validate()
        )

    return tuple(
        sorted(
            items,
            key=lambda item: (
                -item.closure_efficiency,
                item.capability_count,
                -item.route_unlock_count,
                item.capability_tags,
            ),
        )
    )


def one_step_closure_candidates(
    plan: CapabilityBurndownPlan,
) -> tuple[CapabilityBurndownItem, ...]:
    """Return only capabilities that can close at least one route in one step."""

    plan.validate()
    return tuple(item for item in plan.items if item.one_step_unlock_routes > 0)


__all__ = [
    "CAPABILITY_BURNDOWN_SCHEMA",
    "CapabilityBundleBurndownItem",
    "CapabilityBurndownItem",
    "CapabilityBurndownPlan",
    "build_capability_bundle_candidates",
    "build_capability_burndown_plan",
    "one_step_closure_candidates",
]
