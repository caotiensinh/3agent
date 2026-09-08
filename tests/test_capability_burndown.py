from __future__ import annotations

import unittest
from pathlib import Path

from three_agent.diagnostics.capability_burndown import (
    CAPABILITY_BURNDOWN_SCHEMA,
    build_capability_burndown_plan,
    one_step_closure_candidates,
)
from three_agent.diagnostics.capability_promotion import (
    CapabilityBinding,
    build_coverage_report,
)
from three_agent.diagnostics.catalog_compiler import (
    PlannedDiagnosticRoute,
    compile_planned_routes,
)
from three_agent.diagnostics.runtime_registry import (
    default_runtime_capability_bindings,
    runtime_micro_tool_registry,
)


class CapabilityBurndownPlannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = Path(__file__).resolve().parents[1]
        cls.routes = compile_planned_routes(
            (
                root / "docs" / "OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_1.md",
                root / "docs" / "OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_2_EXPANSION.md",
                root / "docs" / "OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_3_EXPANSION.md",
            )
        )
        cls.registry = runtime_micro_tool_registry()
        cls.bindings = default_runtime_capability_bindings()
        cls.plan = build_capability_burndown_plan(
            cls.routes,
            cls.registry,
            bindings=cls.bindings,
        )

    def test_plan_is_planning_only_and_matches_current_coverage_report(self) -> None:
        coverage = build_coverage_report(
            self.routes,
            self.registry,
            bindings=self.bindings,
        )
        self.assertEqual(self.plan.schema_version, CAPABILITY_BURNDOWN_SCHEMA)
        self.assertFalse(self.plan.execution_enabled)
        self.assertEqual(self.plan.selection_authority, "none")
        self.assertEqual(self.plan.total_routes, coverage.total_routes)
        self.assertEqual(self.plan.fully_promotable_routes, coverage.fully_promotable_routes)
        self.assertEqual(self.plan.partially_covered_routes, coverage.partially_covered_routes)
        self.assertEqual(self.plan.uncovered_routes, coverage.uncovered_routes)
        self.assertEqual(
            self.plan.fully_promotable_routes
            + self.plan.partially_covered_routes
            + self.plan.uncovered_routes,
            self.plan.total_routes,
        )

    def test_raw_frequency_cannot_outrank_real_one_step_route_closure(self) -> None:
        routes = (
            self._fixture_route("IT-9001", ("covered", "high.frequency", "other.blocker")),
            self._fixture_route("IT-9002", ("covered", "high.frequency", "other.blocker")),
            self._fixture_route("IT-9003", ("covered", "high.frequency", "other.blocker")),
            self._fixture_route("IT-9004", ("covered", "closer")),
            self._fixture_route("IT-9005", ("covered", "closer")),
        )
        plan = build_capability_burndown_plan(
            routes,
            self.registry,
            bindings=(CapabilityBinding("covered", ("system.platform.identify",)),),
        )
        by_capability = {item.capability_tag: item for item in plan.items}
        high_frequency = by_capability["high.frequency"]
        closer = by_capability["closer"]

        self.assertEqual(high_frequency.unresolved_route_count, 3)
        self.assertEqual(high_frequency.one_step_unlock_routes, 0)
        self.assertEqual(high_frequency.minimum_unresolved_capabilities, 2)
        self.assertEqual(closer.unresolved_route_count, 2)
        self.assertEqual(closer.one_step_unlock_routes, 2)
        self.assertEqual(closer.minimum_unresolved_capabilities, 1)
        self.assertEqual(plan.items[0].capability_tag, "closer")
        self.assertEqual(
            tuple(item.capability_tag for item in one_step_closure_candidates(plan)),
            ("closer",),
        )

    def test_one_step_credit_requires_no_rejected_binding(self) -> None:
        route = self._fixture_route("IT-9010", ("mixed.covered", "closer"))
        plan = build_capability_burndown_plan(
            (route,),
            self.registry,
            bindings=(
                CapabilityBinding(
                    "mixed.covered",
                    ("system.platform.identify", "diagnostic.unknown.fixture"),
                ),
            ),
        )
        by_capability = {item.capability_tag: item for item in plan.items}
        self.assertEqual(by_capability["closer"].minimum_unresolved_capabilities, 1)
        self.assertEqual(by_capability["closer"].one_step_unlock_routes, 0)
        self.assertEqual(one_step_closure_candidates(plan), ())

    def test_current_output_order_is_deterministic_under_input_reversal(self) -> None:
        second = build_capability_burndown_plan(
            reversed(self.routes),
            self.registry,
            bindings=reversed(self.bindings),
        )
        self.assertEqual(self.plan, second)

    def test_sort_key_is_monotonic(self) -> None:
        keys = tuple(
            (
                -item.one_step_unlock_routes,
                item.minimum_unresolved_capabilities,
                -item.unresolved_route_count,
                item.capability_tag,
            )
            for item in self.plan.items
        )
        self.assertEqual(keys, tuple(sorted(keys)))

    def test_external_network_flag_requires_boolean(self) -> None:
        with self.assertRaises(ValueError):
            build_capability_burndown_plan(
                self.routes,
                self.registry,
                bindings=self.bindings,
                allow_external_network=1,  # type: ignore[arg-type]
            )

    def test_implemented_capabilities_are_not_reported_as_missing(self) -> None:
        tags = {item.capability_tag for item in self.plan.items}
        for implemented in (
            "storage.io",
            "print.driver",
            "windows.boot",
            "windows.update",
            "network.reachability",
            "network.quality",
            "identity.session",
        ):
            self.assertNotIn(implemented, tags)

    @staticmethod
    def _fixture_route(
        route_id: str,
        capability_tags: tuple[str, ...],
    ) -> PlannedDiagnosticRoute:
        return PlannedDiagnosticRoute(
            route_id=route_id,
            domain_id="lan_wifi",
            canonical_symptom=f"fixture {route_id}",
            clarification_question_ids=(),
            evidence_capability_tags=capability_tags,
            physical_verification_possible=False,
        ).validate()


if __name__ == "__main__":
    unittest.main()
