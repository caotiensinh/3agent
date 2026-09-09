from __future__ import annotations

import unittest
from pathlib import Path

from three_agent.diagnostics.capability_burndown import (
    CapabilityBundleBurndownItem,
    build_capability_bundle_candidates,
)
from three_agent.diagnostics.capability_promotion import CapabilityBinding
from three_agent.diagnostics.catalog_compiler import (
    PlannedDiagnosticRoute,
    compile_planned_routes,
)
from three_agent.diagnostics.runtime_registry import (
    default_runtime_capability_bindings,
    runtime_micro_tool_registry,
)


class CapabilityBundleBurndownTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = runtime_micro_tool_registry()
        root = Path(__file__).resolve().parents[1]
        cls.routes = compile_planned_routes(
            (
                root / "docs" / "OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_1.md",
                root / "docs" / "OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_2_EXPANSION.md",
                root / "docs" / "OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_3_EXPANSION.md",
            )
        )
        cls.bindings = default_runtime_capability_bindings()

    def test_groups_only_exact_multi_capability_gaps(self) -> None:
        routes = (
            self._route("IT-9101", "alpha", ("covered", "x", "y")),
            self._route("IT-9102", "beta", ("covered", "y", "x")),
            self._route("IT-9103", "alpha", ("covered", "x", "z")),
            self._route("IT-9104", "alpha", ("covered", "single")),
        )
        items = build_capability_bundle_candidates(
            routes,
            self.registry,
            bindings=(CapabilityBinding("covered", ("system.platform.identify",)),),
        )
        by_tags = {item.capability_tags: item for item in items}

        self.assertEqual(set(by_tags), {("x", "y"), ("x", "z")})
        self.assertEqual(by_tags[("x", "y")].route_unlock_count, 2)
        self.assertEqual(by_tags[("x", "y")].affected_domain_ids, ("alpha", "beta"))
        self.assertEqual(by_tags[("x", "y")].capability_count, 2)
        self.assertEqual(by_tags[("x", "y")].closure_efficiency.numerator, 1)
        self.assertEqual(by_tags[("x", "y")].closure_efficiency.denominator, 1)

    def test_rejected_binding_routes_receive_no_bundle_credit(self) -> None:
        route = self._route("IT-9110", "alpha", ("mixed.covered", "x", "y"))
        items = build_capability_bundle_candidates(
            (route,),
            self.registry,
            bindings=(
                CapabilityBinding(
                    "mixed.covered",
                    ("system.platform.identify", "diagnostic.unknown.fixture"),
                ),
            ),
        )
        self.assertEqual(items, ())

    def test_ranking_uses_routes_closed_per_capability_before_raw_frequency(self) -> None:
        routes = tuple(
            [self._route(f"IT-92{i:02d}", "alpha", ("covered", "a", "b")) for i in range(1, 5)]
            + [
                self._route(f"IT-93{i:02d}", "beta", ("covered", "c", "d", "e"))
                for i in range(1, 6)
            ]
        )
        items = build_capability_bundle_candidates(
            routes,
            self.registry,
            bindings=(CapabilityBinding("covered", ("system.platform.identify",)),),
        )

        self.assertEqual(items[0].capability_tags, ("a", "b"))
        self.assertEqual(items[0].route_unlock_count, 4)
        self.assertEqual(items[1].capability_tags, ("c", "d", "e"))
        self.assertEqual(items[1].route_unlock_count, 5)

    def test_output_is_deterministic_under_input_reversal(self) -> None:
        forward = build_capability_bundle_candidates(
            self.routes,
            self.registry,
            bindings=self.bindings,
        )
        reverse = build_capability_bundle_candidates(
            reversed(self.routes),
            self.registry,
            bindings=reversed(self.bindings),
        )
        self.assertEqual(forward, reverse)
        for item in forward:
            self.assertFalse(item.execution_enabled)
            self.assertEqual(item.selection_authority, "none")

    def test_bundle_item_rejects_single_capability_or_authority_widening(self) -> None:
        with self.assertRaises(ValueError):
            CapabilityBundleBurndownItem(
                capability_tags=("only",),
                route_unlock_count=1,
                affected_domain_ids=("alpha",),
            ).validate()
        with self.assertRaises(ValueError):
            CapabilityBundleBurndownItem(
                capability_tags=("a", "b"),
                route_unlock_count=1,
                affected_domain_ids=("alpha",),
                selection_authority="auto",
            ).validate()

    @staticmethod
    def _route(
        route_id: str,
        domain_id: str,
        capability_tags: tuple[str, ...],
    ) -> PlannedDiagnosticRoute:
        return PlannedDiagnosticRoute(
            route_id=route_id,
            domain_id=domain_id,
            canonical_symptom=f"fixture {route_id}",
            clarification_question_ids=(),
            evidence_capability_tags=capability_tags,
            physical_verification_possible=False,
        ).validate()


if __name__ == "__main__":
    unittest.main()
