from __future__ import annotations

import unittest
from pathlib import Path

from three_agent.diagnostics.capability_burndown import (
    CAPABILITY_BURNDOWN_SCHEMA,
    build_capability_burndown_plan,
    one_step_closure_candidates,
)
from three_agent.diagnostics.catalog_compiler import compile_planned_routes
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
        cls.plan = build_capability_burndown_plan(
            cls.routes,
            runtime_micro_tool_registry(),
            bindings=default_runtime_capability_bindings(),
        )

    def test_plan_is_planning_only_and_matches_current_650_route_coverage(self) -> None:
        self.assertEqual(self.plan.schema_version, CAPABILITY_BURNDOWN_SCHEMA)
        self.assertFalse(self.plan.execution_enabled)
        self.assertEqual(self.plan.selection_authority, "none")
        self.assertEqual(self.plan.total_routes, 650)
        self.assertEqual(self.plan.fully_promotable_routes, 85)
        self.assertEqual(
            self.plan.fully_promotable_routes
            + self.plan.partially_covered_routes
            + self.plan.uncovered_routes,
            650,
        )

    def test_one_step_candidates_prioritize_route_closure_not_raw_frequency(self) -> None:
        candidates = one_step_closure_candidates(self.plan)
        first_four = tuple(item.capability_tag for item in candidates[:4])
        self.assertEqual(
            first_four,
            (
                "backup.status",
                "identity.account_state",
                "meeting.client",
                "vpn.status",
            ),
        )
        for item in candidates[:4]:
            self.assertEqual(item.one_step_unlock_routes, 20)
            self.assertEqual(item.minimum_unresolved_capabilities, 1)
            self.assertEqual(item.unresolved_route_count, 20)

    def test_service_health_high_frequency_does_not_gain_false_one_step_credit(self) -> None:
        by_capability = {item.capability_tag: item for item in self.plan.items}
        service_health = by_capability["service.health"]
        self.assertEqual(service_health.unresolved_route_count, 55)
        self.assertEqual(service_health.one_step_unlock_routes, 0)
        self.assertGreater(service_health.minimum_unresolved_capabilities, 1)

        candidate_tags = {
            item.capability_tag for item in one_step_closure_candidates(self.plan)
        }
        self.assertNotIn("service.health", candidate_tags)

    def test_one_step_domains_are_explicit_and_bounded(self) -> None:
        by_capability = {item.capability_tag: item for item in self.plan.items}
        self.assertEqual(
            by_capability["meeting.client"].one_step_domain_ids,
            ("meeting_collaboration",),
        )
        self.assertEqual(
            by_capability["vpn.status"].one_step_domain_ids,
            ("vpn_remote",),
        )
        self.assertEqual(
            by_capability["backup.status"].one_step_domain_ids,
            ("server_backup",),
        )
        self.assertEqual(
            by_capability["identity.account_state"].one_step_domain_ids,
            ("identity_auth",),
        )

    def test_order_is_deterministic(self) -> None:
        second = build_capability_burndown_plan(
            reversed(self.routes),
            runtime_micro_tool_registry(),
            bindings=reversed(default_runtime_capability_bindings()),
        )
        self.assertEqual(self.plan, second)

    def test_external_network_flag_requires_boolean(self) -> None:
        with self.assertRaises(ValueError):
            build_capability_burndown_plan(
                self.routes,
                runtime_micro_tool_registry(),
                bindings=default_runtime_capability_bindings(),
                allow_external_network=1,  # type: ignore[arg-type]
            )

    def test_burndown_output_never_contains_implemented_capability_as_missing(self) -> None:
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


if __name__ == "__main__":
    unittest.main()
