from __future__ import annotations

import unittest

from three_agent.adaptive_diagnostic_router import office_it_micro_tool_registry
from three_agent.diagnostics.capability_promotion import (
    CapabilityBinding,
    build_coverage_report,
    default_office_it_bindings,
    promote_planned_route,
)
from three_agent.diagnostics.catalog_compiler import PlannedDiagnosticRoute
from three_agent.micro_tool_registry import MicroToolRegistry, ToolMetadata


class DiagnosticCapabilityPromotionTests(unittest.TestCase):
    def _route(self, *tags: str) -> PlannedDiagnosticRoute:
        return PlannedDiagnosticRoute(
            route_id="IT-0101",
            domain_id="printing",
            canonical_symptom="Printer shows offline",
            clarification_question_ids=("scope.others_affected",),
            evidence_capability_tags=tuple(tags),
            physical_verification_possible=True,
        ).validate()

    def test_minimal_existing_capability_can_be_promoted_without_execution(self) -> None:
        result = promote_planned_route(
            self._route("print.queue"),
            office_it_micro_tool_registry(),
            bindings=default_office_it_bindings(),
        )
        self.assertTrue(result.promotable)
        self.assertEqual(result.selected_tool_ids, ("windows.printer.queue",))
        self.assertEqual(result.unresolved_capability_tags, ())

    def test_realistic_printing_route_remains_partial_until_missing_tools_exist(self) -> None:
        result = promote_planned_route(
            self._route("print.queue", "print.driver", "print.port", "network.reachability"),
            office_it_micro_tool_registry(),
            bindings=default_office_it_bindings(),
        )
        self.assertFalse(result.promotable)
        self.assertIn("windows.printer.queue", result.selected_tool_ids)
        self.assertIn("network.printer.ipp_probe", result.selected_tool_ids)
        self.assertIn("network.printer.raw_probe", result.selected_tool_ids)
        self.assertEqual(
            set(result.unresolved_capability_tags),
            {"print.driver", "network.reachability"},
        )

    def test_unknown_tool_binding_fails_closed(self) -> None:
        result = promote_planned_route(
            self._route("print.queue"),
            office_it_micro_tool_registry(),
            bindings=(CapabilityBinding("print.queue", ("missing.tool",)),),
        )
        self.assertFalse(result.promotable)
        self.assertEqual(result.unresolved_capability_tags, ("print.queue",))
        self.assertEqual(result.rejected_bindings[0].reason_code, "UNKNOWN_TOOL")

    def test_mutating_tool_binding_is_rejected(self) -> None:
        registry = MicroToolRegistry(
            (
                ToolMetadata(
                    id="test.restart.service",
                    platform="any",
                    category="test",
                    keywords=("test",),
                    cost="C1",
                    risk="write",
                    requires_admin=True,
                    network_access="none",
                    sensitive_outputs=False,
                    effect="write",
                ),
            )
        )
        result = promote_planned_route(
            self._route("print.queue"),
            registry,
            bindings=(CapabilityBinding("print.queue", ("test.restart.service",)),),
        )
        self.assertFalse(result.promotable)
        self.assertEqual(result.rejected_bindings[0].reason_code, "NON_DIAGNOSTIC_EFFECT")

    def test_external_egress_binding_is_disabled_by_default(self) -> None:
        registry = MicroToolRegistry(
            (
                ToolMetadata(
                    id="test.external.read",
                    platform="any",
                    category="test",
                    keywords=("test",),
                    cost="C1",
                    risk="read_only",
                    requires_admin=False,
                    network_access="allowlisted_egress",
                    sensitive_outputs=False,
                    effect="network_read",
                ),
            )
        )
        result = promote_planned_route(
            self._route("print.queue"),
            registry,
            bindings=(CapabilityBinding("print.queue", ("test.external.read",)),),
        )
        self.assertFalse(result.promotable)
        self.assertEqual(result.rejected_bindings[0].reason_code, "EXTERNAL_EGRESS_DISABLED")

    def test_duplicate_capability_bindings_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate capability binding"):
            promote_planned_route(
                self._route("print.queue"),
                office_it_micro_tool_registry(),
                bindings=(
                    CapabilityBinding("print.queue", ("windows.printer.queue",)),
                    CapabilityBinding("print.queue", ("windows.printer.queue",)),
                ),
            )

    def test_coverage_report_counts_full_partial_and_uncovered_routes(self) -> None:
        routes = (
            self._route("print.queue"),
            self._route("print.queue", "print.driver"),
            self._route("print.driver"),
        )
        report = build_coverage_report(
            routes,
            office_it_micro_tool_registry(),
            bindings=default_office_it_bindings(),
        )
        self.assertEqual(report.total_routes, 3)
        self.assertEqual(report.fully_promotable_routes, 1)
        self.assertEqual(report.partially_covered_routes, 1)
        self.assertEqual(report.uncovered_routes, 1)
        self.assertIn(("print.driver", 2), report.unresolved_capability_counts)

    def test_promotion_never_changes_planned_route_execution_flag(self) -> None:
        route = self._route("print.queue")
        self.assertFalse(route.execution_enabled)
        promote_planned_route(
            route,
            office_it_micro_tool_registry(),
            bindings=default_office_it_bindings(),
        )
        self.assertFalse(route.execution_enabled)


if __name__ == "__main__":
    unittest.main()
