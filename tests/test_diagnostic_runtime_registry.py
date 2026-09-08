from __future__ import annotations

import unittest
from pathlib import Path

from three_agent.diagnostics.capability_promotion import build_coverage_report
from three_agent.diagnostics.catalog_compiler import compile_planned_routes
from three_agent.diagnostics.runtime_registry import (
    default_runtime_capability_bindings,
    runtime_micro_tool_registry,
    runtime_tool_metadata,
    unresolved_capability_backlog,
)


class DiagnosticRuntimeRegistryTests(unittest.TestCase):
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

    def test_runtime_registry_combines_nineteen_atomic_tools(self) -> None:
        metadata = runtime_tool_metadata()
        self.assertEqual(len(metadata), 19)
        self.assertEqual(len({tool.id for tool in metadata}), 19)
        self.assertEqual(len(runtime_micro_tool_registry().metadata_view()), 19)

    def test_runtime_registry_contains_no_external_egress_capability(self) -> None:
        self.assertTrue(
            all(tool.network_access != "allowlisted_egress" for tool in runtime_tool_metadata())
        )

    def test_runtime_reachability_binding_uses_only_dedicated_internal_probe(self) -> None:
        mapping = {
            binding.capability_tag: binding.tool_ids
            for binding in default_runtime_capability_bindings()
        }
        self.assertEqual(
            mapping["network.reachability"],
            ("network.reachability.internal",),
        )
        self.assertNotIn("camera.reachability", mapping)
        self.assertNotIn("isp.reachability", mapping)

    def test_runtime_bindings_reuse_common_tools_across_domains(self) -> None:
        mapping = {
            binding.capability_tag: binding.tool_ids
            for binding in default_runtime_capability_bindings()
        }
        self.assertEqual(mapping["system.resources"], ("system.resource.snapshot",))
        self.assertEqual(mapping["server.resources"], ("system.resource.snapshot",))
        self.assertEqual(mapping["network.ip"], ("network.ipconfig.snapshot",))
        self.assertEqual(mapping["network.dhcp"], ("network.ipconfig.snapshot",))
        self.assertEqual(mapping["network.dns"], ("network.dns.snapshot",))
        self.assertEqual(mapping["time.sync"], ("time.sync.status",))
        self.assertEqual(mapping["group_policy"], ("windows.group_policy.result",))

    def test_650_route_coverage_report_is_explicitly_incomplete(self) -> None:
        report = build_coverage_report(
            self.routes,
            runtime_micro_tool_registry(),
            bindings=default_runtime_capability_bindings(),
        )
        self.assertEqual(report.total_routes, 650)
        self.assertEqual(
            report.fully_promotable_routes
            + report.partially_covered_routes
            + report.uncovered_routes,
            650,
        )
        self.assertGreater(report.partially_covered_routes, 0)
        self.assertGreater(report.uncovered_routes, 0)
        self.assertLess(report.fully_promotable_routes, 650)
        self.assertTrue(report.unresolved_capability_counts)

    def test_reachability_and_group_policy_are_removed_from_missing_backlog(self) -> None:
        report = build_coverage_report(
            self.routes,
            runtime_micro_tool_registry(),
            bindings=default_runtime_capability_bindings(),
        )
        missing = dict(report.unresolved_capability_counts)
        self.assertNotIn("network.reachability", missing)
        self.assertNotIn("group_policy", missing)
        self.assertIn("service.health", missing)
        self.assertGreater(missing["service.health"], 0)
        backlog = unresolved_capability_backlog(report.unresolved_capability_counts, limit=10)
        self.assertLessEqual(len(backlog), 10)
        self.assertEqual(backlog, tuple(sorted(backlog, key=lambda item: (-item[1], item[0]))))

    def test_existing_tool_usage_is_visible_in_coverage_report(self) -> None:
        report = build_coverage_report(
            self.routes,
            runtime_micro_tool_registry(),
            bindings=default_runtime_capability_bindings(),
        )
        selected = dict(report.selected_tool_counts)
        self.assertGreater(selected.get("system.resource.snapshot", 0), 0)
        self.assertGreater(selected.get("network.ipconfig.snapshot", 0), 0)
        self.assertGreater(selected.get("network.dns.snapshot", 0), 0)
        self.assertGreater(selected.get("windows.printer.queue", 0), 0)
        self.assertEqual(selected.get("network.reachability.internal"), 100)
        self.assertEqual(selected.get("windows.group_policy.result"), 45)

    def test_backlog_limit_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            unresolved_capability_backlog((("x", 1),), limit=0)


if __name__ == "__main__":
    unittest.main()
