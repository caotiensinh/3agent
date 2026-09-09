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
from three_agent.task_contract import DIAGNOSTIC_STAGED_LOCAL_READ_TOOLS


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

    def test_runtime_registry_contains_unique_atomic_tools_and_staged_wave1_evidence(self) -> None:
        metadata = runtime_tool_metadata()
        runtime_ids = {tool.id for tool in metadata}
        self.assertEqual(len(metadata), len(runtime_ids))
        self.assertEqual(len(runtime_micro_tool_registry().metadata_view()), len(metadata))
        self.assertTrue(DIAGNOSTIC_STAGED_LOCAL_READ_TOOLS.issubset(runtime_ids))

    def test_runtime_registry_contains_no_external_egress_capability(self) -> None:
        self.assertTrue(
            all(tool.network_access != "allowlisted_egress" for tool in runtime_tool_metadata())
        )

    def test_runtime_network_bindings_use_only_dedicated_internal_probes(self) -> None:
        mapping = {
            binding.capability_tag: binding.tool_ids
            for binding in default_runtime_capability_bindings()
        }
        self.assertEqual(
            mapping["network.reachability"],
            ("network.reachability.internal",),
        )
        self.assertEqual(
            mapping["network.quality"],
            ("network.quality.internal",),
        )
        self.assertNotIn("camera.reachability", mapping)
        self.assertNotIn("isp.reachability", mapping)

    def test_runtime_bindings_reuse_common_and_domain_completion_tools(self) -> None:
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
        self.assertEqual(mapping["identity.session"], ("identity.session.snapshot",))
        self.assertEqual(mapping["audio.devices"], ("audio.devices.snapshot",))
        self.assertEqual(mapping["meeting.client"], ("meeting.client.snapshot",))
        self.assertEqual(mapping["process.top"], ("process.top.snapshot",))
        self.assertEqual(mapping["hardware.usb"], ("hardware.usb.snapshot",))
        self.assertEqual(mapping["camera.devices"], ("camera.devices.snapshot",))
        self.assertEqual(mapping["storage.io"], ("storage.io.snapshot",))
        self.assertEqual(mapping["print.driver"], ("windows.print.driver.snapshot",))
        self.assertEqual(mapping["windows.boot"], ("windows.boot.snapshot",))
        self.assertEqual(mapping["windows.update"], ("windows.update.history",))
        self.assertEqual(mapping["vpn.status"], ("vpn.status.snapshot",))

    def test_650_route_coverage_report_reaches_one_hundred_thirty_fully_promotable_routes(self) -> None:
        report = build_coverage_report(
            self.routes,
            runtime_micro_tool_registry(),
            bindings=default_runtime_capability_bindings(),
        )
        self.assertEqual(report.total_routes, 650)
        self.assertEqual(report.fully_promotable_routes, 130)
        self.assertEqual(report.partially_covered_routes, 170)
        self.assertEqual(report.uncovered_routes, 350)
        self.assertEqual(
            report.fully_promotable_routes
            + report.partially_covered_routes
            + report.uncovered_routes,
            650,
        )
        self.assertLess(report.fully_promotable_routes, 650)
        self.assertTrue(report.unresolved_capability_counts)

    def test_implemented_high_reuse_capabilities_are_removed_from_missing_backlog(self) -> None:
        report = build_coverage_report(
            self.routes,
            runtime_micro_tool_registry(),
            bindings=default_runtime_capability_bindings(),
        )
        missing = dict(report.unresolved_capability_counts)
        for capability in (
            "network.reachability",
            "network.quality",
            "group_policy",
            "identity.session",
            "audio.devices",
            "meeting.client",
            "process.top",
            "hardware.usb",
            "camera.devices",
            "storage.io",
            "print.driver",
            "windows.boot",
            "windows.update",
            "vpn.status",
        ):
            self.assertNotIn(capability, missing)
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
        self.assertEqual(selected.get("identity.session.snapshot"), 35)
        self.assertEqual(selected.get("network.quality.internal"), 35)
        self.assertEqual(selected.get("audio.devices.snapshot"), 35)
        self.assertEqual(selected.get("meeting.client.snapshot"), 20)
        self.assertEqual(selected.get("process.top.snapshot"), 22)
        self.assertEqual(selected.get("hardware.usb.snapshot"), 20)
        self.assertEqual(selected.get("camera.devices.snapshot"), 20)
        self.assertEqual(selected.get("storage.io.snapshot"), 20)
        self.assertEqual(selected.get("windows.print.driver.snapshot"), 20)
        self.assertEqual(selected.get("windows.boot.snapshot"), 20)
        self.assertEqual(selected.get("windows.update.history"), 20)
        self.assertEqual(selected.get("vpn.status.snapshot"), 20)

    def test_backlog_limit_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            unresolved_capability_backlog((("x", 1),), limit=0)


if __name__ == "__main__":
    unittest.main()
