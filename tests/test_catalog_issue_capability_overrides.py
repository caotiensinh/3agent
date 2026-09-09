from __future__ import annotations

import unittest
from pathlib import Path

from three_agent.diagnostics.capability_promotion import promote_planned_route
from three_agent.diagnostics.catalog_compiler import compile_planned_routes
from three_agent.diagnostics.runtime_registry import (
    default_runtime_capability_bindings,
    runtime_micro_tool_registry,
)


class CatalogIssueCapabilityOverrideTests(unittest.TestCase):
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
        cls.by_id = {route.route_id: route for route in cls.routes}
        cls.registry = runtime_micro_tool_registry()
        cls.bindings = default_runtime_capability_bindings()

    def test_narrow_server_observation_routes_do_not_require_backup_status(self) -> None:
        expected = {
            "IT-0303": ("service.status",),
            "IT-0304": ("server.resources", "process.top"),
            "IT-0305": ("server.resources", "process.top"),
            "IT-0306": ("storage.capacity",),
            "IT-0320": ("time.sync",),
        }
        for route_id, tags in expected.items():
            with self.subTest(route_id=route_id):
                route = self.by_id[route_id]
                self.assertEqual(route.domain_id, "server_backup")
                self.assertEqual(route.evidence_capability_tags, tags)
                self.assertNotIn("backup.status", route.evidence_capability_tags)
                self.assertFalse(route.execution_enabled)

    def test_backup_specific_routes_keep_conservative_backup_requirement(self) -> None:
        for route_id in ("IT-0313", "IT-0314", "IT-0315", "IT-0316", "IT-0317", "IT-0318"):
            with self.subTest(route_id=route_id):
                tags = self.by_id[route_id].evidence_capability_tags
                self.assertIn("backup.status", tags)
                self.assertIn("service.status", tags)
                self.assertIn("storage.capacity", tags)

    def test_narrow_server_routes_are_promotable_with_existing_runtime_only(self) -> None:
        for route_id in ("IT-0303", "IT-0304", "IT-0305", "IT-0306", "IT-0320"):
            with self.subTest(route_id=route_id):
                result = promote_planned_route(
                    self.by_id[route_id],
                    self.registry,
                    bindings=self.bindings,
                )
                self.assertTrue(
                    result.promotable,
                    (route_id, result.unresolved_capability_tags, result.rejected_bindings),
                )

    def test_unrelated_server_routes_still_use_conservative_domain_profile(self) -> None:
        self.assertEqual(
            self.by_id["IT-0301"].evidence_capability_tags,
            ("server.resources", "service.status", "storage.capacity", "backup.status"),
        )
        self.assertEqual(
            self.by_id["IT-0319"].evidence_capability_tags,
            ("server.resources", "service.status", "storage.capacity", "backup.status"),
        )


if __name__ == "__main__":
    unittest.main()
