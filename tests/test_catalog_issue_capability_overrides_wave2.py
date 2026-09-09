from __future__ import annotations

import unittest
from pathlib import Path

from three_agent.diagnostics.capability_promotion import promote_planned_route
from three_agent.diagnostics.catalog_compiler import compile_planned_routes
from three_agent.diagnostics.runtime_registry import (
    default_runtime_capability_bindings,
    runtime_micro_tool_registry,
)


WAVE2_EXPECTED = {
    "IT-0017": ("vpn.status", "network.route", "network.dns", "time.sync"),
    "IT-0075": ("camera.devices",),
    "IT-0076": ("audio.devices",),
    "IT-0088": ("hardware.usb", "network.interface"),
    "IT-0090": ("hardware.usb", "audio.devices"),
    "IT-0097": ("hardware.usb",),
    "IT-0230": ("network.dns",),
    "IT-0243": ("group_policy",),
    "IT-0260": ("vpn.status", "network.route", "network.dns", "network.reachability"),
    "IT-0325": ("audio.devices", "network.quality"),
    "IT-0330": ("audio.devices",),
    "IT-0331": ("audio.devices",),
}

NEIGHBOR_DEFAULTS = {
    "IT-0016": ("identity.session", "identity.account_state", "time.sync"),
    "IT-0077": (
        "hardware.power",
        "hardware.battery",
        "hardware.thermal",
        "hardware.storage_health",
    ),
    "IT-0087": ("hardware.usb", "hardware.display", "hardware.dock", "driver.inventory"),
    "IT-0231": ("smb.mounts", "smb.permissions", "network.dns", "group_policy"),
    "IT-0259": (
        "application.process",
        "application.events",
        "application.version",
        "license.state",
    ),
    "IT-0301": ("server.resources", "service.status", "storage.capacity", "backup.status"),
    "IT-0302": ("server.resources", "service.status", "storage.capacity", "backup.status"),
    "IT-0311": ("server.resources", "service.status", "storage.capacity", "backup.status"),
    "IT-0324": ("voip.registration", "audio.devices", "network.quality", "network.nat"),
}

UNSUPPORTED_BROAD_TAGS = frozenset(
    {
        "backup.status",
        "cloud.sync",
        "cloud.permissions",
        "identity.account_state",
        "mail.client",
        "mail.account",
        "service.health",
        "voip.registration",
        "network.nat",
    }
)


class CatalogIssueCapabilityOverridesWave2Tests(unittest.TestCase):
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

    def test_wave2_overrides_are_exact_and_execution_remains_disabled(self) -> None:
        for route_id, expected_tags in WAVE2_EXPECTED.items():
            with self.subTest(route_id=route_id):
                route = self.by_id[route_id]
                self.assertEqual(route.evidence_capability_tags, expected_tags)
                self.assertFalse(route.execution_enabled)
                self.assertTrue(
                    UNSUPPORTED_BROAD_TAGS.isdisjoint(route.evidence_capability_tags),
                    (route_id, route.evidence_capability_tags),
                )

    def test_wave2_overrides_are_promotable_with_existing_runtime_only(self) -> None:
        for route_id in WAVE2_EXPECTED:
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
                self.assertTrue(result.selected_tool_ids)

    def test_neighboring_and_broad_routes_keep_conservative_domain_defaults(self) -> None:
        for route_id, expected_tags in NEIGHBOR_DEFAULTS.items():
            with self.subTest(route_id=route_id):
                route = self.by_id[route_id]
                self.assertEqual(route.evidence_capability_tags, expected_tags)
                self.assertFalse(route.execution_enabled)

    def test_wave2_does_not_add_new_route_capability_bindings(self) -> None:
        binding_tags = {binding.capability_tag for binding in self.bindings}
        for expected_tags in WAVE2_EXPECTED.values():
            self.assertTrue(set(expected_tags).issubset(binding_tags))
        for broad_tag in UNSUPPORTED_BROAD_TAGS:
            self.assertNotIn(broad_tag, binding_tags)


if __name__ == "__main__":
    unittest.main()
