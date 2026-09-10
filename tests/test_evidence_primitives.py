from __future__ import annotations

import unittest

from three_agent.diagnostics.evidence_primitives import (
    EvidencePrimitive,
    default_evidence_primitives,
    evidence_primitive_by_id,
)
from three_agent.diagnostics.runtime_registry import runtime_micro_tool_registry


class EvidencePrimitiveRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = runtime_micro_tool_registry()

    def test_default_primitives_reference_only_existing_local_read_tools(self) -> None:
        items = default_evidence_primitives(self.registry)
        self.assertGreaterEqual(len(items), 8)
        self.assertEqual(
            tuple(item.primitive_id for item in items),
            tuple(sorted(item.primitive_id for item in items)),
        )
        for item in items:
            self.assertFalse(item.execution_enabled)
            self.assertEqual(item.selection_authority, "none")
            for tool_id in item.tool_ids:
                metadata = self.registry.get(tool_id)
                self.assertEqual(metadata.network_access, "none")
                self.assertEqual(metadata.effect, "read")

    def test_expected_shared_primitives_are_available(self) -> None:
        ids = {item.primitive_id for item in default_evidence_primitives(self.registry)}
        self.assertTrue(
            {
                "process.snapshot",
                "service.snapshot",
                "network.interface_snapshot",
                "route.snapshot",
                "dns.snapshot",
                "identity.session_snapshot",
                "storage.capacity_snapshot",
                "system.resource_snapshot",
                "vpn.local_status_snapshot",
            }.issubset(ids)
        )

    def test_lookup_returns_exact_primitive(self) -> None:
        item = evidence_primitive_by_id("service.snapshot", registry=self.registry)
        self.assertEqual(item.tool_ids, ("service.status.read",))
        self.assertEqual(item.scope, "local_service_status")

    def test_network_capable_tool_cannot_be_relabelled_as_local_primitive(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot include network-access tool"):
            EvidencePrimitive(
                primitive_id="unsafe.network",
                tool_ids=("network.reachability.internal",),
                scope="unsafe",
            ).validate(self.registry)

    def test_unknown_tool_fails_closed(self) -> None:
        with self.assertRaises(Exception):
            EvidencePrimitive(
                primitive_id="unknown.tool",
                tool_ids=("diagnostic.unknown.fixture",),
                scope="unknown",
            ).validate(self.registry)

    def test_primitive_cannot_enable_execution_or_selection_authority(self) -> None:
        with self.assertRaises(ValueError):
            EvidencePrimitive(
                primitive_id="bad.execution",
                tool_ids=("service.status.read",),
                scope="bad",
                execution_enabled=True,
            ).validate(self.registry)
        with self.assertRaises(ValueError):
            EvidencePrimitive(
                primitive_id="bad.authority",
                tool_ids=("service.status.read",),
                scope="bad",
                selection_authority="auto",
            ).validate(self.registry)


if __name__ == "__main__":
    unittest.main()
