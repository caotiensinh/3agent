from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError, replace

from three_agent.capability_descriptor import project_tool_metadata
from three_agent.capability_registry_snapshot import (
    BUILTIN_TOOL_NAMESPACE,
    CapabilityRegistrySnapshotValidationError,
    build_capability_registry_snapshot,
    reviewed_namespace,
    snapshot_micro_tool_registry,
)
from three_agent.micro_tool_registry import MicroToolRegistry, ToolMetadata
from three_agent.office_it_tools import iter_specs


def _tool(
    tool_id: str,
    *,
    keyword: str,
    platform: str = "windows",
) -> ToolMetadata:
    return ToolMetadata(
        id=tool_id,
        platform=platform,
        category="event",
        keywords=(keyword,),
        cost="C1",
        risk="read_only",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=False,
        effect="read",
    )


class CapabilityRegistrySnapshotTests(unittest.TestCase):
    def test_snapshot_is_deterministic_immutable_and_non_authorizing(self) -> None:
        first = project_tool_metadata(
            _tool("windows.event.system", keyword="system")
        )
        second = project_tool_metadata(
            _tool("windows.event.application", keyword="application")
        )

        forward = build_capability_registry_snapshot((first, second))
        reverse = build_capability_registry_snapshot((second, first))

        self.assertEqual(forward, reverse)
        self.assertTrue(forward.fingerprint.startswith("sha256:"))
        self.assertEqual(forward.namespaces, (BUILTIN_TOOL_NAMESPACE,))
        self.assertEqual(
            tuple(item.id for item in forward.descriptors),
            ("windows.event.application", "windows.event.system"),
        )
        payload = forward.to_dict()
        self.assertNotIn("authority", payload)
        self.assertNotIn("approval", payload)
        self.assertNotIn("credential", payload)
        with self.assertRaises(FrozenInstanceError):
            forward.fingerprint = "sha256:" + "0" * 64  # type: ignore[misc]

    def test_office_it_registry_projects_through_canonical_registry_only(self) -> None:
        registry = MicroToolRegistry.from_specs(iter_specs())
        snapshot = snapshot_micro_tool_registry(registry)

        self.assertEqual(len(snapshot.descriptors), 8)
        self.assertTrue(
            all(item.namespace == "builtin.tool" for item in snapshot.descriptors)
        )
        self.assertTrue(
            all(item.provenance_source == "micro_tool_registry" for item in snapshot.descriptors)
        )

    def test_descriptor_change_changes_registry_fingerprint(self) -> None:
        baseline = build_capability_registry_snapshot(
            (
                project_tool_metadata(
                    _tool("windows.event.system", keyword="system")
                ),
            )
        )
        changed = build_capability_registry_snapshot(
            (
                project_tool_metadata(
                    _tool("windows.event.system", keyword="kernel power")
                ),
            )
        )

        self.assertNotEqual(
            baseline.descriptors[0].fingerprint,
            changed.descriptors[0].fingerprint,
        )
        self.assertNotEqual(baseline.fingerprint, changed.fingerprint)

    def test_namespace_policy_change_changes_registry_fingerprint(self) -> None:
        descriptor = project_tool_metadata(
            _tool("windows.event.system", keyword="system")
        )
        baseline = build_capability_registry_snapshot((descriptor,))
        alternate = reviewed_namespace(
            namespace="builtin.tool",
            kind="tool",
            provenance_source="micro_tool_registry.v2",
        )

        with self.assertRaisesRegex(
            CapabilityRegistrySnapshotValidationError,
            "namespace provenance mismatch",
        ):
            build_capability_registry_snapshot(
                (descriptor,),
                namespaces=(alternate,),
            )
        self.assertNotEqual(
            BUILTIN_TOOL_NAMESPACE.fingerprint,
            alternate.fingerprint,
        )

    def test_unreviewed_namespace_fails_closed(self) -> None:
        descriptor = project_tool_metadata(
            _tool("windows.event.system", keyword="system")
        )
        unrelated = reviewed_namespace(
            namespace="builtin.adapter",
            kind="adapter",
            provenance_source="reviewed_adapter_registry",
        )

        with self.assertRaisesRegex(
            CapabilityRegistrySnapshotValidationError,
            "unreviewed capability namespace",
        ):
            build_capability_registry_snapshot(
                (descriptor,),
                namespaces=(unrelated,),
            )

    def test_namespace_kind_mismatch_fails_closed(self) -> None:
        descriptor = project_tool_metadata(
            _tool("windows.event.system", keyword="system")
        )
        wrong_kind = reviewed_namespace(
            namespace="builtin.tool",
            kind="adapter",
            provenance_source="micro_tool_registry",
        )

        with self.assertRaisesRegex(
            CapabilityRegistrySnapshotValidationError,
            "namespace kind mismatch",
        ):
            build_capability_registry_snapshot(
                (descriptor,),
                namespaces=(wrong_kind,),
            )

    def test_duplicate_capability_ids_fail_closed(self) -> None:
        first = project_tool_metadata(
            _tool("windows.event.system", keyword="system")
        )
        second = project_tool_metadata(
            _tool("windows.event.system", keyword="kernel power")
        )

        with self.assertRaisesRegex(
            CapabilityRegistrySnapshotValidationError,
            "duplicate capability ids",
        ):
            build_capability_registry_snapshot((first, second))

    def test_external_namespace_is_not_reviewed_in_v0_1(self) -> None:
        with self.assertRaisesRegex(
            CapabilityRegistrySnapshotValidationError,
            "external namespaces are not reviewed",
        ):
            reviewed_namespace(
                namespace="external.provider",
                kind="provider",
                provenance_source="plugin_discovery",
                external=True,
            )

    def test_registry_fingerprint_tamper_is_detected(self) -> None:
        snapshot = build_capability_registry_snapshot(
            (
                project_tool_metadata(
                    _tool("windows.event.system", keyword="system")
                ),
            )
        )
        tampered = replace(snapshot, fingerprint="sha256:" + "0" * 64)

        with self.assertRaisesRegex(
            CapabilityRegistrySnapshotValidationError,
            "registry snapshot fingerprint mismatch",
        ):
            tampered.validate()

    def test_snapshot_rejects_noncanonical_input_types(self) -> None:
        descriptor = project_tool_metadata(
            _tool("windows.event.system", keyword="system")
        )

        with self.assertRaises(CapabilityRegistrySnapshotValidationError):
            build_capability_registry_snapshot("not-a-descriptor")  # type: ignore[arg-type]
        with self.assertRaises(CapabilityRegistrySnapshotValidationError):
            build_capability_registry_snapshot(
                (descriptor,),
                namespaces="builtin.tool",  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
