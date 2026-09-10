from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError, replace

from three_agent.capability_descriptor import project_tool_metadata
from three_agent.capability_registry_snapshot import (
    BUILTIN_TOOL_NAMESPACE,
    CAPABILITY_NAMESPACE_POLICY_SCHEMA,
    CapabilityRegistrySnapshotValidationError,
    ReviewedCapabilityNamespace,
    build_capability_registry_snapshot,
    snapshot_micro_tool_registry,
)
from three_agent.micro_tool_registry import MicroToolRegistry, ToolMetadata
from three_agent.office_it_tools import iter_specs


def _sha(payload: dict[str, object]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _namespace_policy(
    *,
    namespace: str,
    kind: str,
    provenance_source: str,
    external: bool = False,
) -> ReviewedCapabilityNamespace:
    identity = {
        "schema_version": CAPABILITY_NAMESPACE_POLICY_SCHEMA,
        "namespace": namespace,
        "kind": kind,
        "provenance_source": provenance_source,
        "external": external,
    }
    return ReviewedCapabilityNamespace(
        namespace=namespace,
        kind=kind,
        provenance_source=provenance_source,
        external=external,
        fingerprint=_sha(identity),
    )


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

        self.assertEqual(len(snapshot.descriptors), 9)
        self.assertTrue(
            all(item.namespace == "builtin.tool" for item in snapshot.descriptors)
        )
        self.assertTrue(
            all(
                item.provenance_source == "micro_tool_registry"
                for item in snapshot.descriptors
            )
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

    def test_structurally_valid_unreviewed_policy_cannot_mint_review(self) -> None:
        descriptor = project_tool_metadata(
            _tool("windows.event.system", keyword="system")
        )
        alternate = _namespace_policy(
            namespace="builtin.tool",
            kind="tool",
            provenance_source="micro_tool_registry.v2",
        )
        self.assertEqual(alternate, alternate.validate())

        with self.assertRaisesRegex(
            CapabilityRegistrySnapshotValidationError,
            "namespace policy is not source-reviewed",
        ):
            build_capability_registry_snapshot(
                (descriptor,),
                namespaces=(alternate,),
            )

    def test_unreviewed_namespace_policy_fails_closed(self) -> None:
        descriptor = project_tool_metadata(
            _tool("windows.event.system", keyword="system")
        )
        unrelated = _namespace_policy(
            namespace="builtin.adapter",
            kind="adapter",
            provenance_source="reviewed_adapter_registry",
        )
        self.assertEqual(unrelated, unrelated.validate())

        with self.assertRaisesRegex(
            CapabilityRegistrySnapshotValidationError,
            "namespace policy is not source-reviewed",
        ):
            build_capability_registry_snapshot(
                (descriptor,),
                namespaces=(unrelated,),
            )

    def test_namespace_kind_mismatch_fails_closed(self) -> None:
        descriptor = project_tool_metadata(
            _tool("windows.event.system", keyword="system")
        )
        forged = replace(descriptor, kind="adapter", fingerprint=descriptor.fingerprint)
        forged = replace(forged, fingerprint=_sha(forged._identity_payload()))
        self.assertEqual(forged, forged.validate())

        with self.assertRaisesRegex(
            CapabilityRegistrySnapshotValidationError,
            "namespace kind mismatch",
        ):
            build_capability_registry_snapshot((forged,))

    def test_namespace_provenance_mismatch_fails_closed(self) -> None:
        descriptor = project_tool_metadata(
            _tool("windows.event.system", keyword="system")
        )
        forged = replace(
            descriptor,
            provenance_source="other_reviewed_source",
            fingerprint=descriptor.fingerprint,
        )
        forged = replace(forged, fingerprint=_sha(forged._identity_payload()))
        self.assertEqual(forged, forged.validate())

        with self.assertRaisesRegex(
            CapabilityRegistrySnapshotValidationError,
            "namespace provenance mismatch",
        ):
            build_capability_registry_snapshot((forged,))

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
        external = _namespace_policy(
            namespace="external.provider",
            kind="provider",
            provenance_source="plugin_discovery",
            external=True,
        )
        with self.assertRaisesRegex(
            CapabilityRegistrySnapshotValidationError,
            "external namespaces are not reviewed",
        ):
            build_capability_registry_snapshot(
                (
                    project_tool_metadata(
                        _tool("windows.event.system", keyword="system")
                    ),
                ),
                namespaces=(external,),
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

    def test_snapshot_rejects_empty_and_noncanonical_inputs(self) -> None:
        descriptor = project_tool_metadata(
            _tool("windows.event.system", keyword="system")
        )

        with self.assertRaises(CapabilityRegistrySnapshotValidationError):
            build_capability_registry_snapshot(())
        with self.assertRaises(CapabilityRegistrySnapshotValidationError):
            build_capability_registry_snapshot("not-a-descriptor")  # type: ignore[arg-type]
        with self.assertRaises(CapabilityRegistrySnapshotValidationError):
            build_capability_registry_snapshot(
                (descriptor,),
                namespaces="builtin.tool",  # type: ignore[arg-type]
            )
        with self.assertRaises(CapabilityRegistrySnapshotValidationError):
            build_capability_registry_snapshot(
                (descriptor,),
                namespaces=("builtin.tool",),  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
