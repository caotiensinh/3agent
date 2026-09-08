from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError, replace

from three_agent.capability_descriptor import (
    CAPABILITY_KINDS,
    DEFAULT_TOOL_NAMESPACE,
    MICRO_TOOL_PROVENANCE_SOURCE,
    CapabilityDescriptorValidationError,
    project_micro_tool_registry,
    project_tool_metadata,
)
from three_agent.micro_tool_registry import MicroToolRegistry, ToolMetadata
from three_agent.office_it_tools import iter_specs
from three_agent.tool_result_boundary import MAX_RESULT_FIELD_BYTES


def _tool(tool_id: str = "windows.event.system", *, keyword: str = "event") -> ToolMetadata:
    return ToolMetadata(
        id=tool_id,
        platform="windows",
        category="event",
        keywords=(keyword,),
        cost="C1",
        risk="read_only",
        requires_admin=False,
        network_access="none",
        sensitive_outputs=False,
        effect="read",
    )


class CapabilityDescriptorTests(unittest.TestCase):
    def test_projection_is_deterministic_immutable_and_non_authorizing(self) -> None:
        first = project_tool_metadata(_tool())
        second = project_tool_metadata(_tool())

        self.assertEqual(first, second)
        self.assertTrue(first.fingerprint.startswith("sha256:"))
        self.assertTrue(first.source_fingerprint.startswith("sha256:"))
        self.assertEqual(first.kind, "tool")
        self.assertEqual(first.namespace, DEFAULT_TOOL_NAMESPACE)
        self.assertEqual(first.provenance_source, MICRO_TOOL_PROVENANCE_SOURCE)
        self.assertTrue(first.evidence_required)
        self.assertNotIn("authority", first.to_dict())
        self.assertNotIn("approval", first.to_dict())
        self.assertNotIn("credential", first.to_dict())
        with self.assertRaises(FrozenInstanceError):
            first.id = "windows.event.changed"  # type: ignore[misc]

    def test_source_metadata_change_changes_source_and_descriptor_fingerprints(self) -> None:
        first = project_tool_metadata(_tool(keyword="event"))
        changed = project_tool_metadata(_tool(keyword="kernel power"))

        self.assertNotEqual(first.source_fingerprint, changed.source_fingerprint)
        self.assertNotEqual(first.fingerprint, changed.fingerprint)

    def test_registry_projection_uses_canonical_registry_order(self) -> None:
        first = _tool("windows.event.system", keyword="system")
        second = _tool("windows.event.application", keyword="application")

        forward = project_micro_tool_registry(MicroToolRegistry((first, second)))
        reverse = project_micro_tool_registry(MicroToolRegistry((second, first)))

        self.assertEqual(forward, reverse)
        self.assertEqual(
            tuple(item.id for item in forward),
            ("windows.event.application", "windows.event.system"),
        )

    def test_current_office_it_registry_projects_without_execution(self) -> None:
        descriptors = project_micro_tool_registry(MicroToolRegistry.from_specs(iter_specs()))

        self.assertEqual(len(descriptors), 8)
        self.assertTrue(all(item.kind == "tool" for item in descriptors))
        self.assertTrue(all(item.namespace == DEFAULT_TOOL_NAMESPACE for item in descriptors))
        self.assertTrue(all(item.fingerprint.startswith("sha256:") for item in descriptors))

    def test_required_environment_contract_accepts_names_only(self) -> None:
        descriptor = project_tool_metadata(
            _tool(),
            required_env_names=("WORKSPACE_TOKEN", "API_ENDPOINT"),
        )
        self.assertEqual(descriptor.required_env_names, ("API_ENDPOINT", "WORKSPACE_TOKEN"))

        for bad in ("TOKEN=secret", "TOKEN secret", "", "A-B"):
            with self.subTest(bad=bad):
                with self.assertRaises(CapabilityDescriptorValidationError):
                    project_tool_metadata(_tool(), required_env_names=(bad,))

    def test_result_limit_fails_closed_outside_platform_boundary(self) -> None:
        for bad in (0, -1, MAX_RESULT_FIELD_BYTES + 1):
            with self.subTest(bad=bad):
                with self.assertRaises(CapabilityDescriptorValidationError):
                    project_tool_metadata(_tool(), result_size_limit_bytes=bad)

    def test_descriptor_tamper_is_detected_by_fingerprint_validation(self) -> None:
        descriptor = project_tool_metadata(_tool())
        tampered = replace(descriptor, effect="compute")
        with self.assertRaisesRegex(CapabilityDescriptorValidationError, "fingerprint mismatch"):
            tampered.validate()

    def test_schema_declares_future_kinds_without_claiming_runtime_projection(self) -> None:
        self.assertEqual(
            CAPABILITY_KINDS,
            frozenset({"tool", "program", "gateway", "agent", "provider", "adapter"}),
        )
        projected = project_tool_metadata(_tool())
        self.assertEqual(projected.kind, "tool")


if __name__ == "__main__":
    unittest.main()
