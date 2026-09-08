from __future__ import annotations

import unittest
from dataclasses import replace

from three_agent.capability_registry_snapshot import snapshot_micro_tool_registry
from three_agent.diagnostics.runtime_registry import (
    runtime_micro_tool_registry,
    runtime_tool_metadata,
)
from three_agent.micro_tool_registry import MicroToolRegistry, ToolMetadata


class RuntimeCapabilitySnapshotParityTests(unittest.TestCase):
    @staticmethod
    def _ids(snapshot) -> tuple[str, ...]:
        return tuple(item.id for item in snapshot.descriptors)

    def test_current_runtime_registry_projects_to_exact_snapshot_parity(self) -> None:
        metadata = runtime_tool_metadata()
        snapshot = snapshot_micro_tool_registry(runtime_micro_tool_registry())

        self.assertEqual(
            self._ids(snapshot),
            tuple(sorted(item.id for item in metadata)),
        )
        self.assertEqual(len(snapshot.descriptors), len(metadata))
        self.assertEqual(len(set(self._ids(snapshot))), len(metadata))

    def test_runtime_snapshot_fingerprint_is_deterministic_and_order_independent(self) -> None:
        metadata = runtime_tool_metadata()
        canonical = snapshot_micro_tool_registry(MicroToolRegistry(metadata))
        reversed_input = snapshot_micro_tool_registry(
            MicroToolRegistry(tuple(reversed(metadata)))
        )
        repeated = snapshot_micro_tool_registry(runtime_micro_tool_registry())

        self.assertEqual(canonical, reversed_input)
        self.assertEqual(canonical.fingerprint, repeated.fingerprint)

    def test_runtime_descriptor_identity_change_changes_snapshot_fingerprint(self) -> None:
        metadata = runtime_tool_metadata()
        baseline = snapshot_micro_tool_registry(MicroToolRegistry(metadata))
        target = metadata[0]
        changed = replace(
            target,
            keywords=tuple(target.keywords) + ("l15-parity-fixture",),
        ).validate()
        mutated_metadata = tuple(
            changed if item.id == target.id else item for item in metadata
        )
        mutated = snapshot_micro_tool_registry(MicroToolRegistry(mutated_metadata))

        self.assertEqual(self._ids(baseline), self._ids(mutated))
        self.assertNotEqual(
            baseline.descriptors[0].fingerprint,
            mutated.descriptors[0].fingerprint,
        )
        self.assertNotEqual(baseline.fingerprint, mutated.fingerprint)

    def test_runtime_addition_cannot_silently_disappear_from_snapshot(self) -> None:
        metadata = runtime_tool_metadata()
        baseline = snapshot_micro_tool_registry(MicroToolRegistry(metadata))
        extra = ToolMetadata(
            id="diagnostic.l15.fixture",
            platform="any",
            category="diagnostic",
            keywords=("l15 fixture",),
            cost="C0",
            risk="read_only",
            requires_admin=False,
            network_access="none",
            sensitive_outputs=False,
            effect="read",
        ).validate()
        expanded = snapshot_micro_tool_registry(
            MicroToolRegistry(metadata + (extra,))
        )

        self.assertNotIn(extra.id, self._ids(baseline))
        self.assertIn(extra.id, self._ids(expanded))
        self.assertEqual(len(expanded.descriptors), len(baseline.descriptors) + 1)
        self.assertNotEqual(baseline.fingerprint, expanded.fingerprint)

    def test_missing_runtime_descriptor_is_detectable_as_parity_failure(self) -> None:
        metadata = runtime_tool_metadata()
        self.assertGreater(len(metadata), 1)
        runtime_ids = {item.id for item in metadata}
        incomplete = snapshot_micro_tool_registry(
            MicroToolRegistry(metadata[:-1])
        )
        snapshot_ids = set(self._ids(incomplete))

        self.assertNotEqual(runtime_ids, snapshot_ids)
        self.assertEqual(runtime_ids - snapshot_ids, {metadata[-1].id})


if __name__ == "__main__":
    unittest.main()
