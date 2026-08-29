import copy
import tempfile
import unittest
from pathlib import Path

from three_agent.artifacts import ArtifactManager
from three_agent.benchmark_snapshot import unpack_metrics_payload
from three_agent.metric_registry import (
    DEFAULT_METRIC_REGISTRY,
    MetricDefinition,
    MetricRegistry,
    validate_metric_registry_payload,
)
from three_agent.metrics_snapshot import MetricsSnapshotService
from three_agent.store import TaskStore


class MetricRegistryTests(unittest.TestCase):
    def _snapshot(self, root: Path):
        store = TaskStore(root / "tasks.db")
        store.initialize()
        store.create_task("metric registry fixture", "deterministic fixture")
        service = MetricsSnapshotService(
            store,
            ArtifactManager(root / "data"),
            root / "inference.jsonl",
            root / "resource.jsonl",
        )
        return service.snapshot()

    def test_unified_snapshot_contains_valid_versioned_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = self._snapshot(Path(tmp))
        registry = payload["metric_registry"]
        digest = validate_metric_registry_payload(registry)
        self.assertEqual(digest, registry["registry_sha256"])
        self.assertEqual(payload["metric_map"], DEFAULT_METRIC_REGISTRY.metric_map())
        self.assertEqual(
            [item["metric_id"] for item in registry["metrics"]],
            [f"D3-{index:02d}" for index in range(1, 8)],
        )

    def test_formula_semantic_change_changes_registry_fingerprint(self):
        definitions = list(DEFAULT_METRIC_REGISTRY.definitions)
        first = definitions[0]
        definitions[0] = MetricDefinition(
            first.metric_id,
            first.name,
            "v2",
            first.output_path,
            first.source_schema,
            first.semantics + "; changed semantics",
        )
        changed = MetricRegistry(tuple(definitions))
        self.assertNotEqual(DEFAULT_METRIC_REGISTRY.sha256, changed.sha256)

    def test_duplicate_metric_ids_are_rejected(self):
        first = DEFAULT_METRIC_REGISTRY.definitions[0]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            MetricRegistry((first, first))

    def test_tampered_registry_hash_fails_closed(self):
        payload = copy.deepcopy(DEFAULT_METRIC_REGISTRY.to_dict())
        payload["metrics"][0]["semantics"] += " tampered"
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_metric_registry_payload(payload)

    def test_unified_metrics_validation_rejects_tampered_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = self._snapshot(Path(tmp))
        payload["metric_registry"]["metrics"][0]["version"] = "v999"
        with self.assertRaisesRegex(ValueError, "does not match"):
            unpack_metrics_payload(payload)

    def test_legacy_unified_metrics_without_registry_remain_readable(self):
        legacy = {
            "schema_version": "workspace-unified-metrics/v1",
            "scope": {
                "date": None,
                "selected_task_count": 1,
                "task_ids": ["TASK-LEGACY"],
            },
        }
        metrics, lineage = unpack_metrics_payload(legacy)
        self.assertEqual(metrics, legacy)
        self.assertIsNone(lineage)


if __name__ == "__main__":
    unittest.main()
