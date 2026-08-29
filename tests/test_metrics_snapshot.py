import tempfile
import unittest
from pathlib import Path

from three_agent.artifacts import ArtifactManager
from three_agent.cli import build_parser
from three_agent.metrics_snapshot import MetricsSnapshotService
from three_agent.store import TaskStore


class MetricsSnapshotTests(unittest.TestCase):
    def make_service(self, root: Path):
        store = TaskStore(root / "tasks.db")
        store.initialize()
        artifacts = ArtifactManager(root / "data")
        service = MetricsSnapshotService(
            store,
            artifacts,
            root / "data" / "activity" / "inference.jsonl",
            root / "data" / "activity" / "resource_events.jsonl",
        )
        return service, store

    def test_empty_snapshot_contains_all_d3_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            service, _ = self.make_service(Path(tmp))
            payload = service.snapshot()
            self.assertEqual(payload["schema_version"], "workspace-unified-metrics/v1")
            self.assertEqual(payload["scope"]["selected_task_count"], 0)
            self.assertEqual(set(payload["metric_map"]), {f"D3-{index:02d}" for index in range(1, 8)})
            self.assertEqual(payload["verified_work"]["schema_version"], "workspace-verified-work-metrics/v1")
            self.assertEqual(payload["token_efficiency"]["schema_version"], "workspace-token-per-verified-task/v1")
            self.assertEqual(payload["resource_efficiency"]["schema_version"], "workspace-resource-per-verified-task/v1")
            self.assertEqual(payload["evidence_coverage"]["schema_version"], "workspace-evidence-coverage/v1")
            self.assertEqual(payload["context_precision_proxy"]["schema_version"], "workspace-context-precision-proxy/v1")
            self.assertEqual(payload["context_recall_proxy"]["schema_version"], "workspace-context-recall-proxy/v1")

    def test_exact_task_scope_is_forwarded_to_every_metric(self):
        with tempfile.TemporaryDirectory() as tmp:
            service, store = self.make_service(Path(tmp))
            first = store.create_task("A", "A")
            store.create_task("B", "B")
            payload = service.snapshot(task_ids=[first.task_id, first.task_id])
            self.assertEqual(payload["scope"]["task_ids"], [first.task_id])
            self.assertEqual(payload["scope"]["selected_task_count"], 1)
            self.assertEqual(payload["verified_work"]["attempted_tasks"], 1)
            self.assertEqual(payload["token_efficiency"]["attempted_tasks"], 1)
            self.assertEqual(payload["resource_efficiency"]["attempted_tasks"], 1)
            self.assertEqual(payload["evidence_coverage"]["selected_tasks"], 1)
            self.assertEqual(payload["context_precision_proxy"]["selected_tasks"], 1)
            self.assertEqual(payload["context_recall_proxy"]["selected_tasks"], 1)

    def test_date_scope_uses_store_activity_membership(self):
        with tempfile.TemporaryDirectory() as tmp:
            service, store = self.make_service(Path(tmp))
            task = store.create_task("A", "A")
            date = task.created_at[:10]
            payload = service.snapshot(date=date)
            self.assertEqual(payload["scope"]["date"], date)
            self.assertIn(task.task_id, payload["scope"]["task_ids"])
            self.assertEqual(payload["verified_work"]["attempted_tasks"], 1)

    def test_conflicting_scope_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            service, store = self.make_service(Path(tmp))
            task = store.create_task("A", "A")
            with self.assertRaises(ValueError):
                service.snapshot(task_ids=[task.task_id], date=task.created_at[:10])

    def test_cli_metrics_scope_options_are_mutually_exclusive(self):
        parser = build_parser()
        args = parser.parse_args(["metrics", "--task-id", "TASK-1", "--task-id", "TASK-2"])
        self.assertEqual(args.command, "metrics")
        self.assertEqual(args.task_ids, ["TASK-1", "TASK-2"])
        with self.assertRaises(SystemExit):
            parser.parse_args(["metrics", "--date", "2026-08-29", "--task-id", "TASK-1"])


if __name__ == "__main__":
    unittest.main()
