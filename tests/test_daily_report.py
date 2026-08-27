import json
import tempfile
import unittest
from pathlib import Path

from three_agent.agents.daily_report import DailyReportAgent
from three_agent.artifacts import ArtifactManager
from three_agent.models import TaskStatus
from three_agent.store import TaskStore


class DummyLLM:
    def generate_json(self, *_args, **_kwargs):
        return {}


class FakeDailyLLM:
    def __init__(self, task_id: str):
        self.task_id = task_id

    def generate_json(self, *_args, **_kwargs):
        return {
            "summary_points": [
                {"text": "根拠付きの要約", "evidence_ids": ["T1"]},
                {"text": "存在しない根拠を使う要約", "evidence_ids": ["Z99"]},
            ],
            "work_items": [
                {"task_id": self.task_id, "text": "対象タスクを実施", "evidence_ids": ["T1", "A1"]},
                {"task_id": "TASK-INVALID", "text": "存在しないタスク", "evidence_ids": ["T1"]},
            ],
            "achievements": [],
            "blockers": [],
            "tomorrow_plan": [],
            "manager_attention": [],
        }


class FailingLLM:
    def generate_json(self, *_args, **_kwargs):
        raise RuntimeError("model unavailable")


class DailyReportAgentTests(unittest.TestCase):
    def make_store(self, root: Path):
        (root / "agent_daily_report.md").write_text("# Test daily report profile\n", encoding="utf-8")
        store = TaskStore(root / "data" / "tasks.db")
        store.initialize()
        artifacts = ArtifactManager(root / "data")
        return store, artifacts

    def test_deterministic_report_collects_tasks_artifacts_blockers_and_is_regeneration_stable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, artifacts = self.make_store(root)
            task = store.create_task("Daily report task", "Track this work")
            store.set_status(task.task_id, TaskStatus.WAITING_HUMAN)
            store.record_activity(task.task_id, "research", "source_fetch", "warning", "Provider returned incomplete data")
            store.record_artifact(task.task_id, "research", "research_json", "data/research/result.json")

            date = ArtifactManager.today()
            agent = DailyReportAgent(root, DummyLLM())
            json_path, md_path = agent.run(date, store, artifacts, live=False)
            first = json.loads(json_path.read_text(encoding="utf-8"))

            self.assertEqual(first["schema_version"], 2)
            self.assertEqual(first["status"], "deterministic_from_evidence")
            self.assertEqual(first["source_counts"]["tasks"], 1)
            self.assertGreaterEqual(first["source_counts"]["activities"], 2)
            self.assertEqual(first["source_counts"]["artifacts"], 1)
            self.assertTrue(first["sections"]["blockers"])
            self.assertIn("WAITING_HUMAN", first["task_snapshots"][0]["status"])
            markdown = md_path.read_text(encoding="utf-8")
            self.assertIn("## Evidence", markdown)
            self.assertIn("Provider returned incomplete data", markdown)

            first_digest = first["evidence_digest"]
            second_json, _ = agent.run(date, store, artifacts, live=False)
            second = json.loads(second_json.read_text(encoding="utf-8"))
            self.assertEqual(second["evidence_digest"], first_digest)
            self.assertEqual(second["source_counts"], first["source_counts"])

    def test_live_report_rejects_unknown_evidence_and_task_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, artifacts = self.make_store(root)
            task = store.create_task("Evidence task", "Do evidence work")
            date = ArtifactManager.today()
            agent = DailyReportAgent(root, FakeDailyLLM(task.task_id))

            json_path, _ = agent.run(date, store, artifacts, live=True)
            payload = json.loads(json_path.read_text(encoding="utf-8"))

            self.assertEqual(payload["status"], "model_generated_evidence_validated")
            self.assertEqual(payload["sections"]["summary_points"][0]["text"], "根拠付きの要約")
            rejected_text = "\n".join(payload["rejected_model_items"])
            self.assertIn("存在しない根拠を使う要約", rejected_text)
            self.assertIn("存在しないタスク", rejected_text)
            self.assertTrue(payload["sections"]["tomorrow_plan"])

    def test_live_model_failure_falls_back_to_deterministic_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, artifacts = self.make_store(root)
            store.create_task("Fallback task", "Fallback request")
            date = ArtifactManager.today()
            agent = DailyReportAgent(root, FailingLLM())

            json_path, _ = agent.run(date, store, artifacts, live=True)
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "deterministic_fallback_after_model_error")
            self.assertTrue(payload["sections"]["work_items"])
            self.assertIn("Live synthesis failed", payload["rejected_model_items"][0])

    def test_no_activity_date_produces_auditable_empty_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, artifacts = self.make_store(root)
            agent = DailyReportAgent(root, DummyLLM())
            json_path, md_path = agent.run("2000-01-01", store, artifacts, live=False)
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "no_activity")
            self.assertEqual(payload["source_counts"], {"tasks": 0, "activities": 0, "artifacts": 0})
            self.assertIn("対象日のEvidenceはありません", md_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
