import json
import tempfile
import unittest
from pathlib import Path

from three_agent.artifacts import ArtifactManager
from three_agent.config import AppConfig, GatewayConfig, LLMConfig
from three_agent.models import TaskStatus
from three_agent.orchestrator import Orchestrator


class HarnessTests(unittest.TestCase):
    def make_config(self, root: Path) -> AppConfig:
        profiles = root / "profiles"
        profiles.mkdir()
        source_profiles = Path(__file__).resolve().parents[1] / "profiles"
        for name in ("agent_research.md", "agent_presentation.md", "agent_daily_report.md"):
            (profiles / name).write_text((source_profiles / name).read_text(encoding="utf-8"), encoding="utf-8")
        return AppConfig(
            environment="test",
            test_mode_full_access=True,
            database_path=root / "data" / "tasks.db",
            artifact_root=root / "data",
            profile_root=profiles,
            llm=LLMConfig("ollama", "http://127.0.0.1:11434", "", 5),
            internet_gateway=GatewayConfig(True, True, root / "internet.jsonl"),
            execution_gateway=GatewayConfig(True, True, root / "execution.jsonl"),
            raw={},
        )

    def test_task_and_dry_run_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            orch = Orchestrator(self.make_config(Path(tmp)))
            orch.initialize()
            task = orch.store.create_task("Test", "Test request")
            self.assertEqual(task.status, TaskStatus.NEW)

            research_json, _ = orch.research_agent.run(task.task_id, orch.store, orch.artifacts, live=False)
            research = json.loads(research_json.read_text(encoding="utf-8"))
            self.assertEqual(research["status"], "dry_run_not_researched")
            self.assertEqual(orch.store.get_task(task.task_id).status, TaskStatus.RESEARCH_COMPLETED)

            presentation_json, _ = orch.presentation_agent.run(task.task_id, orch.store, orch.artifacts, live=False)
            presentation = json.loads(presentation_json.read_text(encoding="utf-8"))
            self.assertEqual(presentation["source_research_artifact"], str(research_json))
            self.assertEqual(orch.store.get_task(task.task_id).status, TaskStatus.PRESENTATION_COMPLETED)

            date = ArtifactManager.today()
            daily_json, _ = orch.daily_report(date, live=False)
            daily = json.loads(daily_json.read_text(encoding="utf-8"))
            self.assertGreaterEqual(daily["activity_count"], 1)

    def test_task_ids_increment(self):
        with tempfile.TemporaryDirectory() as tmp:
            orch = Orchestrator(self.make_config(Path(tmp)))
            orch.initialize()
            a = orch.store.create_task("A", "A")
            b = orch.store.create_task("B", "B")
            self.assertNotEqual(a.task_id, b.task_id)
            self.assertEqual(int(b.task_id.split("-")[-1]), int(a.task_id.split("-")[-1]) + 1)


if __name__ == "__main__":
    unittest.main()
