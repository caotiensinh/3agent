import json
import tempfile
import unittest
from pathlib import Path

from three_agent.agents.presentation import ResearchHandoffNotReady
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

    def test_dry_research_is_blocked_from_presentation(self):
        with tempfile.TemporaryDirectory() as tmp:
            orch = Orchestrator(self.make_config(Path(tmp)))
            orch.initialize()
            task = orch.store.create_task("Test", "Test request")
            self.assertEqual(task.status, TaskStatus.NEW)

            research_json, _, handoff_path = orch.research_agent.run(
                task.task_id, orch.store, orch.artifacts, live=False
            )
            research = json.loads(research_json.read_text(encoding="utf-8"))
            handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
            self.assertEqual(research["status"], "dry_run_not_researched")
            self.assertFalse(handoff["presentation_ready"])
            self.assertIn("NO_USABLE_SOURCE", handoff["blockers"])
            self.assertEqual(orch.store.get_task(task.task_id).status, TaskStatus.WAITING_HUMAN)

            with self.assertRaises(ResearchHandoffNotReady):
                orch.presentation_agent.run(task.task_id, orch.store, orch.artifacts, live=False)
            self.assertEqual(orch.store.get_task(task.task_id).status, TaskStatus.WAITING_HUMAN)

            date = ArtifactManager.today()
            daily_json, _ = orch.daily_report(date, live=False)
            daily = json.loads(daily_json.read_text(encoding="utf-8"))
            self.assertGreaterEqual(daily["activity_count"], 1)

    def test_presentation_accepts_only_ready_handoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            orch = Orchestrator(self.make_config(Path(tmp)))
            orch.initialize()
            task = orch.store.create_task("Ready", "Ready request")
            handoff = {
                "schema_version": "1.0",
                "task_id": task.task_id,
                "presentation_ready": True,
                "blockers": [],
                "key_facts": [
                    {"fact_id": "F001", "claim": "Verified fact", "source_ids": ["S1"], "confidence": "medium"}
                ],
                "inferences": [],
                "conflicts": [],
                "unresolved_items": [],
                "conclusion": "Verified conclusion",
                "recommended_next_actions": [],
                "sources": [
                    {"source_id": "S1", "title": "Source", "url": "https://example.com", "fetch_status": "ok"}
                ],
                "quality_metrics": {"usable_source_count": 1, "verified_fact_count": 1},
            }
            handoff_path = orch.artifacts.write_research_handoff(task.task_id, handoff)
            presentation_json, _ = orch.presentation_agent.run(task.task_id, orch.store, orch.artifacts, live=False)
            presentation = json.loads(presentation_json.read_text(encoding="utf-8"))
            self.assertEqual(presentation["source_research_handoff"], str(handoff_path))
            self.assertEqual(orch.store.get_task(task.task_id).status, TaskStatus.PRESENTATION_COMPLETED)

    def test_presentation_rejects_mismatched_handoff_task_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            orch = Orchestrator(self.make_config(Path(tmp)))
            orch.initialize()
            task = orch.store.create_task("Lineage", "Lineage request")
            handoff = {
                "schema_version": "1.0",
                "task_id": "TASK-WRONG",
                "presentation_ready": True,
                "blockers": [],
                "key_facts": [
                    {"fact_id": "F001", "claim": "Verified fact", "source_ids": ["S1"], "confidence": "medium"}
                ],
                "inferences": [],
                "conflicts": [],
                "unresolved_items": [],
                "conclusion": "",
                "recommended_next_actions": [],
                "sources": [],
                "quality_metrics": {},
            }
            orch.artifacts.write_research_handoff(task.task_id, handoff)
            with self.assertRaisesRegex(ResearchHandoffNotReady, "HANDOFF_TASK_ID_MISMATCH"):
                orch.presentation_agent.run(task.task_id, orch.store, orch.artifacts, live=False)
            self.assertEqual(orch.store.get_task(task.task_id).status, TaskStatus.WAITING_HUMAN)

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
