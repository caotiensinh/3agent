from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from three_agent.agents import ResearchAgent
from three_agent.artifacts import ArtifactManager
from three_agent.prompt_ledger import PromptCompilationLedger
from three_agent.store import TaskStore


class _FakeLLM:
    def generate_json(self, system: str, prompt: str, **kwargs):
        del system, prompt, kwargs
        return {
            "objective": "Troubleshoot Ollama",
            "queries": [
                "Ollama connection refused Ubuntu 24.04 username=administrator password=TopSecret-12345 192.168.11.112"
            ],
            "focus": ["service connectivity"],
        }


class ResearchPromptCompilationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.profiles = self.root / "profiles"
        self.profiles.mkdir()
        (self.profiles / "agent_research.md").write_text(
            "You are the local WorkSpace research agent.", encoding="utf-8"
        )
        self.store = TaskStore(self.root / "tasks.db")
        self.store.initialize()
        self.artifacts = ArtifactManager(self.root / "data")
        self.agent = ResearchAgent(self.profiles, _FakeLLM())

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_dry_research_model_view_is_compiled_but_local_original_is_unchanged(self) -> None:
        repeated = "Do not reboot the production server because workloads are active."
        raw = (
            "password=LocalSecret-123456\n\n"
            f"{repeated}\n\n{repeated}\n\n"
            "Diagnose Ollama connection failure."
        )
        task = self.store.create_task("Ollama", raw)
        paths = self.agent.run(task.task_id, self.store, self.artifacts, live=False)
        payload = json.loads(Path(paths[0]).read_text(encoding="utf-8"))

        self.assertEqual(self.store.get_task(task.task_id).request, raw)
        self.assertIn("LocalSecret-123456", payload["request"])
        self.assertEqual(payload["request"].count(repeated), 1)
        self.assertIn("identical_block_count=2", payload["request"])

        receipt = PromptCompilationLedger(self.store).get(task.task_id)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["duplicate_blocks_removed"], 1)
        self.assertNotIn("LocalSecret-123456", json.dumps(receipt))

    def test_local_plan_can_see_sensitive_context_but_outbound_query_cannot(self) -> None:
        objective, queries, focus = self.agent._plan(
            "Ollama failure",
            "username=administrator password=TopSecret-12345 192.168.11.112 Ubuntu 24.04",
        )
        self.assertEqual(objective, "Troubleshoot Ollama")
        self.assertEqual(focus, ["service connectivity"])
        self.assertEqual(len(queries), 1)
        query = queries[0]
        self.assertIn("Ollama connection refused Ubuntu 24.04", query)
        self.assertNotIn("administrator", query)
        self.assertNotIn("TopSecret", query)
        self.assertNotIn("192.168.11.112", query)


if __name__ == "__main__":
    unittest.main()
