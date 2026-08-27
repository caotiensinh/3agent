import json
import tempfile
import unittest
from pathlib import Path

from three_agent.agents.research import ResearchAgent
from three_agent.artifacts import ArtifactManager
from three_agent.models import TaskStatus
from three_agent.store import TaskStore
from three_agent.web_research import DuckDuckGoSearchProvider, WebResearchClient


SEARCH_HTML = b"""
<html><body>
<div class="result">
  <a class="result__a" href="https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fsource">Primary source</a>
  <a class="result__snippet">Example source snippet for testing.</a>
</div>
</body></html>
"""

SOURCE_HTML = b"""
<html><head><title>Example Evidence</title><style>.x{display:none}</style></head>
<body><main><h1>Verified Evidence</h1><p>The system supports evidence-backed research.</p></main></body></html>
"""


class FakeGateway:
    def get(self, agent_id, task_id, url, timeout=30):
        del agent_id, task_id, timeout
        if "duckduckgo.com/html" in url:
            return SEARCH_HTML
        if url == "https://example.com/source":
            return SOURCE_HTML
        raise RuntimeError(f"unexpected URL: {url}")


class FakeLLM:
    def generate_json(self, system_prompt, user_prompt, **kwargs):
        del system_prompt, kwargs
        if "Create a concise web-research plan" in user_prompt:
            return {
                "objective": "Verify the requested capability",
                "queries": ["evidence backed research example"],
                "focus": ["capability"],
            }
        if "evidence-bounded research task" in user_prompt:
            return {
                "verified_facts": [
                    {"claim": "The source describes evidence-backed research.", "source_ids": ["S1"]},
                    {"claim": "The source describes evidence-backed research.", "source_ids": ["S1"]},
                    {"claim": "This uncited claim must be rejected.", "source_ids": ["S9"]},
                ],
                "inferences": [
                    {"claim": "The design emphasizes source lineage.", "source_ids": ["S1"]}
                ],
                "conflicts": [],
                "unresolved": ["Production performance is not established."],
                "conclusion": "The collected source supports the scoped capability.",
                "recommended_next_actions": ["Collect additional independent sources."],
            }
        raise AssertionError("unexpected LLM prompt")


class WebResearchTests(unittest.TestCase):
    def test_duckduckgo_search_and_source_extraction(self):
        gateway = FakeGateway()
        provider = DuckDuckGoSearchProvider(gateway)
        results = provider.search("research", "TASK-1", "query", 5)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].url, "https://example.com/source")
        self.assertIn("snippet", results[0].snippet)

        client = WebResearchClient(gateway, provider)
        sources = client.fetch_sources("research", "TASK-1", results)
        self.assertEqual(sources[0].fetch_status, "ok")
        self.assertEqual(sources[0].title, "Example Evidence")
        self.assertIn("evidence-backed research", sources[0].extracted_text)

    def test_live_research_cleans_data_and_creates_presentation_handoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profiles = root / "profiles"
            profiles.mkdir()
            source_profile = Path(__file__).resolve().parents[1] / "profiles" / "agent_research.md"
            (profiles / "agent_research.md").write_text(source_profile.read_text(encoding="utf-8"), encoding="utf-8")

            store = TaskStore(root / "tasks.db")
            store.initialize()
            artifacts = ArtifactManager(root / "data")
            task = store.create_task("Evidence task", "Verify research behavior")
            gateway = FakeGateway()
            client = WebResearchClient(gateway, DuckDuckGoSearchProvider(gateway))
            agent = ResearchAgent(profiles, FakeLLM(), client)

            json_path, md_path, handoff_path = agent.run(task.task_id, store, artifacts, live=True)
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
            markdown = md_path.read_text(encoding="utf-8")

            self.assertEqual(payload["status"], "researched_cleaned_and_verified")
            self.assertEqual(payload["sources"][0]["source_id"], "S1")
            self.assertEqual(len(payload["verified_facts"]), 1, "duplicate facts must be removed")
            self.assertEqual(payload["verified_facts"][0]["source_ids"], ["S1"])
            self.assertEqual(payload["verified_facts"][0]["confidence"], "medium")
            self.assertTrue(any("Uncited model claim rejected" in item for item in payload["unresolved_items"]))
            self.assertTrue(handoff["presentation_ready"])
            self.assertEqual(handoff["blockers"], [])
            self.assertEqual(handoff["key_facts"][0]["fact_id"], "F001")
            self.assertNotIn("extracted_text", handoff["sources"][0], "handoff must stay compact")
            self.assertEqual(store.get_task(task.task_id).status, TaskStatus.RESEARCH_COMPLETED)
            self.assertIn("Presentation ready: **True**", markdown)
            self.assertIn("[S1]", markdown)
            self.assertIn("https://example.com/source", markdown)


if __name__ == "__main__":
    unittest.main()
