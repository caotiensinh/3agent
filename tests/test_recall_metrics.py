import tempfile
import unittest
from pathlib import Path

from three_agent.artifacts import ArtifactManager
from three_agent.recall_metrics import ContextRecallProxyAggregator
from three_agent.research_quality import build_handoff, synthesis_context_proxy_accounting
from three_agent.store import TaskStore


def _source(source_id: str, text: str, *, title: str = "T", url: str = "https://example.com/x") -> dict:
    return {
        "source_id": source_id,
        "title": title,
        "url": url,
        "fetch_status": "ok",
        "extracted_text": text,
    }


def _assessment(source_id: str, relevance: str = "high", scope_match: bool = True) -> dict:
    return {
        "source_id": source_id,
        "relevance": relevance,
        "scope_match": scope_match,
        "time_match": True,
        "authority": "primary",
        "reason": "test",
    }


class ContextRecallProxyTests(unittest.TestCase):
    def test_full_budget_retains_all_vetted_source_text(self):
        research = {
            "sources": [_source("S1", "a" * 100), _source("S2", "b" * 200)],
            "source_assessments": [_assessment("S1"), _assessment("S2")],
            "verified_facts": [],
            "inferences": [],
            "conflicts": [],
            "source_assessment_error": None,
        }
        metric = synthesis_context_proxy_accounting(research)
        self.assertEqual(metric["synthesis_vetted_source_count"], 2)
        self.assertEqual(metric["synthesis_supplied_source_count"], 2)
        self.assertEqual(metric["synthesis_vetted_source_text_chars"], 300)
        self.assertEqual(metric["synthesis_supplied_source_text_chars"], 300)
        self.assertEqual(metric["context_recall_proxy"], 1.0)

    def test_context_budget_truncation_reduces_recall_proxy(self):
        source = _source("S1", "abcdefghij", title="A", url="https://e.test/x")
        header = "[S1]\nTITLE: A\nURL: https://e.test/x\nTEXT:\n"
        research = {
            "sources": [source],
            "source_assessments": [_assessment("S1")],
            "verified_facts": [],
            "inferences": [],
            "conflicts": [],
            "source_assessment_error": None,
        }
        metric = synthesis_context_proxy_accounting(research, max_total=len(header) + 4)
        self.assertEqual(metric["synthesis_vetted_source_text_chars"], 10)
        self.assertEqual(metric["synthesis_supplied_source_text_chars"], 4)
        self.assertEqual(metric["context_recall_proxy"], 0.4)

    def test_unvetted_source_is_not_in_recall_denominator(self):
        research = {
            "sources": [_source("S1", "a" * 10), _source("S2", "b" * 90)],
            "source_assessments": [
                _assessment("S1"),
                _assessment("S2", relevance="low", scope_match=False),
            ],
            "verified_facts": [],
            "inferences": [],
            "conflicts": [],
            "source_assessment_error": None,
        }
        metric = synthesis_context_proxy_accounting(research)
        self.assertEqual(metric["synthesis_vetted_source_count"], 1)
        self.assertEqual(metric["synthesis_vetted_source_text_chars"], 10)
        self.assertEqual(metric["context_recall_proxy"], 1.0)

    def test_build_handoff_embeds_recall_proxy_contract(self):
        research = {
            "task_id": "TASK-1",
            "sources": [_source("S1", "evidence")],
            "source_assessments": [_assessment("S1")],
            "verified_facts": [
                {"claim": "Fact", "source_ids": ["S1"], "confidence": "medium"}
            ],
            "inferences": [],
            "conflicts": [],
            "unresolved_items": [],
            "constraint_gaps": [],
            "rejected_numeric_claims": [],
            "rejected_sources": [],
            "source_assessment_error": None,
            "synthesis_error": None,
        }
        quality = build_handoff(research)["quality_metrics"]
        self.assertEqual(quality["context_recall_proxy_kind"], "vetted_source_char_retention_proxy")
        self.assertEqual(quality["context_recall_proxy_scope"], "research_synthesis_context_budget")
        self.assertEqual(quality["synthesis_vetted_source_text_chars"], 8)
        self.assertEqual(quality["synthesis_supplied_source_text_chars"], 8)
        self.assertEqual(quality["context_recall_proxy"], 1.0)

    def test_aggregator_sums_chars_before_computing_ratio(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TaskStore(root / "tasks.db")
            store.initialize()
            artifacts = ArtifactManager(root / "data")
            first = store.create_task("A", "A")
            second = store.create_task("B", "B")
            artifacts.write_research_handoff(
                first.task_id,
                {
                    "quality_metrics": {
                        "context_recall_proxy_kind": "vetted_source_char_retention_proxy",
                        "context_recall_proxy_scope": "research_synthesis_context_budget",
                        "synthesis_vetted_source_count": 1,
                        "synthesis_supplied_source_count": 1,
                        "synthesis_vetted_source_text_chars": 100,
                        "synthesis_supplied_source_text_chars": 100,
                        "context_recall_proxy": 1.0,
                    }
                },
            )
            artifacts.write_research_handoff(
                second.task_id,
                {
                    "quality_metrics": {
                        "context_recall_proxy_kind": "vetted_source_char_retention_proxy",
                        "context_recall_proxy_scope": "research_synthesis_context_budget",
                        "synthesis_vetted_source_count": 3,
                        "synthesis_supplied_source_count": 1,
                        "synthesis_vetted_source_text_chars": 300,
                        "synthesis_supplied_source_text_chars": 0,
                        "context_recall_proxy": 0.0,
                    }
                },
            )
            result = ContextRecallProxyAggregator(store, artifacts).snapshot()
            self.assertEqual(result.synthesis_vetted_source_text_chars, 400)
            self.assertEqual(result.synthesis_supplied_source_text_chars, 100)
            self.assertEqual(result.context_recall_proxy, 0.25)

    def test_missing_and_inconsistent_handoffs_are_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TaskStore(root / "tasks.db")
            store.initialize()
            artifacts = ArtifactManager(root / "data")
            missing = store.create_task("Missing", "Missing")
            bad = store.create_task("Bad", "Bad")
            artifacts.write_research_handoff(
                bad.task_id,
                {
                    "quality_metrics": {
                        "context_recall_proxy_kind": "vetted_source_char_retention_proxy",
                        "context_recall_proxy_scope": "research_synthesis_context_budget",
                        "synthesis_vetted_source_count": 1,
                        "synthesis_supplied_source_count": 2,
                        "synthesis_vetted_source_text_chars": 10,
                        "synthesis_supplied_source_text_chars": 11,
                        "context_recall_proxy": 1.1,
                    }
                },
            )
            result = ContextRecallProxyAggregator(store, artifacts).snapshot(
                [missing.task_id, bad.task_id]
            )
            self.assertEqual(result.tasks_with_recall_accounting, 0)
            self.assertEqual(result.tasks_without_recall_accounting, 2)
            self.assertEqual(result.malformed_handoffs, 1)
            self.assertIsNone(result.context_recall_proxy)

    def test_metric_payload_labels_itself_as_proxy_not_semantic_recall(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TaskStore(root / "tasks.db")
            store.initialize()
            payload = ContextRecallProxyAggregator(
                store, ArtifactManager(root / "data")
            ).snapshot([]).to_dict()
            self.assertEqual(payload["schema_version"], "workspace-context-recall-proxy/v1")
            self.assertEqual(payload["proxy_kind"], "vetted_source_char_retention_proxy")
            self.assertIsNone(payload["true_semantic_recall"])


if __name__ == "__main__":
    unittest.main()
