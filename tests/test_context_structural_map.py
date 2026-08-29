import json
import tempfile
import unittest
from pathlib import Path

from three_agent.context_engine import ContextEngine, _MappedKnowledgeIndexView
from three_agent.knowledge_plane import (
    InboundKnowledgeImporter,
    LocalKnowledgeIndex,
    PublicEvidenceExporter,
)
from three_agent.task_contract import TaskContractCompiler


def research_payload(source_count=1, *, text="GPU inference efficiency evidence"):
    sources = []
    assessments = []
    for index in range(1, source_count + 1):
        source_id = f"S{index}"
        sources.append(
            {
                "source_id": source_id,
                "title": f"Public note {index}",
                "url": f"https://example.com/note-{index}",
                "fetch_status": "ok",
                "extracted_text": f"{text} source {index}",
            }
        )
        assessments.append(
            {
                "source_id": source_id,
                "relevance": "high",
                "scope_match": True,
                "time_match": True,
                "authority": "primary",
            }
        )
    return {
        "task_id": "TASK-20260829-0001",
        "generated_at": "2026-08-29T10:00:00+09:00",
        "sources": sources,
        "source_assessments": assessments,
        "rejected_sources": [],
    }


def contract(*, retrieved_budget=5000):
    base = TaskContractCompiler().compile(
        task_id="TASK-20260829-0001",
        task_type="retrieval",
        sensitivity="confidential",
    )
    return base.__class__(
        **{
            **base.__dict__,
            "context_budget": base.context_budget.__class__(
                max_input_tokens=8192,
                max_retrieved_tokens=retrieved_budget,
                max_tool_output_tokens=1024,
                reserve_tokens=256,
            ),
        }
    )


class CountingIndex(LocalKnowledgeIndex):
    def __init__(self, root):
        super().__init__(root)
        self.map_calls = 0

    def map(self):
        self.map_calls += 1
        return super().map()


class ExplodingMapIndex(LocalKnowledgeIndex):
    def map(self):
        raise AssertionError("zero retrieval budget must short-circuit before map")


class ContextStructuralMapTests(unittest.TestCase):
    def _index(self, base: Path, *, source_count=2):
        exported = PublicEvidenceExporter(base / "out").export_research_payload(
            research_payload(source_count)
        )
        InboundKnowledgeImporter(base / "core").import_bundle(exported)
        return base / "core"

    def test_context_engine_reads_structural_map_once_before_body_search(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._index(Path(tmp), source_count=3)
            index = CountingIndex(root)
            packed = ContextEngine(index).build_public_evidence(
                "GPU inference efficiency",
                contract(),
                max_hits=3,
            )
            self.assertEqual(index.map_calls, 1)
            trace = packed.retrieval_trace
            self.assertTrue(trace["map_before_body_retrieval"])
            self.assertEqual(trace["structural_map"]["map_entries_total"], 3)
            self.assertEqual(trace["ranking_strategy"], "deterministic_lexical_v1")
            self.assertTrue(trace["hard_budget_respected"])
            self.assertFalse(trace["progressive_body_expansion"])

    def test_cached_map_view_preserves_existing_search_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._index(Path(tmp), source_count=3)
            index = LocalKnowledgeIndex(root)
            source_map = index.map()
            direct = index.search(
                "GPU inference efficiency",
                max_hits=5,
                max_chars=20000,
            )
            cached = _MappedKnowledgeIndexView(index, source_map).search(
                "GPU inference efficiency",
                max_hits=5,
                max_chars=20000,
            )
            self.assertEqual(
                [item.to_dict() for item in direct],
                [item.to_dict() for item in cached],
            )

    def test_structural_receipt_is_bounded_and_never_emits_titles_urls_or_body(self):
        source_map = [
            {
                "bundle_id": f"kb_{index:024x}",
                "source_id": f"S{index}",
                "title": f"SECRET TITLE {index}",
                "url": f"https://example.com/secret-{index}",
                "injection_risk": "high" if index % 2 else "low",
            }
            for index in range(100)
        ]
        receipt = ContextEngine._structural_receipt(source_map, max_hits=20)
        self.assertEqual(receipt["map_entries_total"], 100)
        self.assertEqual(receipt["preview_limit"], 64)
        self.assertEqual(receipt["preview_entries"], 64)
        self.assertFalse(receipt["body_text_in_preview"])
        serialized = json.dumps(receipt)
        self.assertNotIn("SECRET TITLE", serialized)
        self.assertNotIn("example.com", serialized)

    def test_zero_budget_short_circuits_before_map_or_body_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            packed = ContextEngine(ExplodingMapIndex(Path(tmp))).build_public_evidence(
                "GPU inference",
                contract(retrieved_budget=0),
                max_hits=5,
            )
            self.assertEqual(packed.text, "")
            self.assertEqual(packed.budget_units_used, 0)
            self.assertEqual(packed.retrieval_trace["reason"], "zero_retrieval_budget")
            self.assertFalse(packed.retrieval_trace["map_before_body_retrieval"])

    def test_provenance_header_is_never_partially_emitted_under_tiny_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._index(Path(tmp), source_count=1)
            packed = ContextEngine(LocalKnowledgeIndex(root)).build_public_evidence(
                "GPU inference efficiency",
                contract(retrieved_budget=10),
                max_hits=1,
            )
            self.assertEqual(packed.text, "")
            self.assertEqual(packed.evidence, ())
            self.assertFalse(
                packed.retrieval_trace["critical_provenance_header_truncated"]
            )
            self.assertTrue(packed.retrieval_trace["hard_budget_respected"])


if __name__ == "__main__":
    unittest.main()
