import json
import tempfile
import unittest
from pathlib import Path

from pptx import Presentation

from three_agent.artifacts import ArtifactManager
from three_agent.presentation_model import (
    EvidenceCatalog,
    PresentationOptions,
    PresentationValidationError,
    normalize_plan,
    research_is_presentable,
)
from three_agent.presentation_renderer import PptxRenderer


class PresentationAgentContractTests(unittest.TestCase):
    def research_payload(self):
        return {
            "status": "researched_with_sources",
            "verified_facts": [
                {"claim": "Product A supports feature X.", "source_ids": ["S1"]},
                {"claim": "Product B costs more than Product A.", "source_ids": ["S2"]},
            ],
            "inferences": [
                {"claim": "Product A may fit the target use case better.", "source_ids": ["S1", "S2"]}
            ],
            "unresolved_items": ["Long-term support terms are not verified."],
            "sources": [
                {"source_id": "S1", "title": "Vendor A", "url": "https://a.example", "fetch_status": "ok"},
                {"source_id": "S2", "title": "Vendor B", "url": "https://b.example", "fetch_status": "ok"},
            ],
        }

    def valid_raw_plan(self):
        return {
            "title": "Decision brief",
            "subtitle": "R&D review",
            "slides": [
                {
                    "kind": "title",
                    "title": "Decision brief",
                    "claim_refs": [],
                    "proposal_points": [],
                    "context_points": ["Internal evaluation"],
                    "speaker_notes": "Open with the decision objective.",
                },
                {
                    "kind": "comparison",
                    "title": "Verified comparison",
                    "claim_refs": ["F1", "F2"],
                    "proposal_points": [],
                    "context_points": [],
                    "speaker_notes": "Explain only the two verified points.",
                },
                {
                    "kind": "decision",
                    "title": "Recommendation",
                    "claim_refs": ["I1"],
                    "proposal_points": ["Run a two-week proof of concept."],
                    "context_points": [],
                    "speaker_notes": "Label the inference and proposal distinctly.",
                },
            ],
        }

    def test_evidence_catalog_preserves_truth_classes_and_sources(self):
        catalog = EvidenceCatalog.from_research(self.research_payload())
        claims = catalog.claim_map
        self.assertEqual(claims["F1"].kind, "verified_fact")
        self.assertEqual(claims["I1"].kind, "inference")
        self.assertEqual(claims["F1"].source_ids, ("S1",))
        self.assertEqual(claims["I1"].source_ids, ("S1", "S2"))

    def test_research_gate_requires_source_backed_claims(self):
        ready, _ = research_is_presentable(self.research_payload())
        self.assertTrue(ready)
        bad = {"status": "researched_with_sources", "verified_facts": [], "inferences": [], "sources": []}
        ready, reason = research_is_presentable(bad)
        self.assertFalse(ready)
        self.assertIn("no source-backed claims", reason)

    def test_unknown_claim_reference_is_hard_failure(self):
        catalog = EvidenceCatalog.from_research(self.research_payload())
        plan = self.valid_raw_plan()
        plan["slides"][1]["claim_refs"] = ["F999"]
        with self.assertRaises(PresentationValidationError):
            normalize_plan(plan, catalog, PresentationOptions(), "Fallback")

    def test_duplicate_titles_are_hard_failure(self):
        catalog = EvidenceCatalog.from_research(self.research_payload())
        plan = self.valid_raw_plan()
        plan["slides"][2]["title"] = plan["slides"][1]["title"]
        with self.assertRaises(PresentationValidationError):
            normalize_plan(plan, catalog, PresentationOptions(), "Fallback")

    def test_sources_and_limitations_are_deterministic(self):
        catalog = EvidenceCatalog.from_research(self.research_payload())
        plan, qa = normalize_plan(self.valid_raw_plan(), catalog, PresentationOptions(slide_count=6), "Fallback")
        self.assertEqual(qa["status"], "pass")
        self.assertTrue(qa["visible_facts_source_bounded"])
        self.assertTrue(any(slide["kind"] == "sources" for slide in plan["slides"]))
        self.assertTrue(any(slide["kind"] == "limitations" for slide in plan["slides"]))
        factual_slide = next(slide for slide in plan["slides"] if slide["title"] == "Verified comparison")
        self.assertEqual(factual_slide["claims"][0]["text"], "Product A supports feature X.")
        self.assertEqual(factual_slide["source_ids"], ["S1", "S2"])

    def test_pptx_renders_and_reopens_with_expected_titles_and_notes(self):
        catalog = EvidenceCatalog.from_research(self.research_payload())
        plan, _ = normalize_plan(self.valid_raw_plan(), catalog, PresentationOptions(slide_count=6), "Fallback")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deck.pptx"
            PptxRenderer().render(plan, path)
            self.assertTrue(path.exists())
            prs = Presentation(path)
            self.assertEqual(len(prs.slides), len(plan["slides"]))
            first_notes = prs.slides[0].notes_slide.notes_text_frame.text
            self.assertIn("decision objective", first_notes)

    def test_artifact_manager_finds_latest_cross_day_research(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            older = root / "research" / "2026-08-26"
            newer = root / "research" / "2026-08-27"
            older.mkdir(parents=True)
            newer.mkdir(parents=True)
            old_path = older / "TASK-1.json"
            new_path = newer / "TASK-1.json"
            old_path.write_text(json.dumps({"v": 1}), encoding="utf-8")
            new_path.write_text(json.dumps({"v": 2}), encoding="utf-8")
            old_path.touch()
            new_path.touch()
            manager = ArtifactManager(root)
            found = manager.find_latest_task_artifact("research", "TASK-1")
            self.assertEqual(found, new_path)


if __name__ == "__main__":
    unittest.main()
