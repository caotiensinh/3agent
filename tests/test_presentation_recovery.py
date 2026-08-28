import unittest

from three_agent.agents.presentation import PresentationAgent
from three_agent.presentation_model import EvidenceCatalog, PresentationOptions, normalize_plan


class PresentationRecoveryTests(unittest.TestCase):
    @staticmethod
    def handoff_payload():
        return {
            "schema_version": "1.0",
            "task_id": "TASK-1",
            "presentation_ready": True,
            "blockers": [],
            "key_facts": [
                {
                    "fact_id": "F001",
                    "claim": "Verified fact one.",
                    "source_ids": ["S1"],
                    "confidence": "medium",
                },
                {
                    "fact_id": "F002",
                    "claim": "Verified fact two.",
                    "source_ids": ["S2"],
                    "confidence": "medium",
                },
            ],
            "inferences": [],
            "conflicts": [],
            "unresolved_items": [],
            "conclusion": "",
            "recommended_next_actions": ["Run a controlled evaluation."],
            "sources": [
                {"source_id": "S1", "title": "Source 1", "url": "https://one.example", "fetch_status": "ok"},
                {"source_id": "S2", "title": "Source 2", "url": "https://two.example", "fetch_status": "ok"},
            ],
        }

    def test_empty_non_title_model_slides_are_dropped_before_validation(self):
        raw = {
            "title": "Weekly brief",
            "subtitle": "R&D",
            "slides": [
                {
                    "kind": "title",
                    "title": "Weekly brief",
                    "claim_refs": [],
                    "proposal_points": [],
                    "context_points": ["Weekly review"],
                    "speaker_notes": "",
                },
                {
                    "kind": "content",
                    "title": "Verified update",
                    "claim_refs": ["F001", "F002"],
                    "proposal_points": [],
                    "context_points": [],
                    "speaker_notes": "",
                },
                {
                    "kind": "risks",
                    "title": "Risks",
                    "claim_refs": [],
                    "proposal_points": [],
                    "context_points": [],
                    "speaker_notes": "Model emitted an empty placeholder.",
                },
                {
                    "kind": "timeline",
                    "title": "Timeline",
                    "claim_refs": [],
                    "proposal_points": [],
                    "context_points": [],
                    "speaker_notes": "Another empty placeholder.",
                },
                {
                    "kind": "decision",
                    "title": "Next action",
                    "claim_refs": [],
                    "proposal_points": ["Run a controlled evaluation."],
                    "context_points": [],
                    "speaker_notes": "",
                },
            ],
        }

        sanitized, dropped = PresentationAgent._drop_empty_model_slides(raw)
        self.assertEqual(dropped, [3, 4])
        self.assertEqual(
            [slide["title"] for slide in sanitized["slides"]],
            ["Weekly brief", "Verified update", "Next action"],
        )

        catalog = EvidenceCatalog.from_handoff(self.handoff_payload())
        plan, qa = normalize_plan(
            sanitized,
            catalog,
            PresentationOptions(slide_count=6),
            "Fallback",
        )
        self.assertEqual(qa["status"], "pass")
        self.assertEqual(len({slide["slide_id"] for slide in plan["slides"]}), len(plan["slides"]))
        self.assertNotIn("Risks", [slide["title"] for slide in plan["slides"]])
        self.assertNotIn("Timeline", [slide["title"] for slide in plan["slides"]])

    def test_unknown_claim_reference_is_not_hidden_by_recovery(self):
        raw = {
            "slides": [
                {"kind": "title", "title": "Title", "claim_refs": [], "proposal_points": [], "context_points": ["Scope"]},
                {"kind": "content", "title": "Bad ref", "claim_refs": ["F999"], "proposal_points": [], "context_points": []},
            ]
        }
        sanitized, dropped = PresentationAgent._drop_empty_model_slides(raw)
        self.assertEqual(dropped, [])
        self.assertEqual(sanitized, raw)


if __name__ == "__main__":
    unittest.main()
