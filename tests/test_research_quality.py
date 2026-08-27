import unittest

from three_agent.research_quality import build_handoff, clean_claims, clean_conflicts


class ResearchQualityTests(unittest.TestCase):
    def test_clean_claims_deduplicates_and_merges_sources(self):
        claims, rejected = clean_claims(
            [
                {"claim": "  Same   fact. ", "source_ids": ["S1"]},
                {"claim": "Same fact", "source_ids": ["S2", "S1"]},
                {"claim": "Unsupported", "source_ids": ["S9"]},
            ],
            {"S1", "S2"},
        )
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0]["source_ids"], ["S1", "S2"])
        self.assertEqual(claims[0]["confidence"], "high")
        self.assertEqual(rejected, ["Unsupported"])

    def test_conflict_requires_two_valid_sources(self):
        conflicts = clean_conflicts(
            [
                {
                    "topic": "Version",
                    "description": "Sources disagree on the supported version.",
                    "severity": "critical",
                    "source_ids": ["S1", "S2"],
                },
                {
                    "topic": "Invalid",
                    "description": "Only one source.",
                    "severity": "critical",
                    "source_ids": ["S1"],
                },
            ],
            {"S1", "S2"},
        )
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["severity"], "critical")

    def test_handoff_blocks_critical_conflict(self):
        research = {
            "task_id": "TASK-1",
            "objective": "Verify",
            "sources": [
                {"source_id": "S1", "title": "A", "url": "https://a", "fetch_status": "ok", "extracted_text": "A"},
                {"source_id": "S2", "title": "B", "url": "https://b", "fetch_status": "ok", "extracted_text": "B"},
            ],
            "verified_facts": [
                {"claim": "Fact", "source_ids": ["S1", "S2"], "confidence": "high"}
            ],
            "inferences": [],
            "conflicts": [
                {
                    "topic": "Critical",
                    "description": "Contradiction",
                    "severity": "critical",
                    "source_ids": ["S1", "S2"],
                }
            ],
            "unresolved_items": [],
            "conclusion": "",
            "recommended_next_actions": [],
            "generated_at": "2026-08-27T00:00:00+09:00",
        }
        handoff = build_handoff(research)
        self.assertFalse(handoff["presentation_ready"])
        self.assertIn("CRITICAL_SOURCE_CONFLICT", handoff["blockers"])
        self.assertNotIn("extracted_text", handoff["sources"][0])


if __name__ == "__main__":
    unittest.main()
