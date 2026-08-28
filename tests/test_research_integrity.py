import unittest

from three_agent.research_integrity import (
    clean_source_assessments,
    core_constraint_gaps,
    detect_request_constraints,
    enforce_numeric_evidence,
    vetted_source_ids,
)


class ResearchIntegrityTests(unittest.TestCase):
    def test_irrelevant_source_is_not_vetted(self):
        assessments = clean_source_assessments(
            [
                {
                    "source_id": "S1",
                    "relevance": "high",
                    "scope_match": True,
                    "time_match": True,
                    "authority": "primary",
                    "reason": "Official product ranking",
                },
                {
                    "source_id": "S2",
                    "relevance": "low",
                    "scope_match": False,
                    "time_match": None,
                    "authority": "unknown",
                    "reason": "Video conferencing page unrelated to products",
                },
            ],
            {"S1", "S2"},
        )
        self.assertEqual(vetted_source_ids(assessments), {"S1"})

    def test_hallucinated_sales_number_is_rejected(self):
        claims = [
            {
                "claim": "The product sold 39,478 units this week.",
                "source_ids": ["S1"],
                "confidence": "medium",
                "evidence_quotes": [
                    {"source_id": "S1", "quote": "The product is ranked #1 in the category."}
                ],
            }
        ]
        accepted, rejected = enforce_numeric_evidence(
            claims,
            {"S1": "The product is ranked #1 in the category."},
        )
        self.assertEqual(accepted, [])
        self.assertEqual(len(rejected), 1)
        self.assertIn("39,478", rejected[0])

    def test_verbatim_numeric_claim_is_accepted(self):
        claims = [
            {
                "claim": "The battery supports up to 30 hours of video playback.",
                "source_ids": ["S1"],
                "confidence": "medium",
                "evidence_quotes": [
                    {"source_id": "S1", "quote": "Video playback: Up to 30 hours"}
                ],
            }
        ]
        accepted, rejected = enforce_numeric_evidence(
            claims,
            {"S1": "Battery information. Video playback: Up to 30 hours. More details."},
        )
        self.assertEqual(len(accepted), 1)
        self.assertEqual(rejected, [])

    def test_current_ranking_requires_fresh_time_matched_evidence(self):
        request = "Find the current top 5 best sellers and weekly sales volume across all categories."
        constraints = detect_request_constraints(request)
        self.assertTrue(constraints["temporal"])
        self.assertTrue(constraints["ranking"])
        self.assertTrue(constraints["quantity"])
        assessments = [
            {
                "source_id": "S1",
                "relevance": "high",
                "scope_match": True,
                "time_match": False,
                "authority": "primary",
            }
        ]
        gaps = core_constraint_gaps(request, [], assessments)
        self.assertIn("FRESHNESS_UNVERIFIED", gaps)
        self.assertIn("QUANTITATIVE_EVIDENCE_MISSING", gaps)
        self.assertIn("RANKING_SCOPE_UNVERIFIED", gaps)


if __name__ == "__main__":
    unittest.main()
