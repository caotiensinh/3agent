import os
import unittest
from unittest.mock import patch

from three_agent.agents import ResearchAgent
from three_agent.agents.research import ResearchAgent as BaseResearchAgent
from three_agent.evidence_packing import (
    EvidencePackingPolicy,
    LEGACY_PACKING_MODE,
    QUALITY_RANKED_PACKING_MODE,
    rank_vetted_sources,
    resolve_evidence_packing_policy,
)


class Source:
    def __init__(self, source_id: str):
        self.source_id = source_id


class EvidencePackingTests(unittest.TestCase):
    def setUp(self):
        self.sources = [Source("S1"), Source("S2"), Source("S3")]
        self.assessments = [
            {
                "source_id": "S1",
                "relevance": "high",
                "scope_match": True,
                "time_match": False,
                "authority": "secondary",
            },
            {
                "source_id": "S2",
                "relevance": "medium",
                "scope_match": True,
                "time_match": True,
                "authority": "primary",
            },
            {
                "source_id": "S3",
                "relevance": "high",
                "scope_match": True,
                "time_match": True,
                "authority": "unknown",
            },
        ]

    def test_default_policy_is_legacy_with_exact_body_dedupe_off(self):
        with patch.dict(os.environ, {}, clear=True):
            policy = resolve_evidence_packing_policy()
        self.assertEqual(policy.mode, LEGACY_PACKING_MODE)
        self.assertFalse(policy.exact_body_dedupe)

    def test_exact_body_dedupe_is_explicit_opt_in(self):
        policy = resolve_evidence_packing_policy(
            {"WORKSPACE_EVIDENCE_EXACT_BODY_DEDUPE": "true"}
        )
        self.assertTrue(policy.exact_body_dedupe)
        fingerprint = policy.to_fingerprint_dict()
        self.assertTrue(fingerprint["exact_body_dedupe"])
        self.assertEqual(
            fingerprint["schema_version"],
            "workspace-evidence-packing-policy/v3",
        )

    def test_invalid_exact_body_dedupe_value_fails_closed(self):
        with self.assertRaises(ValueError):
            resolve_evidence_packing_policy(
                {"WORKSPACE_EVIDENCE_EXACT_BODY_DEDUPE": "sometimes"}
            )

    def test_invalid_policy_fails_closed(self):
        with self.assertRaises(ValueError):
            resolve_evidence_packing_policy(
                {"WORKSPACE_EVIDENCE_PACKING_MODE": "model-decides"}
            )

    def test_legacy_mode_preserves_collection_order(self):
        ranked, receipt = rank_vetted_sources(
            self.sources,
            self.assessments,
            policy=EvidencePackingPolicy(LEGACY_PACKING_MODE),
        )
        self.assertEqual([source.source_id for source in ranked], ["S1", "S2", "S3"])
        self.assertEqual([item["source_id"] for item in receipt], ["S1", "S2", "S3"])

    def test_quality_rank_prioritizes_fresh_relevant_authoritative_sources(self):
        ranked, receipt = rank_vetted_sources(
            self.sources,
            self.assessments,
            policy=EvidencePackingPolicy(QUALITY_RANKED_PACKING_MODE),
        )
        self.assertEqual([source.source_id for source in ranked], ["S3", "S2", "S1"])
        self.assertGreater(receipt[0]["score"], receipt[1]["score"])
        self.assertGreater(receipt[1]["score"], receipt[2]["score"])
        for item in receipt:
            self.assertNotIn("url", item)
            self.assertNotIn("title", item)
            self.assertNotIn("text", item)

    def test_equal_scores_preserve_original_order(self):
        assessments = [
            {
                "source_id": source.source_id,
                "relevance": "high",
                "scope_match": True,
                "time_match": None,
                "authority": "primary",
            }
            for source in self.sources
        ]
        ranked, _ = rank_vetted_sources(
            self.sources,
            assessments,
            policy=EvidencePackingPolicy(QUALITY_RANKED_PACKING_MODE),
        )
        self.assertEqual([source.source_id for source in ranked], ["S1", "S2", "S3"])

    def test_exported_research_agent_reorders_payload_and_vetted_sources_together(self):
        rejected = Source("S4")
        sources = [self.sources[0], rejected, self.sources[1], self.sources[2]]
        assessments = [dict(item) for item in self.assessments]
        assessments.append(
            {
                "source_id": "S4",
                "relevance": "low",
                "scope_match": False,
                "time_match": None,
                "authority": "unknown",
            }
        )
        vetted = [self.sources[0], self.sources[1], self.sources[2]]
        agent = ResearchAgent.__new__(ResearchAgent)

        with patch.object(
            BaseResearchAgent,
            "_assess_sources",
            return_value=(assessments, vetted, None),
        ), patch.dict(
            os.environ,
            {"WORKSPACE_EVIDENCE_PACKING_MODE": QUALITY_RANKED_PACKING_MODE},
            clear=False,
        ):
            returned_assessments, returned_vetted, error = agent._assess_sources(
                "request", "objective", sources
            )

        self.assertIsNone(error)
        self.assertEqual(
            [source.source_id for source in returned_vetted],
            ["S3", "S2", "S1"],
        )
        self.assertEqual(
            [source.source_id for source in sources],
            ["S3", "S2", "S1", "S4"],
        )
        by_id = {item["source_id"]: item for item in returned_assessments}
        self.assertEqual(by_id["S3"]["synthesis_rank"], 1)
        self.assertEqual(by_id["S2"]["synthesis_rank"], 2)
        self.assertEqual(by_id["S1"]["synthesis_rank"], 3)
        self.assertNotIn("synthesis_rank", by_id["S4"])
        self.assertEqual(
            by_id["S3"]["synthesis_packing_mode"],
            QUALITY_RANKED_PACKING_MODE,
        )
        self.assertFalse(by_id["S3"]["synthesis_exact_body_dedupe_enabled"])


if __name__ == "__main__":
    unittest.main()
