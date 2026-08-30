import os
import unittest
from unittest.mock import patch

from three_agent.agents import ResearchAgent
from three_agent.evidence_packing import PACKING_RECEIPT_SCHEMA
from three_agent.web_research import ResearchSource


class DuplicateCitationLLM:
    def generate_json(self, *args, **kwargs):
        return {
            "verified_facts": [
                {
                    "claim": "The supplied evidence supports this fact.",
                    "source_ids": ["S1", "S2"],
                    "evidence_quotes": [],
                }
            ],
            "inferences": [
                {
                    "claim": "This claim relies only on the suppressed mirror.",
                    "source_ids": ["S2"],
                }
            ],
            "conflicts": [
                {
                    "topic": "mirror conflict",
                    "description": "identical bodies must not become two-sided evidence",
                    "severity": "medium",
                    "source_ids": ["S1", "S2"],
                }
            ],
            "unresolved": [],
            "conclusion": "Done",
            "recommended_next_actions": [],
        }


def _source(source_id: str, body: str) -> ResearchSource:
    return ResearchSource(
        source_id=source_id,
        title=f"Source {source_id}",
        url=f"https://example.test/{source_id}",
        search_snippet="",
        extracted_text=body,
        fetch_status="ok",
    )


def _assessment(source_id: str) -> dict:
    return {
        "source_id": source_id,
        "relevance": "high",
        "scope_match": True,
        "time_match": True,
        "authority": "primary",
        "reason": "test",
    }


class SynthesisCitationScopeTests(unittest.TestCase):
    def test_exact_duplicate_cannot_inflate_corroboration_or_support_mirror_only_claim(self):
        body = "identical complete evidence body"
        sources = [_source("S1", body), _source("S2", body)]
        assessments = [_assessment("S1"), _assessment("S2")]
        agent = ResearchAgent.__new__(ResearchAgent)
        agent.llm = DuplicateCitationLLM()
        agent.profile = lambda: "profile"

        with patch.dict(
            os.environ,
            {
                "WORKSPACE_EVIDENCE_PACKING_MODE": "legacy_v1",
                "WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS": "48000",
                "WORKSPACE_EVIDENCE_EXACT_BODY_DEDUPE": "true",
            },
            clear=False,
        ):
            result = agent._synthesize(
                "title",
                "request",
                "objective",
                [],
                sources,
                assessments,
            )

        self.assertTrue(assessments[0]["synthesis_supplied"])
        self.assertFalse(assessments[1]["synthesis_supplied"])
        self.assertTrue(
            assessments[1]["synthesis_exact_body_duplicate_suppressed"]
        )
        self.assertEqual(assessments[1]["synthesis_duplicate_of_source_id"], "S1")

        self.assertEqual(len(result["verified_facts"]), 1)
        fact = result["verified_facts"][0]
        self.assertEqual(fact["source_ids"], ["S1"])
        self.assertEqual(fact["confidence"], "medium")
        self.assertEqual(result["inferences"], [])
        self.assertEqual(result["conflicts"], [])
        self.assertTrue(
            any(
                item.startswith("Uncited model inference rejected:")
                and "suppressed mirror" in item
                for item in result["unresolved"]
            )
        )

    def test_receipt_projection_makes_unsupplied_source_uncitable(self):
        sources = [_source("S1", "alpha"), _source("S2", "beta")]
        assessments = [
            _assessment("S1")
            | {
                "synthesis_packing_receipt_version": PACKING_RECEIPT_SCHEMA,
                "synthesis_supplied": True,
            },
            _assessment("S2")
            | {
                "synthesis_packing_receipt_version": PACKING_RECEIPT_SCHEMA,
                "synthesis_supplied": False,
            },
        ]

        supplied = ResearchAgent._supplied_sources_after_pack(sources, assessments)
        self.assertEqual([source.source_id for source in supplied], ["S1"])

    def test_partial_packing_receipt_citation_scope_fails_closed(self):
        sources = [_source("S1", "alpha"), _source("S2", "beta")]
        assessments = [
            _assessment("S1")
            | {
                "synthesis_packing_receipt_version": PACKING_RECEIPT_SCHEMA,
                "synthesis_supplied": True,
            },
            _assessment("S2"),
        ]

        with self.assertRaisesRegex(
            ValueError,
            "SYNTHESIS_PACKING_RECEIPT_CITATION_SCOPE_INVALID",
        ):
            ResearchAgent._supplied_sources_after_pack(sources, assessments)


if __name__ == "__main__":
    unittest.main()
