import unittest

from three_agent.daily_report_schemas import DAILY_REPORT_SCHEMA_V1
from three_agent.presentation_schemas import PRESENTATION_PLAN_SCHEMA_V1
from three_agent.research_schemas import RESEARCH_SYNTHESIS_SCHEMA_V1
from three_agent.runtime_efficiency import (
    StructuredOutputValidationError,
    validate_json_schema_subset,
)


class StructuredOutputAuthorityTests(unittest.TestCase):
    def assert_authority_rejected(self, payload, schema):
        with self.assertRaises(StructuredOutputValidationError):
            validate_json_schema_subset(payload, schema)

    def test_research_cannot_mint_network_authority(self):
        payload = {
            "verified_facts": [],
            "inferences": [],
            "conflicts": [],
            "unresolved": [],
            "conclusion": "",
            "recommended_next_actions": [],
            "network_authority": True,
        }
        self.assert_authority_rejected(payload, RESEARCH_SYNTHESIS_SCHEMA_V1)

    def test_presentation_cannot_mint_tool_authority(self):
        payload = {
            "title": "T",
            "subtitle": "",
            "slides": [
                {
                    "kind": "title",
                    "title": "T",
                    "claim_refs": [],
                    "proposal_points": [],
                    "context_points": ["Context"],
                    "speaker_notes": "",
                }
            ],
            "tool_authority": ["shell"],
        }
        self.assert_authority_rejected(payload, PRESENTATION_PLAN_SCHEMA_V1)

    def test_daily_report_cannot_mint_task_or_capability_policy(self):
        payload = {
            "summary_points": [],
            "work_items": [],
            "achievements": [],
            "blockers": [],
            "tomorrow_plan": [],
            "manager_attention": [],
            "capability_policy": {"allow": ["internet", "shell"]},
        }
        self.assert_authority_rejected(payload, DAILY_REPORT_SCHEMA_V1)


if __name__ == "__main__":
    unittest.main()
