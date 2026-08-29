import unittest

from three_agent.daily_report_schemas import DAILY_REPORT_SCHEMA_ID
from three_agent.presentation_schemas import PRESENTATION_PLAN_SCHEMA_ID
from three_agent.research_schemas import (
    RESEARCH_PLAN_SCHEMA_ID,
    RESEARCH_SYNTHESIS_SCHEMA_ID,
    SOURCE_ASSESSMENT_SCHEMA_ID,
)
from three_agent.structured_output_policy import (
    StructuredOutputPolicyClient,
    StructuredOutputPolicyError,
)


class CaptureClient:
    def __init__(self):
        self.calls = []

    def generate_json(self, system_prompt, user_prompt, **kwargs):
        self.calls.append((system_prompt, user_prompt, kwargs))
        return {"ok": True}


class StructuredOutputPolicyTests(unittest.TestCase):
    def test_research_plan_gets_versioned_schema(self):
        inner = CaptureClient()
        client = StructuredOutputPolicyClient(inner, agent_id="research")
        client.generate_json("system", "Create a concise web-research plan for this task.")
        kwargs = inner.calls[-1][2]
        self.assertEqual(kwargs["schema_id"], RESEARCH_PLAN_SCHEMA_ID)
        self.assertEqual(kwargs["schema"]["required"], ["objective", "queries", "focus"])

    def test_source_assessment_gets_versioned_schema(self):
        inner = CaptureClient()
        client = StructuredOutputPolicyClient(inner, agent_id="research")
        client.generate_json(
            "system",
            "You are a source suitability gate, not a research answer generator.",
        )
        self.assertEqual(inner.calls[-1][2]["schema_id"], SOURCE_ASSESSMENT_SCHEMA_ID)

    def test_research_synthesis_gets_versioned_schema(self):
        inner = CaptureClient()
        client = StructuredOutputPolicyClient(inner, agent_id="research")
        client.generate_json(
            "system",
            "You are completing an evidence-bounded research task using sources that already passed a suitability gate.",
        )
        kwargs = inner.calls[-1][2]
        self.assertEqual(kwargs["schema_id"], RESEARCH_SYNTHESIS_SCHEMA_ID)
        self.assertIn("verified_facts", kwargs["schema"]["required"])
        self.assertFalse(kwargs["schema"]["additionalProperties"])

    def test_presentation_gets_versioned_plan_schema(self):
        inner = CaptureClient()
        client = StructuredOutputPolicyClient(inner, agent_id="presentation")
        client.generate_json(
            "system",
            "Plan an evidence-bounded professional presentation.\nTASK TITLE: T",
        )
        kwargs = inner.calls[-1][2]
        self.assertEqual(kwargs["schema_id"], PRESENTATION_PLAN_SCHEMA_ID)
        self.assertIn("slides", kwargs["schema"]["required"])
        self.assertFalse(kwargs["schema"]["additionalProperties"])

    def test_daily_report_gets_versioned_schema(self):
        inner = CaptureClient()
        client = StructuredOutputPolicyClient(inner, agent_id="daily_report")
        client.generate_json(
            "system",
            "Create a concise Japanese R&D daily report using ONLY the JSON evidence below.\nEVIDENCE:{}",
        )
        kwargs = inner.calls[-1][2]
        self.assertEqual(kwargs["schema_id"], DAILY_REPORT_SCHEMA_ID)
        self.assertIn("work_items", kwargs["schema"]["required"])

    def test_unknown_schema_governed_path_fails_closed(self):
        for agent_id in ("research", "presentation", "daily_report"):
            with self.subTest(agent_id=agent_id):
                client = StructuredOutputPolicyClient(CaptureClient(), agent_id=agent_id)
                with self.assertRaises(StructuredOutputPolicyError):
                    client.generate_json("system", "Unknown structured operation")

    def test_unregistered_agent_remains_passthrough(self):
        inner = CaptureClient()
        client = StructuredOutputPolicyClient(inner, agent_id="future_agent")
        client.generate_json("system", "future prompt", num_predict=10)
        kwargs = inner.calls[-1][2]
        self.assertNotIn("schema", kwargs)
        self.assertNotIn("schema_id", kwargs)
        self.assertEqual(kwargs["num_predict"], 10)


if __name__ == "__main__":
    unittest.main()
