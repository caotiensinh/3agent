import unittest

from three_agent.workflow_design import (
    WorkflowDesignCompiler,
    WorkflowDesignError,
    render_mermaid,
    render_svg,
    validate_contract,
)


class FakeLLM:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def generate_json(self, system_prompt, user_prompt, **kwargs):
        self.calls.append((system_prompt, user_prompt, kwargs))
        return self.payload


def sample_contract():
    return {
        "title": "Weekly management workflow",
        "objective": "Collect metrics, validate them, request approval, and deliver a report.",
        "trigger": "schedule",
        "risk_level": "medium",
        "data_class": "internal",
        "nodes": [
            {"id": "start", "label": "Weekly trigger", "kind": "input", "action": "input", "depends_on": [], "condition": "", "approval_required": False},
            {"id": "research", "label": "Collect project metrics", "kind": "agent", "action": "research", "depends_on": ["start"], "condition": "", "approval_required": False},
            {"id": "check", "label": "Validate evidence", "kind": "validation", "action": "validate", "depends_on": ["research"], "condition": "", "approval_required": False},
            {"id": "approve", "label": "Manager approval", "kind": "approval", "action": "human_approval", "depends_on": ["check"], "condition": "validation passed", "approval_required": True},
            {"id": "done", "label": "Approved report", "kind": "output", "action": "output", "depends_on": ["approve"], "condition": "", "approval_required": False},
        ],
        "outputs": ["Approved management report"],
        "warnings": [],
    }


class WorkflowDesignTests(unittest.TestCase):
    def test_compiler_uses_one_local_structured_call_and_never_authorizes_execution(self):
        llm = FakeLLM(sample_contract())
        result = WorkflowDesignCompiler(llm).compile(
            "Every Monday collect metrics, validate, get manager approval, then report.",
            language="en",
        )
        self.assertEqual(len(llm.calls), 1)
        self.assertFalse(result.execution_authorized)
        self.assertEqual(result.execution_mode, "design_only")
        self.assertIn("flowchart TD", result.mermaid)
        self.assertIn("<svg", result.svg)
        kwargs = llm.calls[0][2]
        self.assertFalse(kwargs["think"])
        self.assertEqual(kwargs["schema_id"], "workspace-workflow-contract/v1")
        self.assertLessEqual(kwargs["num_predict"], 1400)

    def test_cycle_is_rejected_deterministically(self):
        payload = sample_contract()
        payload["nodes"][0]["depends_on"] = ["done"]
        with self.assertRaisesRegex(WorkflowDesignError, "cycle"):
            validate_contract(payload)

    def test_unknown_action_is_rejected_instead_of_becoming_tool_authority(self):
        payload = sample_contract()
        payload["nodes"][1]["action"] = "shell"
        with self.assertRaisesRegex(WorkflowDesignError, "unsupported workflow action"):
            validate_contract(payload)

    def test_svg_and_mermaid_escape_untrusted_labels(self):
        payload = sample_contract()
        payload["nodes"][1]["label"] = '<script>alert("x")</script> [danger]'
        svg = render_svg(payload)
        mermaid = render_mermaid(payload)
        self.assertNotIn("<script>", svg)
        self.assertIn("&lt;script&gt;", svg)
        self.assertNotIn("[danger]", mermaid)
        self.assertNotIn('"x"', mermaid)

    def test_schedule_trigger_is_design_only_and_adds_warning(self):
        contract = validate_contract(sample_contract())
        self.assertTrue(
            any("design only" in warning.lower() for warning in contract["warnings"])
        )

    def test_high_risk_without_approval_is_warned_not_silently_executable(self):
        payload = sample_contract()
        payload["risk_level"] = "high"
        payload["nodes"] = [node for node in payload["nodes"] if node["id"] != "approve"]
        payload["nodes"][-1]["depends_on"] = ["check"]
        contract = validate_contract(payload)
        self.assertTrue(any("approval" in warning.lower() for warning in contract["warnings"]))


if __name__ == "__main__":
    unittest.main()
