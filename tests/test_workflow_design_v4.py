from __future__ import annotations

import unittest

from three_agent.workflow_design import (
    V4_WORKFLOW_SCHEMA,
    V4_WORKFLOW_SCHEMA_VERSION,
    WorkflowDesignCompilerV4,
    WorkflowDesignError,
    render_mermaid_v4,
    validate_contract_v4,
)


def parallel_contract():
    return {
        "title": "Parallel evidence report",
        "objective": "Run two independent evidence lanes, join them, validate the aggregate result, then report only verified work.",
        "trigger": "manual",
        "risk_level": "low",
        "data_class": "internal",
        "nodes": [
            {"id": "start", "label": "Start", "kind": "input", "action": "input", "depends_on": [], "condition": "", "approval_required": False},
            {"id": "fork", "label": "Split work", "kind": "parallel", "action": "parallel_fork", "depends_on": ["start"], "condition": "", "approval_required": False},
            {"id": "research_a", "label": "Research A", "kind": "agent", "action": "research", "depends_on": ["fork"], "condition": "", "approval_required": False},
            {"id": "research_b", "label": "Research B", "kind": "agent", "action": "research", "depends_on": ["fork"], "condition": "", "approval_required": False},
            {"id": "presentation_a", "label": "Presentation A", "kind": "agent", "action": "presentation", "depends_on": ["research_a"], "condition": "", "approval_required": False},
            {"id": "presentation_b", "label": "Presentation B", "kind": "agent", "action": "presentation", "depends_on": ["research_b"], "condition": "", "approval_required": False},
            {"id": "join", "label": "Verified join", "kind": "parallel", "action": "parallel_join", "depends_on": ["presentation_a", "presentation_b"], "condition": "", "approval_required": False},
            {"id": "gate", "label": "All lanes verified?", "kind": "decision", "action": "validate", "depends_on": ["join"], "condition": "", "approval_required": False},
            {"id": "daily", "label": "Daily report", "kind": "agent", "action": "daily_report", "depends_on": ["gate"], "condition": "passed", "approval_required": False},
            {"id": "failed", "label": "Validation failed", "kind": "output", "action": "output", "depends_on": ["gate"], "condition": "failed", "approval_required": False},
            {"id": "done", "label": "Done", "kind": "output", "action": "output", "depends_on": ["daily"], "condition": "", "approval_required": False},
        ],
        "outputs": ["Verified parallel result"],
        "warnings": [],
    }


class FakeLLM:
    def __init__(self):
        self.system = ""
        self.kwargs = {}

    def generate_json(self, system, prompt, **kwargs):
        self.system = system
        self.kwargs = kwargs
        return parallel_contract()


class WorkflowDesignV4Tests(unittest.TestCase):
    def test_extended_schema_adds_parallel_without_mutating_base_semantics(self):
        node = V4_WORKFLOW_SCHEMA["properties"]["nodes"]["items"]["properties"]
        self.assertIn("parallel", node["kind"]["enum"])
        self.assertIn("parallel_fork", node["action"]["enum"])
        self.assertIn("parallel_join", node["action"]["enum"])
        validated = validate_contract_v4(parallel_contract())
        self.assertEqual(validated["nodes"][1]["kind"], "parallel")
        self.assertEqual(validated["nodes"][6]["action"], "parallel_join")

    def test_parallel_pair_must_be_exact_and_cannot_assert_approval(self):
        payload = parallel_contract()
        payload["nodes"][1]["action"] = "research"
        with self.assertRaisesRegex(WorkflowDesignError, "parallel nodes"):
            validate_contract_v4(payload)

        payload = parallel_contract()
        payload["nodes"][1]["approval_required"] = True
        with self.assertRaisesRegex(WorkflowDesignError, "cannot require approval"):
            validate_contract_v4(payload)

    def test_mermaid_exposes_parallel_control_nodes(self):
        diagram = render_mermaid_v4(parallel_contract())
        self.assertIn('fork[["Split work"]]', diagram)
        self.assertIn('join[["Verified join"]]', diagram)
        self.assertIn("presentation_a --> join", diagram)
        self.assertIn("presentation_b --> join", diagram)

    def test_compiler_reserves_bounded_v4_parallel_semantics(self):
        llm = FakeLLM()
        result = WorkflowDesignCompilerV4(llm).compile("run two lanes in parallel", language="en")
        normalized = " ".join(llm.system.split())
        for token in (
            "exactly TWO lanes",
            "research -> presentation",
            "parallel_join",
            'condition MUST be exactly "passed" or "failed"',
            'condition MUST be exactly "approved" or "rejected"',
            "Scheduling/event triggers remain design-only",
        ):
            self.assertIn(token, normalized)
        self.assertEqual(llm.kwargs["schema_id"], V4_WORKFLOW_SCHEMA_VERSION)
        self.assertEqual(llm.kwargs["template_version"], "workspace.workflow-design.v4")
        self.assertFalse(result.execution_authorized)


if __name__ == "__main__":
    unittest.main()
