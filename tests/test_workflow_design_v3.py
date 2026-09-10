from __future__ import annotations

import unittest

from three_agent.workflow_design import WorkflowDesignCompilerV3


class FakeLLM:
    def __init__(self):
        self.system = ""
        self.kwargs = {}

    def generate_json(self, system, prompt, **kwargs):
        self.system = system
        self.kwargs = kwargs
        return {
            "title": "Approval flow",
            "objective": "Validate then approve",
            "trigger": "manual",
            "risk_level": "low",
            "data_class": "internal",
            "nodes": [
                {"id": "start", "label": "Start", "kind": "input", "action": "input", "depends_on": [], "condition": "", "approval_required": False},
                {"id": "research", "label": "Research", "kind": "agent", "action": "research", "depends_on": ["start"], "condition": "", "approval_required": False},
                {"id": "decision", "label": "Valid?", "kind": "decision", "action": "validate", "depends_on": ["research"], "condition": "", "approval_required": False},
                {"id": "approval", "label": "Approve", "kind": "approval", "action": "human_approval", "depends_on": ["decision"], "condition": "passed", "approval_required": True},
                {"id": "failed", "label": "Failed", "kind": "output", "action": "output", "depends_on": ["decision"], "condition": "failed", "approval_required": False},
                {"id": "approved", "label": "Continue", "kind": "output", "action": "output", "depends_on": ["approval"], "condition": "approved", "approval_required": False},
                {"id": "rejected", "label": "Rejected", "kind": "output", "action": "output", "depends_on": ["approval"], "condition": "rejected", "approval_required": False},
            ],
            "outputs": ["Decision"],
            "warnings": [],
        }


class WorkflowDesignCompilerV3Tests(unittest.TestCase):
    def test_prompt_reserves_only_exact_deterministic_branch_words(self):
        llm = FakeLLM()
        result = WorkflowDesignCompilerV3(llm).compile("validate and approve", language="en")
        self.assertEqual(result.contract["nodes"][3]["condition"], "passed")
        normalized = " ".join(llm.system.split())
        for token in (
            'condition MUST be exactly "passed" or "failed"',
            'condition MUST be exactly "approved" or "rejected"',
            "free-form business rules into executable condition expressions",
            "failed` or `rejected` branch is terminal",
        ):
            self.assertIn(token, normalized)
        self.assertEqual(
            llm.kwargs["template_version"],
            "workspace.workflow-design.v3",
        )


if __name__ == "__main__":
    unittest.main()
