from __future__ import annotations

import inspect
import unittest

from three_agent.chat_gateway_v13 import WorkflowDispatchHTTPHandler
from three_agent.chat_gateway_v14 import HTML_V14, WorkflowV3HTTPHandler


class WorkflowV3GatewayTests(unittest.TestCase):
    def test_gateway_layers_on_v2_and_keeps_workflow_studio(self):
        self.assertTrue(issubclass(WorkflowV3HTTPHandler, WorkflowDispatchHTTPHandler))
        self.assertEqual(WorkflowV3HTTPHandler.server_version, "WorkSpaceChat/0.15")
        self.assertIn("Workflow Studio", HTML_V14)
        self.assertIn("/api/workflows/compile", HTML_V14)

    def test_frontend_exposes_prepare_start_load_and_checkpoint_decisions(self):
        for token in (
            "workflowV3PrepareBtn",
            "workflowV3StartBtn",
            "workflowV3LoadBtn",
            "workflowV3ApproveBtn",
            "workflowV3RejectBtn",
            "/api/workflows/prepare-dispatch",
            "/checkpoint",
            "/state",
            "AUTHORIZE",
            "APPROVE",
            "REJECT",
        ):
            self.assertIn(token, HTML_V14)
        self.assertNotIn("cdn.jsdelivr", HTML_V14)
        self.assertNotIn("unpkg.com", HTML_V14)

    def test_all_v3_mutations_and_state_recovery_are_admin_gated(self):
        for method in (
            WorkflowV3HTTPHandler._prepare_dispatch,
            WorkflowV3HTTPHandler._execute_dispatch,
            WorkflowV3HTTPHandler._checkpoint,
            WorkflowV3HTTPHandler._workflow_state,
        ):
            self.assertIn("self._require_admin()", inspect.getsource(method))
        self.assertIn('admin["user_id"]', inspect.getsource(WorkflowV3HTTPHandler._execute_dispatch))
        self.assertIn('admin["user_id"]', inspect.getsource(WorkflowV3HTTPHandler._checkpoint))

    def test_health_declares_narrow_deterministic_v3_not_general_orchestration(self):
        source = inspect.getsource(WorkflowV3HTTPHandler.do_GET)
        self.assertIn('"workflow_execution_version": "v3"', source)
        self.assertIn('"workflow_execution_risk": "low_only"', source)
        self.assertIn('"workflow_execution_trigger": "manual_only"', source)
        self.assertIn('"workflow_pause_resume": True', source)
        self.assertIn('"workflow_persistent_checkpoint": True', source)
        self.assertIn('"workflow_branching": "deterministic_only"', source)
        self.assertIn('["passed", "failed"]', source)
        self.assertIn('["approved", "rejected"]', source)
        self.assertIn('"workflow_branch_joins": False', source)

    def test_prompt_compiler_and_final_egress_dlp_are_still_inherited(self):
        source = inspect.getsource(WorkflowV3HTTPHandler.do_GET)
        self.assertIn('"prompt_compiler": PROMPT_COMPILER_VERSION', source)
        self.assertIn('"public_query_compiler": PUBLIC_QUERY_COMPILER_VERSION', source)
        self.assertIn('"public_query_final_dlp": True', source)


if __name__ == "__main__":
    unittest.main()
