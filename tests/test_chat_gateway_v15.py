from __future__ import annotations

import inspect
import unittest

from three_agent.chat_gateway import IntentAwareWorkflowDispatchHTTPHandler
from three_agent.chat_gateway import HTML_V15, WorkflowV3HTTPHandler


class WorkflowV3GatewayTests(unittest.TestCase):
    def test_gateway_layers_on_current_chat_fidelity_gateway(self):
        self.assertTrue(
            issubclass(WorkflowV3HTTPHandler, IntentAwareWorkflowDispatchHTTPHandler)
        )
        self.assertEqual(WorkflowV3HTTPHandler.server_version, "WorkSpaceChat/0.16")
        self.assertIn("Workflow Studio", HTML_V15)
        self.assertIn("/api/workflows/compile", HTML_V15)
        self.assertIn("Auto · follow current request", HTML_V15)

    def test_frontend_has_one_v3_execution_controller_and_no_v2_duplicate(self):
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
            self.assertIn(token, HTML_V15)
        self.assertNotIn("workflowPrepareDispatchBtn", HTML_V15)
        self.assertNotIn("workflowAuthorizeDispatchBtn", HTML_V15)
        self.assertNotIn("cdn.jsdelivr", HTML_V15)
        self.assertNotIn("unpkg.com", HTML_V15)

    def test_all_v3_mutations_and_state_recovery_are_admin_gated(self):
        for method in (
            WorkflowV3HTTPHandler._prepare_dispatch,
            WorkflowV3HTTPHandler._execute_dispatch,
            WorkflowV3HTTPHandler._checkpoint,
            WorkflowV3HTTPHandler._workflow_state,
        ):
            self.assertIn("self._require_admin()", inspect.getsource(method))
        self.assertIn(
            'admin["user_id"]',
            inspect.getsource(WorkflowV3HTTPHandler._execute_dispatch),
        )
        self.assertIn(
            'admin["user_id"]',
            inspect.getsource(WorkflowV3HTTPHandler._checkpoint),
        )

    def test_health_declares_narrow_v3_and_preserves_current_chat_features(self):
        source = inspect.getsource(WorkflowV3HTTPHandler.do_GET)
        for token in (
            '"workflow_execution_version": "v3"',
            '"workflow_execution_risk": "low_only"',
            '"workflow_execution_trigger": "manual_only"',
            '"workflow_pause_resume": True',
            '"workflow_persistent_checkpoint": True',
            '"workflow_branching": "deterministic_only"',
            '["passed", "failed"]',
            '["approved", "rejected"]',
            '"workflow_failure_rejection_terminal": True',
            '"workflow_branch_joins": False',
            '"prompt_compiler": PROMPT_COMPILER_VERSION',
            '"public_query_compiler": PUBLIC_QUERY_COMPILER_VERSION',
            '"public_query_final_dlp": True',
            '"direct_chat": True',
            '"direct_chat_public_web": False',
            '"response_language_auto": True',
            '"response_language_current_request_precedence": True',
            '"response_language_validation": True',
        ):
            self.assertIn(token, source)


if __name__ == "__main__":
    unittest.main()
