from __future__ import annotations

import inspect
import unittest

from three_agent.chat_gateway import PromptAwareWorkflowStudioHTTPHandler
from three_agent.chat_gateway import HTML_V13, WorkflowDispatchHTTPHandler


class WorkflowDispatchGatewayTests(unittest.TestCase):
    def test_gateway_layers_on_prompt_aware_v12(self):
        self.assertTrue(
            issubclass(WorkflowDispatchHTTPHandler, PromptAwareWorkflowStudioHTTPHandler)
        )
        self.assertEqual(WorkflowDispatchHTTPHandler.server_version, "WorkSpaceChat/0.14")
        self.assertIn("Workflow Studio", HTML_V13)
        self.assertIn("/api/workflows/compile", HTML_V13)

    def test_frontend_requires_fresh_prepare_and_explicit_authorize(self):
        self.assertIn("workflowPrepareDispatchBtn", HTML_V13)
        self.assertIn("workflowAuthorizeDispatchBtn", HTML_V13)
        self.assertIn("/api/workflows/prepare-dispatch", HTML_V13)
        self.assertIn("/execute", HTML_V13)
        self.assertIn("Type AUTHORIZE exactly", HTML_V13)
        self.assertIn("confirmation:'AUTHORIZE'", HTML_V13)
        self.assertNotIn("cdn.jsdelivr", HTML_V13)
        self.assertNotIn("unpkg.com", HTML_V13)

    def test_prepare_and_execute_are_admin_gated(self):
        prepare_source = inspect.getsource(WorkflowDispatchHTTPHandler._prepare_dispatch)
        execute_source = inspect.getsource(WorkflowDispatchHTTPHandler._execute_dispatch)
        self.assertIn("self._require_admin()", prepare_source)
        self.assertIn("self._require_admin()", execute_source)
        self.assertIn('admin["user_id"]', execute_source)

    def test_health_preserves_prompt_dlp_and_adds_bounded_dispatch(self):
        source = inspect.getsource(WorkflowDispatchHTTPHandler.do_GET)
        self.assertIn('"workflow_execution": True', source)
        self.assertIn('"workflow_execution_risk": "low_only"', source)
        self.assertIn('"workflow_execution_trigger": "manual_only"', source)
        self.assertIn('"workflow_execution_admin_approval": True', source)
        self.assertIn('"workspace-fixed-analysis/v1"', source)
        self.assertIn('"prompt_compiler": PROMPT_COMPILER_VERSION', source)
        self.assertIn('"public_query_compiler": PUBLIC_QUERY_COMPILER_VERSION', source)
        self.assertIn('"public_query_final_dlp": True', source)


if __name__ == "__main__":
    unittest.main()
