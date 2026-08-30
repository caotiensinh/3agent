from __future__ import annotations

import inspect
import unittest

from three_agent.chat_gateway_v11 import WorkflowStudioHTTPHandler
from three_agent.chat_gateway_v12 import HTML_V12, WorkflowDispatchHTTPHandler


class WorkflowDispatchGatewayTests(unittest.TestCase):
    def test_gateway_advances_and_preserves_workflow_studio(self):
        self.assertTrue(issubclass(WorkflowDispatchHTTPHandler, WorkflowStudioHTTPHandler))
        self.assertEqual(WorkflowDispatchHTTPHandler.server_version, "WorkSpaceChat/0.13")
        self.assertIn("Workflow Studio", HTML_V12)
        self.assertIn("/api/workflows/compile", HTML_V12)

    def test_frontend_requires_fresh_prepare_and_explicit_authorize(self):
        self.assertIn("workflowPrepareDispatchBtn", HTML_V12)
        self.assertIn("workflowAuthorizeDispatchBtn", HTML_V12)
        self.assertIn("/api/workflows/prepare-dispatch", HTML_V12)
        self.assertIn("/execute", HTML_V12)
        self.assertIn("Type AUTHORIZE exactly", HTML_V12)
        self.assertIn("confirmation:'AUTHORIZE'", HTML_V12)
        self.assertNotIn("cdn.jsdelivr", HTML_V12)
        self.assertNotIn("unpkg.com", HTML_V12)

    def test_prepare_and_execute_are_admin_gated(self):
        prepare_source = inspect.getsource(WorkflowDispatchHTTPHandler._prepare_dispatch)
        execute_source = inspect.getsource(WorkflowDispatchHTTPHandler._execute_dispatch)
        self.assertIn("self._require_admin()", prepare_source)
        self.assertIn("self._require_admin()", execute_source)
        self.assertIn('admin["user_id"]', execute_source)

    def test_public_dispatch_result_never_exposes_server_paths_or_artifact_lists(self):
        public = WorkflowDispatchHTTPHandler._public_dispatch_result(
            {
                "schema_version": "workspace-workflow-dispatch/v2",
                "task_id": "TASK-1",
                "dispatch_status": "completed",
                "execution_profile": "workspace-fixed-analysis/v1",
                "result": {
                    "task_id": "TASK-1",
                    "status": "completed",
                    "task_status": "done",
                    "stage": "daily_report_completed",
                    "manifest_path": "/srv/workspace/secret/workflow.json",
                    "research_artifacts": ["/srv/workspace/secret/research.json"],
                    "presentation_artifacts": ["/srv/workspace/secret/deck.pptx"],
                    "daily_report_artifacts": ["/srv/workspace/secret/daily.json"],
                    "error": None,
                },
            }
        )
        encoded = repr(public)
        self.assertNotIn("/srv/", encoded)
        self.assertNotIn("manifest_path", encoded)
        self.assertNotIn("research_artifacts", encoded)
        self.assertEqual(public["result"]["status"], "completed")

    def test_health_contract_declares_bounded_execution_not_general_authority(self):
        source = inspect.getsource(WorkflowDispatchHTTPHandler.do_GET)
        self.assertIn('"workflow_execution": True', source)
        self.assertIn('"workflow_execution_risk": "low_only"', source)
        self.assertIn('"workflow_execution_trigger": "manual_only"', source)
        self.assertIn('"workflow_execution_admin_approval": True', source)
        self.assertIn('"workspace-fixed-analysis/v1"', source)


if __name__ == "__main__":
    unittest.main()
