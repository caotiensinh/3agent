import unittest

from three_agent.chat_gateway_v11 import HTML_V11, WorkflowStudioHTTPHandler
from three_agent.workspace_frontend_v8 import WORKSPACE_HTML_V8


class WorkflowStudioGatewayTests(unittest.TestCase):
    def test_frontend_contains_workflow_studio_without_external_diagram_dependency(self):
        self.assertEqual(HTML_V11, WORKSPACE_HTML_V8)
        self.assertIn('id="workflowStudioBtn"', HTML_V11)
        self.assertIn('id="workflowDescription"', HTML_V11)
        self.assertIn("/api/workflows/compile", HTML_V11)
        self.assertIn("Mermaid", HTML_V11)
        self.assertNotIn("cdn.jsdelivr.net", HTML_V11)
        self.assertNotIn("unpkg.com", HTML_V11)
        self.assertNotIn("mermaid.min.js", HTML_V11)

    def test_gateway_version_advances_without_replacing_existing_handler_chain(self):
        self.assertEqual(WorkflowStudioHTTPHandler.server_version, "WorkSpaceChat/0.12")
        self.assertTrue(hasattr(WorkflowStudioHTTPHandler, "_compile_workflow"))


if __name__ == "__main__":
    unittest.main()
