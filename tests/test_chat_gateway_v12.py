import unittest

from three_agent.chat_gateway_v12 import PromptAwareWorkflowStudioHTTPHandler
from three_agent.chat_gateway_v11 import WorkflowStudioHTTPHandler
from three_agent.prompt_compiler import PROMPT_COMPILER_VERSION
from three_agent.public_query_compiler import PUBLIC_QUERY_COMPILER_VERSION


class PromptAwareWorkflowStudioGatewayTests(unittest.TestCase):
    def test_v12_preserves_workflow_studio_handler_chain(self):
        self.assertTrue(issubclass(PromptAwareWorkflowStudioHTTPHandler, WorkflowStudioHTTPHandler))
        self.assertEqual(PromptAwareWorkflowStudioHTTPHandler.server_version, "WorkSpaceChat/0.13")
        self.assertTrue(hasattr(PromptAwareWorkflowStudioHTTPHandler, "_compile_workflow"))

    def test_prompt_compiler_versions_are_nonempty_contract_markers(self):
        self.assertTrue(PROMPT_COMPILER_VERSION)
        self.assertTrue(PUBLIC_QUERY_COMPILER_VERSION)


if __name__ == "__main__":
    unittest.main()
