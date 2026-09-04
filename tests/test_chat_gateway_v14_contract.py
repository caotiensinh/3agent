from __future__ import annotations

import unittest

from three_agent.chat_gateway import WorkflowDispatchHTTPHandler
from three_agent.chat_gateway import (
    HTML_V14,
    IntentAwareProjectChatService,
    IntentAwareWorkflowDispatchHTTPHandler,
)


class ChatGatewayV14ContractTests(unittest.TestCase):
    def test_dispatch_handler_chain_is_preserved(self) -> None:
        self.assertTrue(issubclass(IntentAwareWorkflowDispatchHTTPHandler, WorkflowDispatchHTTPHandler))
        self.assertEqual(IntentAwareWorkflowDispatchHTTPHandler.server_version, "WorkSpaceChat/0.15")
        self.assertTrue(callable(IntentAwareWorkflowDispatchHTTPHandler._execute_dispatch))

    def test_auto_language_is_default_and_used_by_studio_and_dispatch(self) -> None:
        self.assertIn('option value="auto" selected>Auto · follow current request</option>', HTML_V14)
        self.assertIn("language:document.getElementById('lang').value", HTML_V14)
        self.assertIn("/api/workflows/prepare-dispatch", HTML_V14)
        self.assertIn("/execute", HTML_V14)
        self.assertNotIn("language:'ja'", HTML_V14)

    def test_direct_chat_contract_is_real_server_logic(self) -> None:
        names = IntentAwareProjectChatService._execute_direct_chat.__code__.co_names
        self.assertIn("direct_chat_system_prompt", names)
        self.assertIn("direct_chat_answer_valid", names)
        self.assertIn("generate", names)

    def test_explicit_research_path_still_delegates_to_existing_service(self) -> None:
        source_names = IntentAwareProjectChatService._execute.__code__.co_names
        self.assertIn("_execute_direct_chat", source_names)
        self.assertIn("_reject_wrong_language_workflow_answer", source_names)


if __name__ == "__main__":
    unittest.main()
