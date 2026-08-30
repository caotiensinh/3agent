from __future__ import annotations

import unittest

from three_agent.chat_gateway_v13 import (
    HTML_V13,
    IntentAwareProjectChatService,
    IntentAwareWorkflowStudioHTTPHandler,
)


class ChatGatewayV13ContractTests(unittest.TestCase):
    def test_auto_language_is_default_in_frontend(self) -> None:
        self.assertIn('option value="auto" selected>Auto · follow current request</option>', HTML_V13)
        self.assertIn("language:document.getElementById('lang').value", HTML_V13)

    def test_gateway_declares_direct_chat_release(self) -> None:
        self.assertEqual(IntentAwareWorkflowStudioHTTPHandler.server_version, "WorkSpaceChat/0.14")
        self.assertTrue(issubclass(IntentAwareProjectChatService, object))

    def test_direct_chat_contract_markers_are_present(self) -> None:
        source = IntentAwareProjectChatService._execute_direct_chat.__code__.co_names
        self.assertIn("direct_chat_system_prompt", source)
        self.assertIn("direct_chat_answer_valid", source)
        self.assertIn("generate", source)


if __name__ == "__main__":
    unittest.main()
