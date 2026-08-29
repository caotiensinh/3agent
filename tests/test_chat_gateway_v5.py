import unittest

from three_agent.chat_gateway_v5 import HTML_V5, _conversation_title, _history_owner_key


class ChatGatewayV5Tests(unittest.TestCase):
    def test_sidebar_history_account_and_chat_contract_are_present(self):
        required = (
            'id="sidebar"',
            'id="sidebarToggle"',
            'id="newChatBtn"',
            'id="historySearchBtn"',
            'id="historySearchInput"',
            'id="pinnedList"',
            'id="historyList"',
            'id="accountBtn"',
            'id="logoutBtn"',
            'id="plusBtn"',
            'id="micBtn"',
            'id="sendBtn"',
            'placeholder="Ask WorkSpace"',
            "/api/session",
            "/api/conversations",
            "/api/logout",
            "/api/capabilities",
            "/api/uploads",
            "/api/upload",
            "/api/chat",
            "conversation_id:state.currentConversationId",
            "mode:state.requestMode",
            "effort:document.getElementById('effort').value",
            "workspace.sidebarCollapsed",
            "workspace.currentConversationId",
        )
        for value in required:
            self.assertIn(value, HTML_V5)
        self.assertNotIn("SpeechRecognition", HTML_V5)
        self.assertNotIn("webkitSpeechRecognition", HTML_V5)

    def test_history_owner_key_is_pseudonymous_and_channel_scoped(self):
        web = _history_owner_key("web", "192.168.11.20")
        telegram = _history_owner_key("telegram", "192.168.11.20")
        self.assertEqual(len(web), 64)
        self.assertNotIn("192.168.11.20", web)
        self.assertNotEqual(web, telegram)

    def test_conversation_title_is_compact(self):
        self.assertEqual(
            _conversation_title("  hello   WorkSpace  "),
            "hello WorkSpace",
        )
        self.assertLessEqual(len(_conversation_title("x" * 200)), 96)


if __name__ == "__main__":
    unittest.main()
