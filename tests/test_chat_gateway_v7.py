import unittest

from three_agent.chat_gateway_v7 import HTML_V7


class ChatGatewayV7FrontendTests(unittest.TestCase):
    def test_conversation_management_contract_is_present(self):
        for marker in (
            'id="archivedChatsBtn"',
            'id="conversationMenu"',
            'id="conversationRenameAction"',
            'id="conversationArchiveAction"',
            'id="conversationDeleteAction"',
            'id="renameConversationModal"',
            'id="deleteConversationModal"',
            '/rename',
            '/archive',
            '/delete',
            "Today",
            "Yesterday",
            "Previous 7 days",
            "Archived chats",
            "Restore this chat to continue",
        ):
            self.assertIn(marker, HTML_V7)

    def test_existing_account_sidebar_and_composer_contract_survives(self):
        for marker in (
            'id="sidebar"',
            'id="newChatBtn"',
            'id="historySearchBtn"',
            'id="pinnedList"',
            'id="accountBtn"',
            'id="manageUsersBtn"',
            'id="changePasswordBtn"',
            'id="plusBtn"',
            'id="micBtn"',
            'id="sendBtn"',
            'placeholder="Ask WorkSpace"',
            '/api/conversations',
            '/api/chat',
        ):
            self.assertIn(marker, HTML_V7)


if __name__ == "__main__":
    unittest.main()
