import unittest

from three_agent.chat_gateway_v6 import HTML_V6


class ChatGatewayV6Tests(unittest.TestCase):
    def test_local_account_frontend_contract_is_present(self):
        for marker in (
            'id="username"',
            'placeholder="Password"',
            'id="manageUsersBtn"',
            'id="changePasswordBtn"',
            'id="userAdminModal"',
            'id="passwordModal"',
            "/api/users",
            "/api/account/password",
            "workspace.lastUsername",
            "username:username,password:key",
        ):
            self.assertIn(marker, HTML_V6)
        self.assertNotIn("Enter the LAN access key.", HTML_V6)

    def test_existing_sidebar_and_composer_contract_survives_account_upgrade(self):
        for marker in (
            'id="sidebar"',
            'id="sidebarToggle"',
            'id="newChatBtn"',
            'id="historySearchBtn"',
            'id="pinnedList"',
            'id="accountBtn"',
            'placeholder="Ask WorkSpace"',
            'id="plusBtn"',
            'id="micBtn"',
            'id="sendBtn"',
            "/api/conversations",
            "/api/uploads",
            "/api/chat",
        ):
            self.assertIn(marker, HTML_V6)


if __name__ == "__main__":
    unittest.main()
