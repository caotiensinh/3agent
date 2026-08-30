import unittest
from types import SimpleNamespace

from three_agent.chat_gateway_v6 import HTML_V6, _job_is_owned


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

    def test_job_and_artifact_ownership_is_exact_account_scoped(self):
        identity = "workspace-user:usr_0123456789abcdef"
        own = SimpleNamespace(channel="web", sender=identity)
        other = SimpleNamespace(
            channel="web", sender="workspace-user:usr_fedcba9876543210"
        )
        telegram = SimpleNamespace(channel="telegram", sender=identity)
        self.assertTrue(_job_is_owned(own, identity))
        self.assertFalse(_job_is_owned(other, identity))
        self.assertFalse(_job_is_owned(telegram, identity))
        self.assertFalse(_job_is_owned(None, identity))


if __name__ == "__main__":
    unittest.main()
