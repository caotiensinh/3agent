from __future__ import annotations

import unittest

from three_agent.chat_gateway import FourWayLoginHTTPHandler, HTML_V10


class FourWayLoginGatewayTests(unittest.TestCase):
    def test_login_ui_contains_local_google_github_and_line_contract(self) -> None:
        self.assertIn('id="username"', HTML_V10)
        self.assertIn('id="key"', HTML_V10)
        self.assertIn('id="externalLoginList"', HTML_V10)
        self.assertIn("Continue with ", HTML_V10)
        self.assertIn("Google", HTML_V10)
        self.assertIn("GitHub", HTML_V10)
        self.assertIn("LINE", HTML_V10)
        self.assertIn("verify identity only", HTML_V10)
        self.assertIn("workspace_external_ticket", HTML_V10)

    def test_admin_ui_requires_binding_external_identity_to_local_user(self) -> None:
        self.assertIn('id="externalIdentityList"', HTML_V10)
        self.assertIn("Select local user", HTML_V10)
        self.assertIn("/approve", HTML_V10)
        self.assertIn("/reject", HTML_V10)

    def test_gateway_declares_external_auth_routes(self) -> None:
        get_constants = " ".join(str(v) for v in FourWayLoginHTTPHandler.do_GET.__code__.co_consts)
        post_constants = " ".join(str(v) for v in FourWayLoginHTTPHandler.do_POST.__code__.co_consts)
        self.assertIn("/api/auth/providers", get_constants)
        self.assertIn("/api/external-identities", get_constants)
        self.assertIn("/api/external/login", post_constants)
        self.assertIn("approve", post_constants)
        self.assertIn("reject", post_constants)

    def test_gateway_version_is_bumped(self) -> None:
        self.assertEqual(FourWayLoginHTTPHandler.server_version, "WorkSpaceChat/0.11")


if __name__ == "__main__":
    unittest.main()
