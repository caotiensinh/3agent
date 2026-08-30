from __future__ import annotations

import unittest

from three_agent.chat_gateway_v11 import DispatchHTTPHandler, HTML_V11


class DispatchGatewayTests(unittest.TestCase):
    def test_gateway_preserves_external_auth_ui_and_adds_dispatch(self):
        self.assertIn('id="externalLoginList"', HTML_V11)
        self.assertIn("Continue with ", HTML_V11)
        self.assertIn("Google", HTML_V11)
        self.assertIn("GitHub", HTML_V11)
        self.assertIn("LINE", HTML_V11)
        self.assertIn('id="dispatchModal"', HTML_V11)
        self.assertIn("Approve &amp; Dispatch", HTML_V11)

    def test_gateway_declares_dispatch_routes(self):
        get_constants = " ".join(str(value) for value in DispatchHTTPHandler.do_GET.__code__.co_consts)
        post_constants = " ".join(str(value) for value in DispatchHTTPHandler.do_POST.__code__.co_consts)
        self.assertIn("/api/dispatch/", get_constants)
        self.assertIn("/api/dispatch/compile", post_constants)
        self.assertIn("run", post_constants)

    def test_gateway_version_is_next_after_external_auth(self):
        self.assertEqual(DispatchHTTPHandler.server_version, "WorkSpaceChat/0.12")


if __name__ == "__main__":
    unittest.main()
