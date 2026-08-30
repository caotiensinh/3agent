from __future__ import annotations

import unittest
from types import SimpleNamespace

from three_agent.chat_gateway_v18 import workspace_ui_capabilities
from three_agent.workspace_frontend_v13 import WORKSPACE_HTML_V13


def config() -> SimpleNamespace:
    return SimpleNamespace(
        product_name="WorkSpace",
        environment="secure-local",
        confidentiality_mode="confidential",
        internet_gateway=SimpleNamespace(enabled=True, public_search_enabled=False),
        raw={"github": {"enabled": False}},
    )


class WorkspaceFrontendV13Tests(unittest.TestCase):
    def test_language_selector_is_not_user_visible_and_auto_is_authoritative(self) -> None:
        html = WORKSPACE_HTML_V13
        self.assertNotIn("<label>Response language", html)
        self.assertIn('<select id="lang" hidden aria-hidden="true">', html)
        self.assertIn('<option value="auto" selected>Auto</option>', html)
        self.assertIn("language:document.getElementById('lang').value", html)
        self.assertNotIn('<option value="ja">日本語</option>', html)
        self.assertNotIn('<option value="vi">Tiếng Việt</option>', html)
        self.assertNotIn('<option value="en">English</option>', html)

    def test_plus_menu_contains_requested_primary_tools_and_integrations(self) -> None:
        html = WORKSPACE_HTML_V13
        self.assertEqual(html.count('id="plusBtn"'), 1)
        for action in (
            "upload",
            "library",
            "image_generation",
            "web_search",
            "deep_research",
            "figma",
            "canva",
            "github",
            "gmail",
        ):
            with self.subTest(action=action):
                self.assertIn(f'data-action="{action}"', html)

        for label in (
            "Add photos &amp; files",
            "Add from library",
            "Create image",
            "Web search",
            "Deep research",
            "Figma",
            "Canva",
            "GitHub",
            "Gmail",
        ):
            with self.subTest(label=label):
                self.assertIn(label, html)

    def test_unconfigured_external_integrations_remain_fail_closed(self) -> None:
        html = WORKSPACE_HTML_V13
        self.assertIn("if(!f.enabled){showToast", html)
        features = workspace_ui_capabilities(config())["features"]
        for name in ("figma", "canva", "gmail"):
            with self.subTest(name=name):
                self.assertFalse(features[name]["enabled"])
                self.assertEqual(features[name]["state_label"], "Connect")
                self.assertIn("No connector authority has been granted", features[name]["reason"])


if __name__ == "__main__":
    unittest.main()
