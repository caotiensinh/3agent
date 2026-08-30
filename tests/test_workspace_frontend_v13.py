from __future__ import annotations

import unittest

from three_agent.workspace_frontend_v13 import WORKSPACE_HTML_V13


class WorkspaceFrontendV13Tests(unittest.TestCase):
    def test_language_selector_is_not_user_visible_and_auto_is_authoritative(self) -> None:
        html = WORKSPACE_HTML_V13
        self.assertNotIn("<label>Response language", html)
        self.assertIn('<select id="lang" hidden aria-hidden="true">', html)
        self.assertIn('<option value="auto" selected>Auto</option>', html)
        self.assertIn("Language follows each current request automatically.", html)
        self.assertIn("language:document.getElementById('lang').value", html)

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
            "Add photos & files",
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
        self.assertIn("This connector is not configured for the local WorkSpace runtime.", html)
        self.assertIn("new Set(['figma','canva','gmail'])", html)
        self.assertIn(
            "function unavailable(name){const f=cap(name);showToast(f.reason||'This feature is not available')}",
            html,
        )
        self.assertIn("else unavailable(action)", html)


if __name__ == "__main__":
    unittest.main()
