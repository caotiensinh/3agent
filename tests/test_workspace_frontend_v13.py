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
        self.assertIn("Report + Slide PDF", html)

    def test_plus_menu_contains_each_primary_tool_and_integration_exactly_once(self) -> None:
        html = WORKSPACE_HTML_V13
        self.assertEqual(html.count('id="plusBtn"'), 1)
        actions = (
            "upload",
            "library",
            "image_generation",
            "web_search",
            "deep_research",
            "figma",
            "canva",
            "github",
            "gmail",
        )
        for action in actions:
            with self.subTest(action=action):
                self.assertEqual(html.count(f'data-action="{action}"'), 1)

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

        self.assertLess(
            html.index('data-action="figma"'),
            html.index('data-action="canva"'),
        )
        self.assertLess(
            html.index('data-action="canva"'),
            html.index('data-action="github"'),
        )
        self.assertLess(
            html.index('data-action="github"'),
            html.index('data-action="gmail"'),
        )

    def test_unconfigured_external_integrations_remain_fail_closed(self) -> None:
        html = WORKSPACE_HTML_V13
        self.assertIn("This connector is not configured for the local WorkSpace runtime.", html)
        self.assertIn("['figma','canva','gmail']", html)
        self.assertIn("enabled:false", html)
        self.assertIn("else unavailable(action)", html)
        for action in ("figma", "canva", "gmail"):
            with self.subTest(action=action):
                self.assertIn(
                    f'data-action="{action}" data-connect-action="true" role="menuitem"',
                    html,
                )

    def test_github_row_is_normalized_to_menuitem_without_duplication(self) -> None:
        html = WORKSPACE_HTML_V13
        self.assertEqual(
            html.count('data-action="github" role="menuitem"'),
            1,
        )
        self.assertNotIn(
            '<button class="menu-row" type="button" data-action="github">',
            html,
        )


if __name__ == "__main__":
    unittest.main()
