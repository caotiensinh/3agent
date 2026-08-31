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
        self.assertIn("else unavailable(action)", html)
        features = workspace_ui_capabilities(config())["features"]
        for name in ("figma", "canva", "gmail"):
            with self.subTest(name=name):
                self.assertFalse(features[name]["enabled"])
                self.assertEqual(features[name]["state_label"], "Connect")
                self.assertIn("No connector authority has been granted", features[name]["reason"])

    def test_assistant_identity_is_icon_only_and_accessible(self) -> None:
        html = WORKSPACE_HTML_V13
        self.assertIn("function workspaceSenderMark()", html)
        self.assertIn("h.className='who workspace-who'", html)
        self.assertIn("h.setAttribute('aria-label','WorkSpace')", html)
        self.assertIn('class="workspace-message-mark"', html)
        self.assertIn("if(cls.includes('user')){h=document.createElement('div');h.className='who';h.textContent=who}else h=workspaceSenderMark()", html)

    def test_completed_answers_hide_success_stage_cards_but_keep_exceptions(self) -> None:
        html = WORKSPACE_HTML_V13
        self.assertIn("function shouldShowAnswerStages(job,route)", html)
        self.assertIn("if(exceptional)return true", html)
        self.assertIn("if(job.answer)return false", html)
        self.assertIn("return route!=='direct_chat'", html)
        self.assertIn("if(shouldShowAnswerStages(j,node.dataset.uiRoute))node.insertBefore(renderStages(j.stages)", html)
        self.assertIn("if(j.ui_route)node.dataset.uiRoute=j.ui_route", html)

    def test_every_completed_assistant_answer_has_compact_actions(self) -> None:
        html = WORKSPACE_HTML_V13
        for label in (
            "Copy answer",
            "Export answer",
            "Regenerate answer",
            "More answer actions",
        ):
            with self.subTest(label=label):
                self.assertIn(label, html)
        self.assertIn("bar.className='answerTools compact-actions'", html)
        self.assertIn("if(!cls.includes('user')&&d.dataset.answer)renderActions(d,job||{answer:d.dataset.answer})", html)
        self.assertNotIn("b.textContent='Copy answer';b.onclick=()=>copyAnswer(node)", html)

    def test_export_is_local_only_and_does_not_invoke_system_share(self) -> None:
        html = WORKSPACE_HTML_V13
        self.assertIn("new Blob([text],{type:'text/plain;charset=utf-8'})", html)
        self.assertIn("URL.createObjectURL(blob)", html)
        self.assertIn("a.download='workspace-answer-'", html)
        self.assertNotIn("navigator.share", html)

    def test_regenerate_reuses_text_but_requires_attachments_again(self) -> None:
        html = WORKSPACE_HTML_V13
        self.assertIn("function previousUserPrompt(node)", html)
        self.assertIn("const marker='\\n\\nAttached:'", html)
        self.assertIn("showToast('Reattach files before regenerating')", html)
        self.assertIn("await sendMsg()", html)


if __name__ == "__main__":
    unittest.main()
