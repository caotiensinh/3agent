from __future__ import annotations

import unittest

from three_agent.chat_context import CONTEXT_MODE_FOLLOW_UP
from three_agent.chat_context import build_conversation_context, classify_context_request
from three_agent.chat_fidelity import parse_chat_request


class ReferencedTransformContextTests(unittest.TestCase):
    def test_vietnamese_report_translation_is_follow_up_and_targets_vietnamese(self) -> None:
        text = "dịch báo cáo trên sang tiếng việt"
        mode, reason, language = classify_context_request(text)
        self.assertEqual(mode, CONTEXT_MODE_FOLLOW_UP)
        self.assertTrue(reason.startswith("vi_referenced_transform_"))
        self.assertEqual(language, "vi")

        controls = parse_chat_request(text, selected_language="auto", fallback_language="ja")
        self.assertEqual(controls.language, "vi")
        self.assertNotEqual(controls.language_source, "fallback")

    def test_english_previous_report_translation_is_follow_up(self) -> None:
        mode, _, language = classify_context_request(
            "Translate the previous report into English."
        )
        self.assertEqual(mode, CONTEXT_MODE_FOLLOW_UP)
        self.assertEqual(language, "en")

    def test_japanese_previous_report_rewrite_is_follow_up(self) -> None:
        mode, _, language = classify_context_request(
            "前の報告書を日本語で書き直してください。"
        )
        self.assertEqual(mode, CONTEXT_MODE_FOLLOW_UP)
        self.assertEqual(language, "ja")

    def test_generic_translation_without_prior_reference_does_not_unlock_history(self) -> None:
        mode, _, language = classify_context_request(
            "Hãy dịch tài liệu đính kèm sang tiếng Việt."
        )
        self.assertNotEqual(mode, CONTEXT_MODE_FOLLOW_UP)
        self.assertEqual(language, "")

    def test_referenced_report_transform_receives_bounded_completed_context(self) -> None:
        messages = [
            {
                "role": "assistant",
                "content": "# Technical Report\nVerified result: GPU worker scheduling passed.",
                "job_id": "prior-report",
                "status": "completed",
            },
            {
                "role": "assistant",
                "content": "FAILED CONTENT MUST NOT APPEAR",
                "job_id": "failed-report",
                "status": "failed",
            },
            {
                "role": "user",
                "content": "dịch báo cáo trên sang tiếng việt",
                "job_id": "current",
                "status": "completed",
            },
        ]
        plan = build_conversation_context(
            messages,
            "dịch báo cáo trên sang tiếng việt",
            current_job_id="current",
            max_messages=4,
            max_chars=1200,
        )
        self.assertEqual(plan.mode, CONTEXT_MODE_FOLLOW_UP)
        self.assertEqual(plan.language_hint, "vi")
        self.assertIn("Technical Report", plan.text)
        self.assertIn("GPU worker scheduling passed", plan.text)
        self.assertNotIn("FAILED CONTENT", plan.text)
        self.assertNotIn("dịch báo cáo trên", plan.text)


if __name__ == "__main__":
    unittest.main()
