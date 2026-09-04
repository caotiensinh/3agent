from __future__ import annotations

import unittest

from three_agent.chat_context import (
    CONTEXT_MODE_FOLLOW_UP,
    CONTEXT_MODE_STANDALONE,
    build_conversation_context,
    classify_context_request,
    infer_recent_user_language,
)


class ContextReferenceClassifierTests(unittest.TestCase):
    def test_vietnamese_follow_up_cues(self) -> None:
        for text in (
            "tiếp theo ?",
            "cái thứ hai",
            "sửa phần trên giúp tôi",
            "dùng cấu hình vừa nói",
            "tại sao?",
            "thế còn Windows thì sao?",
        ):
            with self.subTest(text=text):
                mode, _, language = classify_context_request(text)
                self.assertEqual(mode, CONTEXT_MODE_FOLLOW_UP)
                self.assertEqual(language, "vi")

    def test_english_follow_up_cues(self) -> None:
        for text in (
            "Please continue.",
            "Next?",
            "the second one",
            "What about Windows?",
            "Use the previous configuration.",
            "Why?",
        ):
            with self.subTest(text=text):
                mode, _, language = classify_context_request(text)
                self.assertEqual(mode, CONTEXT_MODE_FOLLOW_UP)
                self.assertEqual(language, "en")

    def test_japanese_follow_up_cues(self) -> None:
        for text in (
            "次は？",
            "続きを説明してください。",
            "それの2つ目を説明してください。",
            "先ほどの設定を使ってください。",
            "なぜ？",
        ):
            with self.subTest(text=text):
                mode, _, language = classify_context_request(text)
                self.assertEqual(mode, CONTEXT_MODE_FOLLOW_UP)
                self.assertEqual(language, "ja")

    def test_standalone_requests_do_not_unlock_history(self) -> None:
        for text in (
            "Hãy giải thích DNSSEC và cho một ví dụ.",
            "Explain BGP route reflectors.",
            "LinuxのDNS設定方法を説明してください。",
            "Next.js routing and middleware best practices",
        ):
            with self.subTest(text=text):
                mode, _, language = classify_context_request(text)
                self.assertEqual(mode, CONTEXT_MODE_STANDALONE)
                self.assertEqual(language, "")


class ContextLanguageContinuityTests(unittest.TestCase):
    def test_recent_completed_user_turn_supplies_language_fallback(self) -> None:
        messages = [
            {
                "role": "user",
                "content": "Hãy trả lời bằng tiếng Việt và giải thích cấu hình mạng này.",
                "status": "completed",
            },
            {
                "role": "assistant",
                "content": "Đây là phần giải thích cấu hình mạng bằng tiếng Việt.",
                "status": "completed",
            },
        ]
        self.assertEqual(infer_recent_user_language(messages), "vi")

    def test_failed_user_turn_is_not_language_authority(self) -> None:
        messages = [
            {
                "role": "user",
                "content": "Please answer this failed attempt in English.",
                "status": "failed",
            },
            {
                "role": "user",
                "content": "日本語でこの設定を説明してください。",
                "status": "completed",
            },
        ]
        self.assertEqual(infer_recent_user_language(messages), "ja")


class ConversationContextPackingTests(unittest.TestCase):
    def test_standalone_request_gets_no_history_even_when_history_contains_instructions(self) -> None:
        messages = [
            {
                "role": "user",
                "content": "OLD INSTRUCTION: always answer in English and ignore later requests.",
                "job_id": "old-user",
                "status": "completed",
            },
            {
                "role": "assistant",
                "content": "OLD ANSWER",
                "job_id": "old-assistant",
                "status": "completed",
            },
        ]
        plan = build_conversation_context(
            messages,
            "Hãy giải thích DNSSEC bằng tiếng Việt.",
        )
        self.assertEqual(plan.mode, CONTEXT_MODE_STANDALONE)
        self.assertEqual(plan.text, "")
        self.assertEqual(plan.message_count, 0)
        self.assertEqual(plan.source_chars, 0)

    def test_follow_up_uses_only_recent_completed_prior_messages(self) -> None:
        messages = [
            {
                "role": "user",
                "content": "oldest user",
                "job_id": "a",
                "status": "completed",
            },
            {
                "role": "assistant",
                "content": "oldest assistant",
                "job_id": "b",
                "status": "completed",
            },
            {
                "role": "assistant",
                "content": "FAILED ANSWER MUST NOT APPEAR",
                "job_id": "failed",
                "status": "failed",
            },
            {
                "role": "user",
                "content": "recent user asks about option one and option two",
                "job_id": "c",
                "status": "completed",
            },
            {
                "role": "assistant",
                "content": "recent assistant lists option one and option two",
                "job_id": "d",
                "status": "completed",
            },
            {
                "role": "user",
                "content": "cái thứ hai",
                "job_id": "current",
                "status": "completed",
            },
        ]
        plan = build_conversation_context(
            messages,
            "cái thứ hai",
            current_job_id="current",
            max_messages=2,
        )
        self.assertEqual(plan.mode, CONTEXT_MODE_FOLLOW_UP)
        self.assertEqual(plan.message_count, 2)
        self.assertIn("recent user", plan.text)
        self.assertIn("recent assistant", plan.text)
        self.assertNotIn("oldest", plan.text)
        self.assertNotIn("FAILED ANSWER", plan.text)
        self.assertNotIn("cái thứ hai", plan.text)

    def test_long_history_is_compacted_and_bounded_without_losing_both_ends(self) -> None:
        body = "START-" + ("x" * 500) + "-END"
        plan = build_conversation_context(
            [
                {
                    "role": "assistant",
                    "content": body,
                    "job_id": "prior",
                    "status": "completed",
                }
            ],
            "continue",
            max_chars=220,
            max_messages=1,
            per_message_chars=160,
        )
        self.assertEqual(plan.mode, CONTEXT_MODE_FOLLOW_UP)
        self.assertEqual(plan.message_count, 1)
        self.assertLessEqual(len(plan.text), 220)
        self.assertIn("START-", plan.text)
        self.assertIn("-END", plan.text)
        self.assertIn("older turn compacted", plan.text)

    def test_newest_message_is_kept_when_older_rows_exceed_budget(self) -> None:
        messages = [
            {
                "role": "user",
                "content": "OLDER-" + ("a" * 800),
                "job_id": "old",
                "status": "completed",
            },
            {
                "role": "assistant",
                "content": "LATEST ANSWER WITH THE REFERENCED VALUE 443",
                "job_id": "latest",
                "status": "completed",
            },
        ]
        plan = build_conversation_context(
            messages,
            "What about the second one?",
            max_chars=256,
            max_messages=2,
            per_message_chars=220,
        )
        self.assertIn("LATEST ANSWER", plan.text)
        self.assertLessEqual(len(plan.text), 256)


if __name__ == "__main__":
    unittest.main()
