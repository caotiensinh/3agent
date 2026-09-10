from __future__ import annotations

import unittest

from three_agent.chat_context import (
    CONTEXT_MODE_CONTINUITY,
    CONTEXT_MODE_FOLLOW_UP,
    build_continuity_context,
)


class ConversationContinuityTests(unittest.TestCase):
    def test_same_conversation_is_injected_without_magic_followup_words(self):
        messages = [
            {
                "role": "user",
                "content": "Chúng ta đang thiết kế server AI dùng hai GPU.",
                "job_id": "a",
                "status": "completed",
            },
            {
                "role": "assistant",
                "content": "Tôi đề xuất Ubuntu làm server duy nhất trong LAN.",
                "job_id": "a",
                "status": "completed",
            },
            {
                "role": "user",
                "content": "Cấu hình firewall nên như thế nào?",
                "job_id": "b",
                "status": "completed",
            },
        ]
        plan = build_continuity_context(
            messages,
            "Port 8787 có cần mở toàn mạng không?",
            current_job_id="current",
        )
        self.assertEqual(plan.mode, CONTEXT_MODE_CONTINUITY)
        self.assertIn("Ubuntu làm server duy nhất", plan.text)
        self.assertGreaterEqual(plan.message_count, 2)

    def test_explicit_reference_keeps_followup_mode(self):
        plan = build_continuity_context(
            [
                {
                    "role": "assistant",
                    "content": "Phương án A",
                    "job_id": "x",
                    "status": "completed",
                }
            ],
            "tiếp tục phần trên",
            current_job_id="current",
        )
        self.assertEqual(plan.mode, CONTEXT_MODE_FOLLOW_UP)
        self.assertIn("Phương án A", plan.text)

    def test_current_and_failed_messages_are_not_reinjected(self):
        messages = [
            {
                "role": "user",
                "content": "old-safe",
                "job_id": "old",
                "status": "completed",
            },
            {
                "role": "assistant",
                "content": "failed-secret",
                "job_id": "bad",
                "status": "failed",
            },
            {
                "role": "user",
                "content": "current-duplicate",
                "job_id": "now",
                "status": "completed",
            },
        ]
        plan = build_continuity_context(
            messages,
            "new question",
            current_job_id="now",
        )
        self.assertIn("old-safe", plan.text)
        self.assertNotIn("failed-secret", plan.text)
        self.assertNotIn("current-duplicate", plan.text)


if __name__ == "__main__":
    unittest.main()
