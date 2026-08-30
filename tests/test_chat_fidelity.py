from __future__ import annotations

import unittest

from three_agent.chat_fidelity import (
    direct_chat_answer_valid,
    parse_chat_request,
    response_language_matches,
)


class ChatLanguageResolutionTests(unittest.TestCase):
    def test_vietnamese_message_instruction_overrides_japanese_ui(self) -> None:
        controls = parse_chat_request(
            "Hãy trả lời bằng tiếng Việt. Giải thích nguyên nhân lỗi mạng này.",
            selected_language="ja",
            fallback_language="ja",
        )
        self.assertEqual(controls.language, "vi")
        self.assertEqual(controls.language_source, "message_instruction")

    def test_english_message_instruction_overrides_japanese_ui(self) -> None:
        controls = parse_chat_request(
            "Please reply in English and explain why this service failed.",
            selected_language="ja",
            fallback_language="ja",
        )
        self.assertEqual(controls.language, "en")
        self.assertEqual(controls.language_source, "message_instruction")

    def test_vietnamese_request_for_english_overrides_japanese_ui(self) -> None:
        controls = parse_chat_request(
            "Bạn hãy trả lời bằng tiếng Anh và giữ nguyên các lệnh shell.",
            selected_language="ja",
            fallback_language="ja",
        )
        self.assertEqual(controls.language, "en")
        self.assertEqual(controls.language_source, "message_instruction")

    def test_command_is_stronger_than_conflicting_natural_instruction(self) -> None:
        controls = parse_chat_request(
            "/vi Please reply in English. Giải thích vấn đề này.",
            selected_language="ja",
            fallback_language="ja",
        )
        self.assertEqual(controls.language, "vi")
        self.assertEqual(controls.language_source, "command")

    def test_auto_detects_vietnamese_english_and_japanese(self) -> None:
        self.assertEqual(
            parse_chat_request(
                "Tôi cần bạn phân tích kết quả này và giải thích rõ nguyên nhân.",
                selected_language="auto",
            ).language,
            "vi",
        )
        self.assertEqual(
            parse_chat_request(
                "Please explain why this network route is failing.",
                selected_language="auto",
            ).language,
            "en",
        )
        self.assertEqual(
            parse_chat_request(
                "このネットワーク障害の原因を説明してください。",
                selected_language="auto",
            ).language,
            "ja",
        )

    def test_parser_preserves_multiline_code_instead_of_flattening_prompt(self) -> None:
        message = "/en Explain this exactly:\n```bash\nip addr\nping -c 2 1.1.1.1\n```"
        controls = parse_chat_request(message, selected_language="ja")
        self.assertEqual(controls.language, "en")
        self.assertIn("```bash\nip addr\nping -c 2 1.1.1.1\n```", controls.text)
        self.assertNotIn("/en", controls.text)

    def test_output_prefix_and_language_prefix_compose(self) -> None:
        controls = parse_chat_request(
            "/vi /pdf Phân tích dữ liệu này.",
            selected_language="ja",
        )
        self.assertEqual(controls.language, "vi")
        self.assertEqual(controls.output_format, "pdf")
        self.assertEqual(controls.text, "Phân tích dữ liệu này.")


class ChatResponseLanguageTests(unittest.TestCase):
    def test_english_validator_rejects_japanese_body(self) -> None:
        self.assertFalse(
            response_language_matches(
                "この問題の原因はネットワーク設定です。設定を確認してください。",
                "en",
            )
        )
        self.assertTrue(
            response_language_matches(
                "The likely cause is the network configuration. Check the route and DNS settings.",
                "en",
            )
        )

    def test_vietnamese_validator_rejects_english_body(self) -> None:
        self.assertFalse(
            response_language_matches(
                "The service is failing because the route is missing.",
                "vi",
            )
        )
        self.assertTrue(
            response_language_matches(
                "Dịch vụ đang lỗi vì tuyến mạng bị thiếu. Hãy kiểm tra cấu hình gateway.",
                "vi",
            )
        )

    def test_japanese_validator_rejects_english_body(self) -> None:
        self.assertFalse(
            response_language_matches(
                "The service is failing because the route is missing.",
                "ja",
            )
        )
        self.assertTrue(
            response_language_matches(
                "サービス障害の原因はルート設定です。ゲートウェイを確認してください。",
                "ja",
            )
        )

    def test_direct_chat_rejects_old_research_wrapper_leak(self) -> None:
        ok, reason = direct_chat_answer_valid(
            "# WorkSpace Report\n\nAgent 1 · Research result",
            "en",
            "Explain why my Python script fails.",
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "workflow_wrapper_leak")


if __name__ == "__main__":
    unittest.main()
