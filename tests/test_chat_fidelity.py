from __future__ import annotations

import unittest

from three_agent.chat_fidelity import (
    direct_chat_answer_valid,
    language_neutral_response_matches_request,
    parse_chat_request,
    requested_language_neutral_format,
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
        self.assertEqual(parse_chat_request(
            "Tôi cần bạn phân tích kết quả này và giải thích rõ nguyên nhân.",
            selected_language="auto",
        ).language, "vi")
        self.assertEqual(parse_chat_request(
            "Please explain why this network route is failing.",
            selected_language="auto",
        ).language, "en")
        self.assertEqual(parse_chat_request(
            "このネットワーク障害の原因を説明してください。",
            selected_language="auto",
        ).language, "ja")

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
        self.assertFalse(response_language_matches(
            "この問題の原因はネットワーク設定です。設定を確認してください。", "en"
        ))
        self.assertTrue(response_language_matches(
            "The likely cause is the network configuration. Check the route and DNS settings.", "en"
        ))

    def test_vietnamese_validator_rejects_english_body(self) -> None:
        self.assertFalse(response_language_matches(
            "The service is failing because the route is missing.", "vi"
        ))
        self.assertTrue(response_language_matches(
            "Dịch vụ đang lỗi vì tuyến mạng bị thiếu. Hãy kiểm tra cấu hình gateway.", "vi"
        ))

    def test_japanese_validator_rejects_english_body(self) -> None:
        self.assertFalse(response_language_matches(
            "The service is failing because the route is missing.", "ja"
        ))
        self.assertTrue(response_language_matches(
            "サービス障害の原因はルート設定です。ゲートウェイを確認してください。", "ja"
        ))

    def test_direct_chat_rejects_old_research_wrapper_leak(self) -> None:
        ok, reason = direct_chat_answer_valid(
            "# WorkSpace Report\n\nAgent 1 · Research result",
            "en",
            "Explain why my Python script fails.",
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "workflow_wrapper_leak")


class LanguageNeutralFormatTests(unittest.TestCase):
    def test_number_only_request_accepts_exact_number_without_forcing_prose(self) -> None:
        request = "Hãy chỉ trả lời bằng một số duy nhất: cổng HTTPS mặc định là bao nhiêu?"
        self.assertEqual(requested_language_neutral_format(request), "number")
        self.assertTrue(language_neutral_response_matches_request("443", request))
        self.assertEqual(direct_chat_answer_valid("443", "vi", request), (True, "ok"))

    def test_json_only_request_requires_whole_answer_to_be_json(self) -> None:
        request = "Hãy chỉ trả lời JSON thôi: đưa protocol và port của HTTPS."
        self.assertEqual(requested_language_neutral_format(request), "json")
        self.assertEqual(
            direct_chat_answer_valid('{"protocol":"HTTPS","port":443}', "vi", request),
            (True, "ok"),
        )
        ok, reason = direct_chat_answer_valid(
            'Kết quả: {"protocol":"HTTPS","port":443}', "vi", request
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "requested_format_mismatch")

    def test_japanese_code_only_request_accepts_one_fenced_block(self) -> None:
        request = (
            "LinuxでIPアドレスを表示するコマンドをコードブロックだけで返してください。"
            "日本語の説明文は不要です。"
        )
        answer = "```bash\nip addr\n```"
        self.assertEqual(requested_language_neutral_format(request), "code")
        self.assertEqual(direct_chat_answer_valid(answer, "ja", request), (True, "ok"))

    def test_command_only_request_accepts_one_shell_command(self) -> None:
        request = "Command only, no explanation: show listening TCP sockets on Linux."
        self.assertEqual(requested_language_neutral_format(request), "code")
        self.assertEqual(direct_chat_answer_valid("ss -lnt", "en", request), (True, "ok"))

    def test_explain_code_request_does_not_bypass_vietnamese_language_gate(self) -> None:
        request = "Hãy trả lời bằng tiếng Việt và giải thích đoạn code này hoạt động thế nào."
        self.assertEqual(requested_language_neutral_format(request), "")
        ok, reason = direct_chat_answer_valid(
            "This code opens a socket and waits for a connection.", "vi", request
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "target_language_mismatch")


if __name__ == "__main__":
    unittest.main()
