from __future__ import annotations

import unittest
from pathlib import Path

from three_agent.chat_context import (
    CONTEXT_MODE_FOLLOW_UP,
    CONTEXT_MODE_STANDALONE,
    classify_context_request,
)
from three_agent.chat_output_contract import (
    compile_chat_output_contract,
    tighten_for_missing_reference,
)


ROOT = Path(__file__).resolve().parents[1]


class ChatOutputContractTests(unittest.TestCase):
    def test_vi_exact_bullets_are_bounded(self):
        contract = compile_chat_output_contract(
            "Hãy nêu đúng 3 gạch đầu dòng về cách kiểm tra DNS."
        )
        self.assertEqual(contract.kind, "bullets")
        self.assertEqual(contract.exact_items, 3)
        self.assertLessEqual(contract.max_chars, 900)
        self.assertLess(contract.num_predict, 4096)
        self.assertEqual(contract.validate("- Một\n- Hai\n- Ba"), (True, "ok"))
        self.assertFalse(contract.validate("Mở đầu\n- Một\n- Hai\n- Ba")[0])

    def test_en_exact_bullets_are_bounded(self):
        contract = compile_chat_output_contract(
            "Reply in English with exactly 2 bullet points about DNS checks."
        )
        self.assertEqual(contract.kind, "bullets")
        self.assertEqual(contract.exact_items, 2)
        self.assertLessEqual(contract.max_chars, 700)

    def test_ja_exact_bullets_are_bounded(self):
        contract = compile_chat_output_contract(
            "日本語で、DNS確認方法をちょうど3つの箇条書きで答えてください。"
        )
        self.assertEqual(contract.kind, "bullets")
        self.assertEqual(contract.exact_items, 3)
        self.assertLessEqual(contract.max_chars, 900)

    def test_one_sentence_has_hard_line_size_and_sentence_budget(self):
        for prompt in (
            "Explain that in exactly one sentence.",
            "Đúng một câu thôi.",
            "一文で答えてください。",
        ):
            with self.subTest(prompt=prompt):
                contract = compile_chat_output_contract(prompt)
                self.assertEqual(contract.kind, "single_sentence")
                self.assertEqual(contract.max_lines, 1)
                self.assertLessEqual(contract.max_chars, 400)
                self.assertLessEqual(contract.num_predict, 128)
                self.assertTrue(contract.validate("This is one sentence.")[0])
                self.assertFalse(contract.validate("First sentence. Second sentence.")[0])
                self.assertFalse(contract.validate("一文です。二文目です。")[0])

    def test_sentence_validator_does_not_split_decimal(self):
        contract = compile_chat_output_contract("Explain in one sentence.")
        self.assertTrue(contract.validate("Version 1.2 remains supported.")[0])

    def test_language_neutral_formats_are_tightly_bounded(self):
        number = compile_chat_output_contract("Chỉ trả lời một số duy nhất: HTTPS port?")
        self.assertEqual(number.kind, "single_number")
        self.assertTrue(number.validate("443")[0])
        self.assertFalse(number.validate("Port 443")[0])

        command = compile_chat_output_contract("Return the command only, no explanation.")
        self.assertEqual(command.kind, "code_only")
        self.assertLessEqual(command.max_chars, 160)

        json_only = compile_chat_output_contract("JSON only: return the result.")
        self.assertEqual(json_only.kind, "json_only")
        self.assertTrue(json_only.validate('{"ok":true}')[0])
        self.assertFalse(json_only.validate("```json\n{}\n```")[0])

    def test_missing_reference_forces_one_concise_clarification(self):
        original = compile_chat_output_contract("tiếp theo?")
        tightened = tighten_for_missing_reference(original)
        self.assertEqual(tightened.kind, "single_sentence")
        self.assertEqual(tightened.max_lines, 1)
        self.assertLessEqual(tightened.max_chars, 400)
        self.assertIn("do not invent", tightened.instruction)
        self.assertFalse(tightened.validate("Bạn muốn tiếp phần nào? Hãy cho tôi nội dung trước.")[0])

    def test_standard_default_no_longer_has_4096_token_budget(self):
        contract = compile_chat_output_contract("Explain DNSSEC briefly.", effort="standard")
        self.assertEqual(contract.kind, "prose")
        self.assertLess(contract.num_predict, 4096)
        self.assertLessEqual(contract.max_chars, 2800)

    def test_japanese_internal_numbered_list_is_standalone(self):
        prompt = (
            "日本語で、DNSの確認方法を説明してください。"
            "1つ目は名前解決、2つ目は到達性、3つ目はDNSサーバー確認です。"
        )
        mode, _, _ = classify_context_request(prompt)
        self.assertEqual(mode, CONTEXT_MODE_STANDALONE)

        mode, _, language = classify_context_request("2つ目だけ詳しく説明してください。")
        self.assertEqual(mode, CONTEXT_MODE_FOLLOW_UP)
        self.assertEqual(language, "ja")

    def test_current_service_preserves_high_reasoning_and_dynamic_predict_budget(self):
        text = (ROOT / "src/three_agent/chat_service_fidelity_v2.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('high_effort = str(effort or "").strip().lower() == "high"', text)
        self.assertIn("think=high_effort", text)
        self.assertIn("generation_num_predict = max(contract.num_predict, 768) if high_effort else contract.num_predict", text)
        self.assertIn("num_predict=generation_num_predict", text)
        self.assertIn("contract.validate(answer)", text)
        self.assertIn("workspace.chat.direct.v2", text)


if __name__ == "__main__":
    unittest.main()
