from __future__ import annotations

import inspect
import json
import unittest
from types import SimpleNamespace

from three_agent.chat_context import (
    CONTEXT_MODE_FOLLOW_UP,
    CONTEXT_MODE_STANDALONE,
    classify_context_request,
)
from three_agent.chat_output_contract import (
    compile_chat_output_contract,
    render_strict_structured_answer,
    strict_structured_schema,
    tighten_for_missing_reference,
)
from three_agent.chat_service_fidelity import (
    ContractAwareProjectChatService,
    _bounded_generation_num_predict,
    _use_structured_attempt,
)


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

    def test_multilingual_explicit_line_bounds_are_compiled(self):
        prompts = (
            (
                "Dịch câu sau sang tiếng Việt và chỉ trả lời một dòng: 'The service started successfully.'",
                1,
            ),
            (
                "次の文を日本語に翻訳し、一行だけで答えてください: 'The service started successfully.'",
                1,
            ),
            (
                "Translate the following into English in one line only: 'Dịch vụ đã khởi động thành công.'",
                1,
            ),
            (
                "Trả lời bằng tiếng Việt trong tối đa 3 dòng: đoạn Python này lỗi vì sao?",
                3,
            ),
            (
                "日本語で3行以内に答えてください。Python のエラー原因は何ですか。",
                3,
            ),
            (
                "Reply in English in at most 3 lines: why does this Python fail?",
                3,
            ),
        )
        for prompt, expected_lines in prompts:
            with self.subTest(prompt=prompt):
                contract = compile_chat_output_contract(prompt)
                self.assertEqual(contract.kind, "brief_prose")
                self.assertEqual(contract.max_lines, expected_lines)
                self.assertIsNotNone(strict_structured_schema(contract))

        one_line = compile_chat_output_contract(prompts[0][0])
        self.assertTrue(one_line.validate("Một dòng.")[0])
        self.assertFalse(one_line.validate("Dòng một.\nDòng hai.")[0])

    def test_explicit_json_keys_use_structured_decoder_and_exact_renderer(self):
        prompts = (
            "Trả lời bằng JSON thuần, không giải thích. Dùng hai khóa protocol và port cho dịch vụ HTTPS mặc định.",
            "説明文なしのJSONだけで答えてください。標準HTTPSサービスについて protocol と port の2つのキーを使ってください。",
            "Reply with JSON only, no prose. Use the two keys protocol and port for the default HTTPS service.",
        )
        for prompt in prompts:
            with self.subTest(prompt=prompt):
                contract = compile_chat_output_contract(prompt)
                self.assertEqual(contract.kind, "json_only")
                self.assertEqual(contract.json_keys, ("protocol", "port"))
                schema = strict_structured_schema(contract)
                self.assertIsNotNone(schema)
                self.assertEqual(schema["required"], ["protocol", "port"])
                self.assertFalse(schema["additionalProperties"])
                rendered = render_strict_structured_answer(
                    contract,
                    {"protocol": "https", "port": 443},
                )
                self.assertEqual(json.loads(rendered), {"protocol": "https", "port": 443})
                self.assertTrue(contract.validate(rendered)[0])
                self.assertFalse(contract.validate('{"protocol":"https"}')[0])

    def test_missing_reference_forces_one_concise_clarification(self):
        original = compile_chat_output_contract("tiếp theo?")
        tightened = tighten_for_missing_reference(original)
        self.assertEqual(tightened.kind, "single_sentence")
        self.assertEqual(tightened.max_lines, 1)
        self.assertLessEqual(tightened.max_chars, 400)
        self.assertIn("do not invent", tightened.instruction)
        self.assertFalse(tightened.validate("Bạn muốn tiếp phần nào? Hãy cho tôi nội dung trước.")[0])

    def test_explicit_multilingual_brevity_is_a_hard_current_request_bound(self):
        prompts = (
            "Hãy giới thiệu ngắn gọn về bạn bằng tiếng Việt.",
            "日本語で簡単に自己紹介してください。",
            "Please introduce yourself briefly in English.",
            "Explain DNSSEC concisely.",
        )
        for prompt in prompts:
            with self.subTest(prompt=prompt):
                contract = compile_chat_output_contract(prompt, effort="standard")
                self.assertEqual(contract.kind, "brief_prose")
                self.assertEqual(contract.max_chars, 600)
                self.assertLessEqual(contract.num_predict, 128)
                self.assertTrue(contract.validate("A" * 600)[0])
                self.assertFalse(contract.validate("A" * 601)[0])

    def test_brief_topic_word_does_not_accidentally_shrink_detailed_request(self):
        contract = compile_chat_output_contract(
            "Provide a detailed analysis of brief packet-loss incidents in this trace.",
            effort="standard",
        )
        self.assertEqual(contract.kind, "prose")
        self.assertEqual(contract.max_chars, 2800)

    def test_standard_default_no_longer_has_4096_token_budget(self):
        contract = compile_chat_output_contract("Explain DNSSEC with practical details.", effort="standard")
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

    def test_structured_retry_falls_back_on_requested_format_mismatch(self):
        self.assertTrue(_use_structured_attempt(True, 0, ""))
        self.assertFalse(
            _use_structured_attempt(True, 1, "requested_format_mismatch")
        )
        self.assertFalse(
            _use_structured_attempt(True, 1, "target_language_mismatch")
        )
        self.assertTrue(
            _use_structured_attempt(True, 1, "output_contract_lines:2_gt_1")
        )

    def test_current_service_preserves_task_semantics_and_validation(self):
        source = inspect.getsource(ContractAwareProjectChatService._execute_direct_chat)
        self.assertIn(
            "For a translation request, put the translated text itself in the value",
            source,
        )
        self.assertIn("direct_chat_answer_valid(answer, job.language, job.message)", source)
        self.assertIn("contract.validate(answer)", source)
        self.assertIn("for attempt in range(2)", source)

    def test_current_service_preserves_high_reasoning_and_bounds_standard_generation(self):
        standard = SimpleNamespace(num_predict=4096, max_chars=2800)
        high_floor = SimpleNamespace(num_predict=128, max_chars=600)
        self.assertEqual(_bounded_generation_num_predict(standard, False), 560)
        self.assertEqual(_bounded_generation_num_predict(high_floor, True), 768)

        source = inspect.getsource(ContractAwareProjectChatService._execute_direct_chat)
        self.assertIn("think=high_effort", source)
        self.assertIn("generation_temperature = None if high_effort else 0.0", source)
        self.assertIn("num_predict=generation_num_predict", source)
        self.assertIn("temperature=generation_temperature", source)
        self.assertIn("contract.validate(answer)", source)
        self.assertIn('template_version="workspace.chat.direct.v2"', source)


if __name__ == "__main__":
    unittest.main()
