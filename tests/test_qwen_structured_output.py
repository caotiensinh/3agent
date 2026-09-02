import unittest

from three_agent.llm import LocalLLMError, _extract_json_object


class QwenStructuredOutputTests(unittest.TestCase):
    def test_ignores_complete_thinking_wrapper_with_json_like_reasoning(self):
        response = '<think>candidate {"wrong": true}</think>\n{"value": 5}'
        self.assertEqual(_extract_json_object(response), {"value": 5})

    def test_accepts_json_fence_surrounded_by_prose(self):
        response = 'analysis complete\n```json\n{"value": 6}\n```\ndone'
        self.assertEqual(_extract_json_object(response), {"value": 6})

    def test_balanced_extraction_preserves_braces_inside_json_strings(self):
        response = 'prefix {"text":"brace } inside { string","nested":{"ok":true}} suffix'
        self.assertEqual(
            _extract_json_object(response),
            {"text": "brace } inside { string", "nested": {"ok": True}},
        )

    def test_rejects_multiple_valid_json_objects_as_ambiguous(self):
        with self.assertRaisesRegex(LocalLLMError, "multiple JSON objects"):
            _extract_json_object('{"first": 1}\n{"second": 2}')

    def test_rejects_unterminated_thinking_wrapper(self):
        with self.assertRaisesRegex(LocalLLMError, "unterminated thinking wrapper"):
            _extract_json_object('<think>candidate reasoning\n{"value": 7}')

    def test_does_not_salvage_nested_object_from_invalid_outer_json(self):
        with self.assertRaisesRegex(LocalLLMError, "invalid JSON"):
            _extract_json_object('{"broken": {"nested": true}, }')


if __name__ == "__main__":
    unittest.main()
