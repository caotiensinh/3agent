import unittest

from three_agent.llm import LocalLLMError, _extract_json_object


class LLMTests(unittest.TestCase):
    def test_extract_plain_json(self):
        self.assertEqual(_extract_json_object('{"ok": true}'), {"ok": True})

    def test_extract_fenced_json(self):
        self.assertEqual(_extract_json_object('```json\n{"value": 3}\n```'), {"value": 3})

    def test_extract_json_from_surrounding_text(self):
        self.assertEqual(_extract_json_object('result follows: {"value": 4} end'), {"value": 4})

    def test_reject_non_object(self):
        with self.assertRaises(LocalLLMError):
            _extract_json_object('[1, 2, 3]')


if __name__ == "__main__":
    unittest.main()
