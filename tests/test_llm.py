import unittest
from types import SimpleNamespace

from three_agent.llm import LocalLLMError, OllamaClient, _extract_json_object


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

    def test_generate_json_repairs_malformed_first_response(self):
        class FakeClient(OllamaClient):
            def __init__(self):
                super().__init__(
                    SimpleNamespace(
                        model="qwen-test",
                        base_url="http://127.0.0.1:11434",
                        timeout_seconds=10,
                    )
                )
                self.calls = []

            def _request(self, system_prompt, user_prompt, **kwargs):
                self.calls.append((system_prompt, user_prompt, kwargs))
                if len(self.calls) == 1:
                    return {"response": '{"verified_facts":[{"claim":"a" "source_ids":["S1"]}]}'}
                return {
                    "response": '{"verified_facts":[{"claim":"a","source_ids":["S1"]}]}'
                }

        client = FakeClient()
        result = client.generate_json("system", "user", num_predict=4096)
        self.assertEqual(result["verified_facts"][0]["source_ids"], ["S1"])
        self.assertEqual(len(client.calls), 2)
        self.assertIn("syntax repair", client.calls[1][0])

    def test_generate_json_fails_after_one_repair_retry(self):
        class FakeClient(OllamaClient):
            def __init__(self):
                super().__init__(
                    SimpleNamespace(
                        model="qwen-test",
                        base_url="http://127.0.0.1:11434",
                        timeout_seconds=10,
                    )
                )
                self.calls = 0

            def _request(self, system_prompt, user_prompt, **kwargs):
                self.calls += 1
                return {"response": '{"broken": }'}

        client = FakeClient()
        with self.assertRaisesRegex(LocalLLMError, "automatic repair retry also failed"):
            client.generate_json("system", "user")
        self.assertEqual(client.calls, 2)


if __name__ == "__main__":
    unittest.main()
