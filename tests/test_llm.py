import unittest
from types import SimpleNamespace

from three_agent.llm import (
    AdaptiveOllamaClient,
    LocalLLMError,
    OllamaClient,
    _extract_json_object,
)
from three_agent.resource_budget import ResourceAdmissionError


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

    def test_generate_json_passes_native_schema_to_request(self):
        class FakeClient(OllamaClient):
            def __init__(self):
                super().__init__(
                    SimpleNamespace(
                        model="qwen-test",
                        base_url="http://127.0.0.1:11434",
                        timeout_seconds=10,
                        keep_alive="2m",
                    )
                )
                self.calls = []

            def _request(self, system_prompt, user_prompt, **kwargs):
                self.calls.append((system_prompt, user_prompt, kwargs))
                return {"response": '{"answer":"ok"}'}

        schema = {
            "type": "object",
            "properties": {"answer": {"type": "string"}},
            "required": ["answer"],
            "additionalProperties": False,
        }
        client = FakeClient()
        result = client.generate_json("system", "user", schema=schema, schema_id="answer-v1")
        self.assertEqual(result, {"answer": "ok"})
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.calls[0][2]["format_schema"], schema)
        self.assertEqual(client.calls[0][2]["schema_id"], "answer-v1")

    def test_generate_json_schema_failure_does_not_retry_model(self):
        class FakeClient(OllamaClient):
            def __init__(self):
                super().__init__(
                    SimpleNamespace(
                        model="qwen-test",
                        base_url="http://127.0.0.1:11434",
                        timeout_seconds=10,
                        keep_alive="2m",
                    )
                )
                self.calls = 0

            def _request(self, system_prompt, user_prompt, **kwargs):
                self.calls += 1
                return {"response": '{}'}

        schema = {
            "type": "object",
            "properties": {"answer": {"type": "string"}},
            "required": ["answer"],
        }
        client = FakeClient()
        with self.assertRaisesRegex(LocalLLMError, "deterministic validation"):
            client.generate_json("system", "user", schema=schema)
        self.assertEqual(client.calls, 1)

    def test_generate_json_malformed_response_fails_without_probabilistic_repair(self):
        class FakeClient(OllamaClient):
            def __init__(self):
                super().__init__(
                    SimpleNamespace(
                        model="qwen-test",
                        base_url="http://127.0.0.1:11434",
                        timeout_seconds=10,
                        keep_alive="2m",
                    )
                )
                self.calls = 0

            def _request(self, system_prompt, user_prompt, **kwargs):
                self.calls += 1
                return {"response": '{"broken": }'}

        client = FakeClient()
        with self.assertRaisesRegex(LocalLLMError, "invalid JSON"):
            client.generate_json("system", "user")
        self.assertEqual(client.calls, 1)

    def test_adaptive_client_uses_primary_for_normal_prompt(self):
        class Fake:
            def __init__(self, name):
                self.config = SimpleNamespace(model=name)
                self.calls = 0

            def generate(self, system_prompt, user_prompt, **kwargs):
                self.calls += 1
                return self.config.model

            def unload(self):
                return None

        primary = Fake("research-30b")
        deep = Fake("deep-32b")
        client = AdaptiveOllamaClient(
            primary,
            deep=deep,
            deep_prompt_chars=100,
            role="research",
        )
        self.assertEqual(client.generate("s", "short prompt"), "research-30b")
        self.assertEqual(primary.calls, 1)
        self.assertEqual(deep.calls, 0)

    def test_adaptive_client_prefers_deep_for_large_research_prompt(self):
        class Fake:
            def __init__(self, name):
                self.config = SimpleNamespace(model=name)
                self.calls = 0

            def generate_json(self, system_prompt, user_prompt, **kwargs):
                self.calls += 1
                return {"model": self.config.model}

            def unload(self):
                return None

        primary = Fake("research-30b")
        deep = Fake("deep-32b")
        client = AdaptiveOllamaClient(
            primary,
            deep=deep,
            deep_prompt_chars=2000,
            role="research",
        )
        result = client.generate_json("s", "x" * 2500)
        self.assertEqual(result["model"], "deep-32b")
        self.assertEqual(primary.calls, 0)
        self.assertEqual(deep.calls, 1)

    def test_adaptive_client_escalates_after_primary_failure(self):
        class Fake:
            def __init__(self, name, fail=False):
                self.config = SimpleNamespace(model=name)
                self.fail = fail
                self.calls = 0

            def generate(self, system_prompt, user_prompt, **kwargs):
                self.calls += 1
                if self.fail:
                    raise LocalLLMError("primary failed")
                return self.config.model

            def unload(self):
                return None

        primary = Fake("presentation-14b", fail=True)
        deep = Fake("deep-32b")
        client = AdaptiveOllamaClient(primary, deep=deep, role="presentation")
        self.assertEqual(client.generate("s", "normal"), "deep-32b")
        self.assertEqual(primary.calls, 1)
        self.assertEqual(deep.calls, 1)

    def test_resource_denial_does_not_escalate_to_larger_model(self):
        class Fake:
            def __init__(self, name, deny=False):
                self.config = SimpleNamespace(model=name)
                self.deny = deny
                self.calls = 0

            def generate(self, system_prompt, user_prompt, **kwargs):
                self.calls += 1
                if self.deny:
                    raise ResourceAdmissionError("budget denied")
                return self.config.model

            def unload(self):
                return None

        primary = Fake("presentation-14b", deny=True)
        deep = Fake("deep-32b")
        client = AdaptiveOllamaClient(primary, deep=deep, role="presentation")
        with self.assertRaises(ResourceAdmissionError):
            client.generate("s", "normal")
        self.assertEqual(primary.calls, 1)
        self.assertEqual(deep.calls, 0)

    def test_deep_resource_denial_falls_back_to_primary(self):
        class Fake:
            def __init__(self, name, deny=False):
                self.config = SimpleNamespace(model=name)
                self.deny = deny
                self.calls = 0

            def generate_json(self, system_prompt, user_prompt, **kwargs):
                self.calls += 1
                if self.deny:
                    raise ResourceAdmissionError("budget denied")
                return {"model": self.config.model}

            def unload(self):
                return None

        primary = Fake("research-30b")
        deep = Fake("deep-32b", deny=True)
        client = AdaptiveOllamaClient(
            primary,
            deep=deep,
            deep_prompt_chars=2000,
            role="research",
        )
        result = client.generate_json("s", "x" * 2500)
        self.assertEqual(result["model"], "research-30b")
        self.assertEqual(deep.calls, 1)
        self.assertEqual(primary.calls, 1)


if __name__ == "__main__":
    unittest.main()
