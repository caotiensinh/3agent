from __future__ import annotations

import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from three_agent.chat_service_fidelity_v2 import _bounded_generation_num_predict
from three_agent.llm import OllamaClient


ROOT = Path(__file__).resolve().parents[1]


class _FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return b'{"response":"ok"}'


class P2ConstrainedGenerationTests(unittest.TestCase):
    def _client(self) -> OllamaClient:
        return OllamaClient(
            SimpleNamespace(
                model="qwen-test",
                base_url="http://127.0.0.1:11434",
                timeout_seconds=10,
                keep_alive="2m",
            ),
            telemetry=None,
        )

    def test_standard_budget_is_capped_against_output_chars(self):
        bullets = SimpleNamespace(num_predict=288, max_chars=840)
        code = SimpleNamespace(num_predict=96, max_chars=160)
        number = SimpleNamespace(num_predict=16, max_chars=32)
        prose = SimpleNamespace(num_predict=768, max_chars=2800)

        self.assertEqual(_bounded_generation_num_predict(bullets, False), 168)
        self.assertEqual(_bounded_generation_num_predict(code, False), 32)
        self.assertEqual(_bounded_generation_num_predict(number, False), 8)
        self.assertEqual(_bounded_generation_num_predict(prose, False), 560)

    def test_high_effort_preserves_reasoning_floor(self):
        strict = SimpleNamespace(num_predict=96, max_chars=160)
        deep = SimpleNamespace(num_predict=2048, max_chars=8000)
        self.assertEqual(_bounded_generation_num_predict(strict, True), 768)
        self.assertEqual(_bounded_generation_num_predict(deep, True), 2048)

    def test_explicit_temperature_reaches_ollama_request(self):
        captured = {}

        def fake_urlopen(req, timeout):
            captured["timeout"] = timeout
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return _FakeResponse()

        with mock.patch("three_agent.llm.urlopen", side_effect=fake_urlopen):
            answer = self._client().generate(
                "system",
                "user",
                num_predict=37,
                temperature=0.0,
                trust_domain="workspace-local-chat",
                template_version="workspace.chat.direct.v2",
            )

        self.assertEqual(answer, "ok")
        self.assertEqual(captured["body"]["options"]["num_predict"], 37)
        self.assertEqual(captured["body"]["options"]["temperature"], 0.0)
        self.assertFalse(captured["body"]["think"])

    def test_default_sampling_remains_unforced_for_high_effort_callers(self):
        captured = {}

        def fake_urlopen(req, timeout):
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return _FakeResponse()

        with mock.patch("three_agent.llm.urlopen", side_effect=fake_urlopen):
            self._client().generate("system", "user", think=True, num_predict=768)

        self.assertEqual(captured["body"]["options"]["num_predict"], 768)
        self.assertNotIn("temperature", captured["body"]["options"])
        self.assertTrue(captured["body"]["think"])

    def test_production_service_wires_bounded_budget_and_sampling(self):
        text = (ROOT / "src/three_agent/chat_service_fidelity_v2.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "generation_num_predict = _bounded_generation_num_predict(contract, high_effort)",
            text,
        )
        self.assertIn("generation_temperature = None if high_effort else 0.0", text)
        self.assertIn("temperature=generation_temperature", text)
        self.assertIn("for attempt in range(2):", text)
        self.assertIn("contract.validate(answer)", text)


if __name__ == "__main__":
    unittest.main()
