from __future__ import annotations

import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from three_agent.chat_multiturn_acceptance_v2 import DiagnosticRecordingLLM
from three_agent.chat_output_contract import (
    ChatOutputContract,
    render_strict_structured_answer,
    strict_structured_schema,
)
from three_agent.chat_service_fidelity_v2 import (
    _bounded_generation_num_predict,
    _strict_structured_mode,
)
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

    def test_bullet_schema_has_exact_required_properties_without_extras(self):
        contract = ChatOutputContract(
            kind="bullets",
            exact_items=3,
            max_chars=840,
            num_predict=288,
        )
        schema = strict_structured_schema(contract)
        self.assertIsNotNone(schema)
        self.assertEqual(
            list(schema["properties"]),
            ["item_1", "item_2", "item_3"],
        )
        self.assertEqual(schema["required"], ["item_1", "item_2", "item_3"])
        self.assertFalse(schema["additionalProperties"])

    def test_structured_bullet_renderer_removes_wrapper_shape_by_construction(self):
        contract = ChatOutputContract(
            kind="bullets",
            exact_items=3,
            max_chars=840,
            num_predict=288,
        )
        answer = render_strict_structured_answer(
            contract,
            {
                "item_1": "- ip addr kiểm tra địa chỉ IP",
                "item_2": "2. ip route kiểm tra default gateway",
                "item_3": "resolvectl status\nkiểm tra DNS",
            },
        )
        self.assertEqual(
            answer,
            "- ip addr kiểm tra địa chỉ IP\n"
            "- ip route kiểm tra default gateway\n"
            "- resolvectl status kiểm tra DNS",
        )
        self.assertEqual(contract.validate(answer), (True, "ok"))

    def test_structured_number_renderer_is_canonical(self):
        contract = ChatOutputContract(kind="single_number", max_lines=1, max_chars=32)
        self.assertEqual(render_strict_structured_answer(contract, {"value": 443}), "443")
        self.assertEqual(render_strict_structured_answer(contract, {"value": 443.0}), "443")
        self.assertEqual(contract.validate("443"), (True, "ok"))

    def test_structured_single_sentence_still_faces_authoritative_validator(self):
        contract = ChatOutputContract(kind="single_sentence", max_lines=1, max_chars=400)
        answer = render_strict_structured_answer(
            contract,
            {"answer": "First sentence.\nSecond sentence."},
        )
        self.assertEqual(answer, "First sentence. Second sentence.")
        self.assertFalse(contract.validate(answer)[0])

    def test_structured_mode_is_standard_only_and_requires_json_capability(self):
        contract = ChatOutputContract(kind="single_sentence", max_lines=1, max_chars=400)
        capable = SimpleNamespace(generate_json=lambda *args, **kwargs: {})
        incapable = SimpleNamespace(generate=lambda *args, **kwargs: "")
        self.assertTrue(_strict_structured_mode(capable, contract, False))
        self.assertFalse(_strict_structured_mode(capable, contract, True))
        self.assertFalse(_strict_structured_mode(incapable, contract, False))

    def test_diagnostic_recorder_tracks_structured_calls_without_raw_output(self):
        class Delegate:
            def generate_json(self, system_prompt, user_prompt, **kwargs):
                del system_prompt, kwargs
                return {"answer": "sensitive-model-answer"}

        recorder = DiagnosticRecordingLLM(Delegate())
        result = recorder.generate_json(
            "system",
            '<CURRENT_USER_REQUEST>\nmode="standalone"\nsecret prompt',
            schema={"type": "object"},
        )
        self.assertEqual(result, {"answer": "sensitive-model-answer"})
        self.assertEqual(len(recorder.calls), 1)
        evidence = recorder.calls[0]
        self.assertTrue(evidence.succeeded)
        self.assertTrue(evidence.current_request_boundary)
        self.assertTrue(evidence.standalone_policy)
        self.assertFalse(hasattr(evidence, "answer"))

    def test_production_service_wires_bounded_budget_and_structured_decoding(self):
        text = (ROOT / "src/three_agent/chat_service_fidelity_v2.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "generation_num_predict = _bounded_generation_num_predict(contract, high_effort)",
            text,
        )
        self.assertIn("generation_temperature = None if high_effort else 0.0", text)
        self.assertIn("structured_mode = _strict_structured_mode", text)
        self.assertIn("self.orchestrator.llm.generate_json(", text)
        self.assertIn("render_strict_structured_answer(contract, payload)", text)
        self.assertIn("temperature=generation_temperature", text)
        self.assertIn("for attempt in range(2):", text)
        self.assertIn("contract.validate(answer)", text)


if __name__ == "__main__":
    unittest.main()
