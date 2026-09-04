from __future__ import annotations

import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from three_agent.chat_fidelity import direct_chat_answer_valid
from three_agent.chat_gateway_v16 import (
    CONVERSATION_CONTEXT_POLICY_VERSION,
    FOLLOW_UP_REFERENCE_ANCHOR_POLICY,
)
from three_agent.chat_multiturn_acceptance_v2 import DiagnosticRecordingLLM
from three_agent.chat_output_contract import (
    ChatOutputContract,
    render_strict_structured_answer,
    strict_structured_schema,
)
from three_agent.chat_service_fidelity import (
    ContractAwareProjectChatService,
    _bounded_generation_num_predict,
    _strict_structured_mode,
    _structured_generation_num_predict,
    _use_structured_attempt,
)
from three_agent.llm import LocalLLMError, OllamaClient
from three_agent.resource_budget import ResourceAdmissionError


ROOT = Path(__file__).resolve().parents[1]


class _FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return b'{"response":"ok"}'


class _NoopStore:
    def record_activity(self, *args, **kwargs):
        del args, kwargs


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

    def _bare_service(self, llm, contract):
        service = object.__new__(ContractAwareProjectChatService)
        service.orchestrator = SimpleNamespace(llm=llm, store=_NoopStore())
        service._job_uploads = {"job": []}
        service._job_language_sources = {"job": "message_instruction"}
        service._effective_output_contract = lambda job, effort: contract
        service._direct_prompt = lambda job, uploads: (
            "<CURRENT_USER_REQUEST>\n"
            + job.message
            + "\n</CURRENT_USER_REQUEST>\n"
            + '<CONVERSATION_CONTEXT_POLICY mode="standalone">\n'
            + "Answer only the current request.\n"
            + "</CONVERSATION_CONTEXT_POLICY>"
        )
        service._test_updates = []
        service._test_stages = []
        service._update = lambda job_id, **kwargs: service._test_updates.append(
            (job_id, kwargs)
        )
        service._stage = lambda job_id, name, status, detail="": service._test_stages.append(
            (job_id, name, status, detail)
        )
        return service

    def test_standard_budget_is_capped_against_output_chars(self):
        bullets = SimpleNamespace(num_predict=288, max_chars=840)
        code = SimpleNamespace(num_predict=96, max_chars=160)
        number = SimpleNamespace(num_predict=16, max_chars=32)
        prose = SimpleNamespace(num_predict=768, max_chars=2800)

        self.assertEqual(_bounded_generation_num_predict(bullets, False), 168)
        self.assertEqual(_bounded_generation_num_predict(code, False), 32)
        self.assertEqual(_bounded_generation_num_predict(number, False), 8)
        self.assertEqual(_bounded_generation_num_predict(prose, False), 560)

    def test_structured_internal_json_budget_has_independent_floor(self):
        number = ChatOutputContract(
            kind="single_number",
            max_lines=1,
            max_chars=32,
            num_predict=16,
        )
        bullets = ChatOutputContract(
            kind="bullets",
            exact_items=3,
            max_chars=840,
            num_predict=288,
        )
        prose = ChatOutputContract(kind="prose", max_chars=2800, num_predict=768)

        self.assertEqual(_bounded_generation_num_predict(number, False), 8)
        self.assertEqual(_structured_generation_num_predict(number, 8), 32)
        self.assertEqual(_structured_generation_num_predict(bullets, 168), 168)
        self.assertEqual(_structured_generation_num_predict(prose, 560), 560)

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

    def test_vi_technical_only_bullets_stay_rejected_by_language_gate(self):
        request = (
            "Hãy trả lời bằng tiếng Việt với đúng 3 gạch đầu dòng theo thứ tự: "
            "(1) kiểm tra địa chỉ IP bằng ip addr; (2) kiểm tra default gateway bằng "
            "ip route; (3) kiểm tra DNS bằng resolvectl status."
        )
        technical_only = "- ip addr\n- ip route\n- resolvectl status"
        localized = (
            "- Kiểm tra địa chỉ IP bằng ip addr\n"
            "- Kiểm tra cổng mặc định bằng ip route\n"
            "- Kiểm tra DNS bằng resolvectl status"
        )

        self.assertEqual(
            direct_chat_answer_valid(technical_only, "vi", request),
            (False, "target_language_mismatch"),
        )
        self.assertEqual(
            direct_chat_answer_valid(localized, "vi", request),
            (True, "ok"),
        )

    def test_structured_repair_uses_independent_plain_generation_path(self):
        self.assertTrue(_use_structured_attempt(True, 0, ""))
        self.assertFalse(
            _use_structured_attempt(True, 1, "target_language_mismatch")
        )
        self.assertFalse(
            _use_structured_attempt(True, 1, "structured_runtime_error")
        )
        self.assertTrue(
            _use_structured_attempt(True, 1, "output_contract_chars:900_gt_840")
        )
        self.assertFalse(_use_structured_attempt(False, 0, ""))

    def test_local_structured_failure_gets_one_plain_bounded_repair(self):
        class LLM:
            def __init__(self):
                self.json_calls = []
                self.plain_calls = []

            def generate_json(self, system_prompt, user_prompt, **kwargs):
                del system_prompt, user_prompt
                self.json_calls.append(kwargs)
                raise LocalLLMError("Local LLM returned invalid JSON")

            def generate(self, system_prompt, user_prompt, **kwargs):
                del system_prompt, user_prompt
                self.plain_calls.append(kwargs)
                return "443"

        contract = ChatOutputContract(
            kind="single_number",
            max_lines=1,
            max_chars=32,
            num_predict=16,
        )
        llm = LLM()
        service = self._bare_service(llm, contract)
        job = SimpleNamespace(
            language="vi",
            message="Hãy chỉ trả lời bằng một số duy nhất: cổng HTTPS mặc định là bao nhiêu?",
        )

        service._execute_direct_chat("job", job, "standard")

        self.assertEqual(len(llm.json_calls), 1)
        self.assertEqual(llm.json_calls[0]["num_predict"], 32)
        self.assertEqual(len(llm.plain_calls), 1)
        self.assertEqual(llm.plain_calls[0]["num_predict"], 8)
        self.assertEqual(service._test_updates[-1][1]["status"], "completed")
        self.assertEqual(service._test_updates[-1][1]["answer"], "443")

    def test_resource_admission_denial_remains_fail_closed_without_plain_retry(self):
        class LLM:
            def __init__(self):
                self.json_calls = 0
                self.plain_calls = 0

            def generate_json(self, system_prompt, user_prompt, **kwargs):
                del system_prompt, user_prompt, kwargs
                self.json_calls += 1
                raise ResourceAdmissionError("denied")

            def generate(self, system_prompt, user_prompt, **kwargs):
                del system_prompt, user_prompt, kwargs
                self.plain_calls += 1
                return "443"

        contract = ChatOutputContract(
            kind="single_number",
            max_lines=1,
            max_chars=32,
            num_predict=16,
        )
        llm = LLM()
        service = self._bare_service(llm, contract)
        job = SimpleNamespace(
            language="vi",
            message="Hãy chỉ trả lời bằng một số duy nhất: cổng HTTPS mặc định là bao nhiêu?",
        )

        service._execute_direct_chat("job", job, "standard")

        self.assertEqual(llm.json_calls, 1)
        self.assertEqual(llm.plain_calls, 0)
        self.assertEqual(service._test_updates[-1][1]["status"], "failed")
        self.assertIn("ResourceAdmissionError", service._test_updates[-1][1]["error"])

    def test_follow_up_reference_policy_requires_semantic_self_containment(self):
        policy = " ".join(FOLLOW_UP_REFERENCE_ANCHOR_POLICY)
        self.assertEqual(
            CONVERSATION_CONTEXT_POLICY_VERSION,
            "deterministic-reference-gated/v2",
        )
        self.assertIn("semantic subject or concept", policy)
        self.assertIn("preserve the semantic label", policy)
        self.assertIn("command or identifier", policy)
        self.assertIn("number, or JSON-only output", policy)

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
        self.assertIn("structured_num_predict = _structured_generation_num_predict", text)
        self.assertIn("generation_temperature = None if high_effort else 0.0", text)
        self.assertIn("structured_mode = _strict_structured_mode", text)
        self.assertIn("use_structured = _use_structured_attempt", text)
        self.assertIn("except LocalLLMError:", text)
        self.assertIn("self.orchestrator.llm.generate_json(", text)
        self.assertIn("num_predict=structured_num_predict", text)
        self.assertIn("render_strict_structured_answer(contract, payload)", text)
        self.assertIn("temperature=generation_temperature", text)
        self.assertIn("for attempt in range(2):", text)
        self.assertIn("contract.validate(answer)", text)
        self.assertIn("Technical commands and identifiers may remain unchanged", text)

    def test_reference_policy_is_wired_only_into_follow_up_context(self):
        text = (ROOT / "src/three_agent/chat_gateway_v16.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("*FOLLOW_UP_REFERENCE_ANCHOR_POLICY", text)
        self.assertIn("follow_up_reference_anchoring", text)
        self.assertIn('<CONVERSATION_CONTEXT_POLICY mode="standalone">', text)


if __name__ == "__main__":
    unittest.main()
