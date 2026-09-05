from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from three_agent.chat_context import CONTEXT_MODE_FOLLOW_UP, CONTEXT_MODE_STANDALONE
from three_agent.chat_gateway import ContextAwareProjectChatService
from three_agent.chat_multiturn_acceptance import (
    CORPUS,
    MultiTurnCase,
    RecordingLLM,
    TurnSpec,
    contract_summary,
    corpus_sha256,
    run_case,
    validation_errors,
)


class FakeKnowledgeGateway:
    def validate_upload_ids(self, upload_ids):
        return list(upload_ids)

    def load_upload_sources(self, upload_ids, *, max_sources=8):
        del upload_ids, max_sources
        return [], []


class FakeStore:
    def record_activity(self, *args, **kwargs):
        del args, kwargs


class FakeLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def generate(self, system_prompt, user_prompt, **kwargs):
        self.calls.append((system_prompt, user_prompt, kwargs))
        if not self.responses:
            raise AssertionError("unexpected model call")
        return self.responses.pop(0)


class MultiTurnAcceptanceContractTests(unittest.TestCase):
    def test_repository_corpus_is_valid_and_hashed(self):
        self.assertEqual(validation_errors(), ())
        self.assertTrue(corpus_sha256().startswith("sha256:"))
        self.assertEqual(corpus_sha256(), corpus_sha256(tuple(CORPUS)))

    def test_contract_mode_never_claims_live_execution_or_raw_content(self):
        summary = contract_summary(CORPUS[:2])
        self.assertTrue(summary["valid"])
        self.assertFalse(summary["live_model_executed"])
        self.assertFalse(summary["privacy"]["raw_prompts_in_report"])
        self.assertFalse(summary["privacy"]["raw_answers_in_report"])
        self.assertFalse(summary["privacy"]["production_database_mutated"])
        self.assertFalse(summary["privacy"]["public_egress_enabled"])

    def test_corpus_contains_reference_language_and_stale_history_cases(self):
        ids = {case.case_id for case in CORPUS}
        self.assertIn("vi_network_reference_chain", ids)
        self.assertIn("en_reference_then_language_override", ids)
        self.assertIn("ja_network_reference_chain", ids)
        self.assertIn("stale_history_isolation", ids)
        self.assertIn("vi_missing_reference_clarifies", ids)


class MultiTurnAcceptanceServicePathTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp.cleanup()

    def _service(self, responses):
        delegate = FakeLLM(responses)
        recorder = RecordingLLM(delegate)
        orchestrator = SimpleNamespace(
            config=SimpleNamespace(database_path=Path(self.temp.name) / "acceptance.db"),
            knowledge_gateway=FakeKnowledgeGateway(),
            store=FakeStore(),
            llm=recorder,
        )
        service = ContextAwareProjectChatService(orchestrator, default_language="ja")
        service.start()
        return service, recorder

    def test_same_service_path_switches_standalone_to_follow_up_without_raw_report_content(self):
        case = MultiTurnCase(
            "unit_vi_follow_up",
            (
                TurnSpec(
                    "Hãy trả lời bằng tiếng Việt với đúng 2 gạch đầu dòng: IP và gateway.",
                    "vi",
                    CONTEXT_MODE_STANDALONE,
                    output_kind="bullets",
                    required_groups=(("IP",), ("gateway",)),
                    exact_items=2,
                    context_available=False,
                ),
                TurnSpec(
                    "Cái thứ hai: giải thích trong một câu.",
                    "vi",
                    CONTEXT_MODE_FOLLOW_UP,
                    required_groups=(("gateway",),),
                    max_lines=1,
                    min_context_messages=2,
                    context_available=True,
                ),
            ),
        )
        service, recorder = self._service([
            "- IP: kiểm tra địa chỉ IP.\n- gateway: kiểm tra cổng mặc định.",
            "Gateway là cổng mặc định dùng để chuyển lưu lượng ra ngoài mạng cục bộ.",
        ])
        result = run_case(service, recorder, case, timeout_seconds=3)
        service._queue.join()
        self.assertTrue(result["passed"], result)
        first, second = result["turns"]
        self.assertEqual(first["actual_context_mode"], CONTEXT_MODE_STANDALONE)
        self.assertEqual(first["context_message_count"], 0)
        self.assertFalse(first["prompt_evidence"]["recent_context"])
        self.assertEqual(second["actual_context_mode"], CONTEXT_MODE_FOLLOW_UP)
        self.assertGreaterEqual(second["context_message_count"], 2)
        self.assertTrue(second["prompt_evidence"]["recent_context"])
        rendered = repr(result)
        self.assertNotIn("kiểm tra địa chỉ IP", rendered)
        self.assertNotIn("cổng mặc định dùng để", rendered)

    def test_missing_reference_is_marked_unavailable_and_keeps_vietnamese(self):
        case = MultiTurnCase(
            "unit_missing_reference",
            (
                TurnSpec(
                    "tiếp theo?",
                    "vi",
                    CONTEXT_MODE_FOLLOW_UP,
                    required_groups=(("nội dung", "phần", "trước"),),
                    context_available=False,
                ),
            ),
        )
        service, recorder = self._service([
            "Bạn muốn tôi tiếp tục phần hoặc nội dung nào trước đó?"
        ])
        result = run_case(service, recorder, case, timeout_seconds=3)
        service._queue.join()
        self.assertTrue(result["passed"], result)
        turn = result["turns"][0]
        self.assertEqual(turn["actual_language"], "vi")
        self.assertEqual(turn["context_message_count"], 0)
        self.assertTrue(turn["prompt_evidence"]["unavailable_context"])


if __name__ == "__main__":
    unittest.main()
