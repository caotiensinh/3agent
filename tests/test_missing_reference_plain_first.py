from __future__ import annotations

import unittest
from types import SimpleNamespace

from three_agent.chat_output_contract import (
    ChatOutputContract,
    strict_structured_schema,
    tighten_for_missing_reference,
)
from three_agent.chat_service_fidelity_v2 import ContractAwareProjectChatService


class _NoopStore:
    def record_activity(self, *args, **kwargs):
        del args, kwargs


class MissingReferencePlainFirstTests(unittest.TestCase):
    def test_missing_reference_disables_only_internal_structured_decoding(self) -> None:
        normal = ChatOutputContract(
            kind="single_sentence",
            max_lines=1,
            max_chars=400,
            num_predict=128,
            instruction="Return exactly one concise sentence.",
        )
        clarification = tighten_for_missing_reference(normal)

        self.assertEqual(clarification.kind, "single_sentence")
        self.assertEqual(clarification.max_lines, 1)
        self.assertLessEqual(clarification.max_chars, 400)
        self.assertTrue(normal.structured_decoding)
        self.assertFalse(clarification.structured_decoding)
        self.assertIsNotNone(strict_structured_schema(normal))
        self.assertIsNone(strict_structured_schema(clarification))

    def test_missing_reference_uses_one_plain_model_call_when_first_answer_is_valid(self) -> None:
        class LLM:
            def __init__(self) -> None:
                self.json_calls = 0
                self.plain_calls = 0

            def generate_json(self, system_prompt, user_prompt, **kwargs):
                del system_prompt, user_prompt, kwargs
                self.json_calls += 1
                raise AssertionError("missing-reference clarification must not use JSON decoding")

            def generate(self, system_prompt, user_prompt, **kwargs):
                del system_prompt, user_prompt, kwargs
                self.plain_calls += 1
                return "Bạn muốn tôi tiếp tục phần nào?"

        contract = tighten_for_missing_reference(
            ChatOutputContract(kind="prose", max_chars=2800, num_predict=768)
        )
        llm = LLM()
        service = object.__new__(ContractAwareProjectChatService)
        service.orchestrator = SimpleNamespace(llm=llm, store=_NoopStore())
        service._job_uploads = {"job": []}
        service._job_language_sources = {"job": "follow_up_cue"}
        service._effective_output_contract = lambda job, effort: contract
        service._direct_prompt = lambda job, uploads: (
            "<CURRENT_USER_REQUEST>\n"
            + job.message
            + "\n</CURRENT_USER_REQUEST>\n"
            + '<CONVERSATION_CONTEXT_POLICY mode="follow_up">\n'
            + "Resolve only the current missing reference.\n"
            + "</CONVERSATION_CONTEXT_POLICY>\n"
            + '<RECENT_CONVERSATION_CONTEXT available="false">\n'
            + "No eligible completed prior conversation is available.\n"
            + "</RECENT_CONVERSATION_CONTEXT>"
        )
        service._test_updates = []
        service._test_stages = []
        service._update = lambda job_id, **kwargs: service._test_updates.append(
            (job_id, kwargs)
        )
        service._stage = lambda job_id, name, status, detail="": service._test_stages.append(
            (job_id, name, status, detail)
        )

        job = SimpleNamespace(language="vi", message="tiếp theo?")
        service._execute_direct_chat("job", job, "standard")

        self.assertEqual(llm.json_calls, 0)
        self.assertEqual(llm.plain_calls, 1)
        self.assertEqual(service._test_updates[-1][1]["status"], "completed")
        self.assertEqual(
            service._test_updates[-1][1]["answer"],
            "Bạn muốn tôi tiếp tục phần nào?",
        )


if __name__ == "__main__":
    unittest.main()
