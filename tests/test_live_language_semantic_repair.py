from __future__ import annotations

import unittest
from types import SimpleNamespace

from three_agent.chat_output_contract import (
    ChatOutputContract,
    render_strict_structured_answer,
    strict_structured_schema,
)
from three_agent.chat_service_fidelity import ContractAwareProjectChatService


class _NoopStore:
    def record_activity(self, *args, **kwargs):
        del args, kwargs


def _service(llm, contract, prompt):
    service = object.__new__(ContractAwareProjectChatService)
    service.orchestrator = SimpleNamespace(llm=llm, store=_NoopStore())
    service._job_uploads = {"job": []}
    service._job_language_sources = {"job": "detected"}
    service._effective_output_contract = lambda job, effort: contract
    service._direct_prompt = lambda job, uploads: prompt
    service._updates = []
    service._stages = []
    service._update = lambda job_id, **kwargs: service._updates.append((job_id, kwargs))
    service._stage = lambda job_id, name, status, detail="": service._stages.append(
        (job_id, name, status, detail)
    )
    return service


class LiveLanguageSemanticRepairTests(unittest.TestCase):
    def test_brief_prose_has_private_structured_envelope_but_keeps_visible_cap(self) -> None:
        contract = ChatOutputContract(
            kind="brief_prose",
            max_chars=600,
            num_predict=128,
            instruction="Answer briefly.",
        )
        schema = strict_structured_schema(contract)
        self.assertIsNotNone(schema)
        self.assertEqual(schema["required"], ["answer"])
        self.assertFalse(schema["additionalProperties"])
        answer = render_strict_structured_answer(
            contract,
            {"answer": "日本語の短い説明です。\n二文目も日本語です。"},
        )
        self.assertEqual(answer, "日本語の短い説明です。 二文目も日本語です。")
        self.assertEqual(contract.validate(answer), (True, "ok"))
        self.assertFalse(contract.validate("あ" * 601)[0])

    def test_follow_up_structured_prompt_requires_resolved_semantic_label(self) -> None:
        class LLM:
            def __init__(self) -> None:
                self.system_prompts = []

            def generate_json(self, system_prompt, user_prompt, **kwargs):
                del user_prompt, kwargs
                self.system_prompts.append(system_prompt)
                return {"answer": "Cổng mặc định được kiểm tra bằng ip route."}

        contract = ChatOutputContract(
            kind="single_sentence",
            max_lines=1,
            max_chars=400,
            num_predict=128,
            instruction="Return exactly one concise sentence.",
        )
        prompt = (
            "<CURRENT_USER_REQUEST>\nCái thứ hai: giải thích trong đúng một câu.\n"
            "</CURRENT_USER_REQUEST>\n"
            '<CONVERSATION_CONTEXT_POLICY mode="follow_up">\n'
            "Resolve references from eligible recent context.\n"
            "</CONVERSATION_CONTEXT_POLICY>\n"
            "<RECENT_CONVERSATION_CONTEXT>\n"
            "[PRIOR USER] mục thứ hai kiểm tra default gateway bằng ip route\n"
            "</RECENT_CONVERSATION_CONTEXT>"
        )
        llm = LLM()
        service = _service(llm, contract, prompt)
        job = SimpleNamespace(
            language="vi",
            message="Cái thứ hai: giải thích trong đúng một câu.",
        )

        service._execute_direct_chat("job", job, "standard")

        self.assertEqual(len(llm.system_prompts), 1)
        system = llm.system_prompts[0]
        self.assertIn("FOLLOW-UP SEMANTIC ANCHOR", system)
        self.assertIn("semantic label or canonical term", system)
        self.assertIn("preserve a short semantic label or canonical term", system)
        self.assertEqual(service._updates[-1][1]["status"], "completed")
        self.assertIn("Cổng mặc định", service._updates[-1][1]["answer"])

    def test_target_language_retry_explicitly_requires_japanese_script(self) -> None:
        class LLM:
            def __init__(self) -> None:
                self.system_prompts = []

            def generate(self, system_prompt, user_prompt, **kwargs):
                del user_prompt, kwargs
                self.system_prompts.append(system_prompt)
                if len(self.system_prompts) == 1:
                    return "I am WorkSpace."
                return "私はWorkSpaceです。"

        contract = ChatOutputContract(
            kind="prose",
            max_chars=600,
            num_predict=128,
            instruction="Answer briefly.",
        )
        prompt = (
            "<CURRENT_USER_REQUEST>\n日本語で簡単に自己紹介してください。\n"
            "</CURRENT_USER_REQUEST>\n"
            '<CONVERSATION_CONTEXT_POLICY mode="standalone">\n'
            "Answer only the current request.\n"
            "</CONVERSATION_CONTEXT_POLICY>"
        )
        llm = LLM()
        service = _service(llm, contract, prompt)
        job = SimpleNamespace(language="ja", message="日本語で簡単に自己紹介してください。")

        service._execute_direct_chat("job", job, "standard")

        self.assertEqual(len(llm.system_prompts), 2)
        self.assertNotIn("TARGET-LANGUAGE REPAIR", llm.system_prompts[0])
        self.assertIn("TARGET-LANGUAGE REPAIR", llm.system_prompts[1])
        self.assertIn("Japanese script", llm.system_prompts[1])
        self.assertEqual(service._updates[-1][1]["status"], "completed")
        self.assertEqual(service._updates[-1][1]["answer"], "私はWorkSpaceです。")


if __name__ == "__main__":
    unittest.main()
