from __future__ import annotations

import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

from three_agent.chat_context import (
    CONTEXT_MODE_FOLLOW_UP,
    ConversationContextPlan,
)
from three_agent.chat_gateway_v14 import (
    IntentAwareProjectChatService,
    IntentAwareWorkflowDispatchHTTPHandler,
)
from three_agent.chat_gateway_v15 import (
    CONVERSATION_CONTEXT_POLICY_VERSION,
    ContextAwareProjectChatService,
    ContextAwareWorkflowDispatchHTTPHandler,
)


class ChatGatewayV15ContractTests(unittest.TestCase):
    def test_v14_security_and_workflow_chain_is_preserved(self) -> None:
        self.assertTrue(issubclass(ContextAwareProjectChatService, IntentAwareProjectChatService))
        self.assertTrue(
            issubclass(ContextAwareWorkflowDispatchHTTPHandler, IntentAwareWorkflowDispatchHTTPHandler)
        )
        self.assertEqual(ContextAwareWorkflowDispatchHTTPHandler.server_version, "WorkSpaceChat/0.16")
        self.assertTrue(callable(ContextAwareWorkflowDispatchHTTPHandler._execute_dispatch))

    def test_context_policy_is_reference_gated_and_versioned(self) -> None:
        self.assertEqual(CONTEXT_MODE_FOLLOW_UP, "follow_up")
        self.assertEqual(CONVERSATION_CONTEXT_POLICY_VERSION, "deterministic-reference-gated/v1")
        names = ContextAwareProjectChatService._direct_prompt.__code__.co_names
        self.assertIn("_context_plan", names)
        self.assertIn("_upload_context", names)

    def test_missing_follow_up_context_is_rendered_as_unavailable_not_invented(self) -> None:
        service = object.__new__(ContextAwareProjectChatService)
        service._lock = threading.RLock()
        service._job_context_plans = {}
        service._context_plan = lambda job: ConversationContextPlan(
            mode=CONTEXT_MODE_FOLLOW_UP,
            reason="test",
            text="",
            message_count=0,
            source_chars=0,
            language_hint="vi",
        )
        service._upload_context = lambda upload_ids: ""
        prompt = service._direct_prompt(
            SimpleNamespace(job_id="job-test", message="tiếp theo ?"),
            [],
        )
        self.assertIn('available="false"', prompt)
        self.assertIn("Do not invent the missing referenced content", prompt)
        self.assertNotIn("[PRIOR USER]", prompt)

    def test_short_follow_up_cue_keeps_language_even_without_conversation_id(self) -> None:
        service = object.__new__(ContextAwareProjectChatService)
        service.default_language = "ja"
        language = service._language_for_follow_up(
            "tiếp theo ?",
            channel="web",
            sender="workspace-user:test",
            language="auto",
            conversation_id=None,
        )
        self.assertEqual(language, "vi")

    def test_package_entrypoints_use_gateway_v15(self) -> None:
        pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(
            encoding="utf-8"
        )
        self.assertIn('version = "0.16.0"', pyproject)
        self.assertIn('workspace-chat = "three_agent.chat_gateway_v15:main"', pyproject)
        self.assertIn('three-agent-chat = "three_agent.chat_gateway_v15:main"', pyproject)
        self.assertIn('workspace-chat-acceptance = "three_agent.chat_acceptance:main"', pyproject)

    def test_v14_remains_importable_as_rollback_boundary(self) -> None:
        self.assertEqual(IntentAwareWorkflowDispatchHTTPHandler.server_version, "WorkSpaceChat/0.15")
        self.assertTrue(callable(IntentAwareProjectChatService._execute_direct_chat))


if __name__ == "__main__":
    unittest.main()
