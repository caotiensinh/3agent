from __future__ import annotations

import inspect
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

from three_agent.chat_context import (
    CONTEXT_MODE_FOLLOW_UP,
    ConversationContextPlan,
)
from three_agent.chat_gateway_v14 import IntentAwareProjectChatService
from three_agent.chat_gateway_v15 import WorkflowV3Application, WorkflowV3HTTPHandler
from three_agent.chat_gateway_v16 import (
    CONVERSATION_CONTEXT_POLICY_VERSION,
    ContextAwareProjectChatService,
    ContextAwareWorkflowV3HTTPHandler,
)
from three_agent.version import PACKAGE_VERSION


class ChatGatewayV16ContractTests(unittest.TestCase):
    def test_v16_preserves_workflow_v3_and_direct_chat_inheritance(self) -> None:
        self.assertTrue(
            issubclass(ContextAwareProjectChatService, IntentAwareProjectChatService)
        )
        self.assertTrue(
            issubclass(ContextAwareWorkflowV3HTTPHandler, WorkflowV3HTTPHandler)
        )
        self.assertEqual(
            ContextAwareWorkflowV3HTTPHandler.server_version,
            "WorkSpaceChat/0.17",
        )
        self.assertIs(
            ContextAwareWorkflowV3HTTPHandler.do_POST,
            WorkflowV3HTTPHandler.do_POST,
        )
        self.assertTrue(callable(WorkflowV3Application))
        for method_name in (
            "_prepare_dispatch",
            "_execute_dispatch",
            "_checkpoint",
            "_workflow_state",
        ):
            self.assertTrue(
                callable(getattr(ContextAwareWorkflowV3HTTPHandler, method_name))
            )

    def test_health_preserves_workflow_v3_contract_and_adds_context_contract(self) -> None:
        source = inspect.getsource(ContextAwareWorkflowV3HTTPHandler.do_GET)
        for token in (
            '"workflow_execution_version": "v3"',
            '"workflow_execution_profile": EXECUTION_PROFILE',
            '"workflow_execution_risk": "low_only"',
            '"workflow_execution_trigger": "manual_only"',
            '"workflow_pause_resume": True',
            '"workflow_persistent_checkpoint": True',
            '"workflow_branching": "deterministic_only"',
            '"workflow_failure_rejection_terminal": True',
            '"workflow_branch_joins": False',
            '"prompt_compiler": PROMPT_COMPILER_VERSION',
            '"public_query_compiler": PUBLIC_QUERY_COMPILER_VERSION',
            '"direct_chat": True',
            '"direct_chat_public_web": False',
            '"response_language_current_request_precedence": True',
            '"conversation_context_policy": CONVERSATION_CONTEXT_POLICY_VERSION',
            '"conversation_context_reference_gated": True',
            '"conversation_context_completed_only": True',
            '"standalone_request_history_injected": False',
            '"follow_up_language_continuity": True',
            '"follow_up_reference_anchoring": True',
        ):
            self.assertIn(token, source)

    def test_context_policy_is_versioned(self) -> None:
        self.assertEqual(CONTEXT_MODE_FOLLOW_UP, "follow_up")
        self.assertEqual(
            CONVERSATION_CONTEXT_POLICY_VERSION,
            "deterministic-reference-gated/v2",
        )

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

    def test_v16_and_v18_remain_rollback_layers_while_entrypoint_advances_to_v19(self) -> None:
        root = Path(__file__).resolve().parents[1]
        pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn(f'version = "{PACKAGE_VERSION}"', pyproject)
        self.assertIn('workspace-chat = "three_agent.chat_gateway_v19:main"', pyproject)
        self.assertIn('three-agent-chat = "three_agent.chat_gateway_v19:main"', pyproject)
        self.assertIn(
            'workspace-chat-acceptance = "three_agent.chat_acceptance:main"',
            pyproject,
        )
        self.assertIn(
            'workspace-chat-multiturn-acceptance = "three_agent.chat_multiturn_acceptance_v2:main"',
            pyproject,
        )
        self.assertTrue((root / "src/three_agent/chat_gateway_v17.py").is_file())
        self.assertTrue((root / "src/three_agent/chat_gateway_v18.py").is_file())
        self.assertTrue((root / "src/three_agent/chat_gateway_v19.py").is_file())

    def test_v15_remains_workflow_v3_rollback_boundary(self) -> None:
        self.assertEqual(WorkflowV3HTTPHandler.server_version, "WorkSpaceChat/0.16")
        self.assertTrue(callable(WorkflowV3HTTPHandler._checkpoint))
        self.assertTrue(callable(WorkflowV3HTTPHandler._execute_dispatch))


if __name__ == "__main__":
    unittest.main()
