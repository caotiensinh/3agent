from __future__ import annotations

import inspect
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from three_agent import chat_gateway
from three_agent.chat_context import CONTEXT_MODE_FOLLOW_UP, ConversationContextPlan
from three_agent.chat_gateway import (
    CONVERSATION_CONTEXT_POLICY_VERSION,
    ChatService,
    ContextAwareProjectChatService,
    ContinuitySecurityAwareProjectChatService,
    SecurityE2EApplication,
    SecurityE2EHTTPHandler,
    SessionStore,
    TelegramBridge,
    _parse_allowed_ids,
    _parse_request_controls,
    _private_client,
)
from three_agent.privacy import redact_sensitive_text


class FakeWorkflowResult:
    status = "completed"
    task_id = "TASK-TEST-0001"
    research_artifacts = []
    presentation_artifacts = []
    daily_report_artifacts = []
    error = None


class FakeOrchestrator:
    def run_workflow(self, **kwargs):
        self.kwargs = kwargs
        return FakeWorkflowResult()


class FakeGateway:
    def __init__(self):
        self.calls = []

    def post_json(self, agent_id, task_id, url, payload, timeout=30):
        self.calls.append((agent_id, task_id, url, payload, timeout))
        if url.endswith("/sendMessage"):
            return b'{"ok":true,"result":{}}'
        return b'{"ok":true,"result":[]}'


class ChatGatewayTests(unittest.TestCase):
    def test_private_client_gate(self):
        self.assertTrue(_private_client("192.168.11.20"))
        self.assertTrue(_private_client("127.0.0.1"))
        self.assertFalse(_private_client("8.8.8.8"))

    def test_request_controls(self):
        text, lang, fmt = _parse_request_controls("/vi /pptx nghien cuu camera", "ja")
        self.assertEqual(text, "nghien cuu camera")
        self.assertEqual(lang, "vi")
        self.assertEqual(fmt, "pptx")

    def test_session_is_ip_bound(self):
        store = SessionStore("a" * 32)
        session = store.login("a" * 32, "192.168.1.2")
        self.assertIsNotNone(session)
        self.assertTrue(store.valid(session or "", "192.168.1.2"))
        self.assertFalse(store.valid(session or "", "192.168.1.3"))

    def test_telegram_allow_list_parser(self):
        self.assertEqual(_parse_allowed_ids("123, 456;789"), {123, 456, 789})

    def test_telegram_token_redaction(self):
        token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"
        redacted = redact_sensitive_text(f"https://api.telegram.org/bot{token}/getUpdates")
        self.assertNotIn(token, redacted)
        self.assertIn("REDACTED_TELEGRAM_BOT_TOKEN", redacted)

    def test_telegram_rejects_unlisted_user_without_submitting(self):
        class Service:
            def submit(self, *args, **kwargs):
                raise AssertionError("unauthorized user must not submit")

        gateway = FakeGateway()
        bridge = TelegramBridge(
            Service(),
            gateway,
            "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi",
            {42},
        )
        bridge.handle_update(
            {"message": {"text": "hello", "from": {"id": 7}, "chat": {"id": 7}}}
        )
        self.assertTrue(gateway.calls)
        self.assertIn("Not authorized", gateway.calls[-1][3]["text"])

    def test_chat_service_runs_one_workflow(self):
        fake = FakeOrchestrator()
        service = ChatService(fake, default_language="ja")
        service.start()
        job = service.submit("/en test request", channel="web", sender="192.168.1.2")
        deadline = time.time() + 2
        current = service.get(job.job_id)
        while current and current.status in {"queued", "running"} and time.time() < deadline:
            time.sleep(0.02)
            current = service.get(job.job_id)
        self.assertIsNotNone(current)
        self.assertEqual(current.status, "completed")
        self.assertEqual(fake.kwargs["language"], "en")
        self.assertEqual(fake.kwargs["output_format"], "source")

    def test_workspace_identity_remains_stable_for_context_ownership(self):
        service = ChatService(FakeOrchestrator(), default_language="ja")
        sender = "workspace-user:usr_context_owner"
        job = service.submit("hello", channel="web", sender=sender)
        self.assertEqual(job.sender, sender)

    def test_canonical_context_policy(self):
        self.assertEqual(CONTEXT_MODE_FOLLOW_UP, "follow_up")
        self.assertEqual(
            CONVERSATION_CONTEXT_POLICY_VERSION,
            "bounded-conversation-continuity/v3",
        )

    def test_missing_follow_up_context_is_explicitly_unavailable(self):
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

    def test_short_follow_up_cue_keeps_language(self):
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

    def test_final_health_surface_exposes_current_context_and_security_contracts(self):
        source = "\n".join(
            inspect.getsource(base.__dict__["do_GET"])
            for base in SecurityE2EHTTPHandler.__mro__
            if "do_GET" in base.__dict__
        )
        self.assertIn("conversation_context_policy", source)
        self.assertIn("CONVERSATION_CONTEXT_POLICY_VERSION", source)
        self.assertIn("public_query_final_dlp", source)
        self.assertIn("workflow_execution", source)

    def test_canonical_main_uses_final_service_and_application(self):
        source = inspect.getsource(chat_gateway.main)
        self.assertIn("ContinuitySecurityAwareProjectChatService", source)
        self.assertIn("SecurityE2EApplication", source)
        self.assertNotIn("chat_gateway_v", source)
        self.assertTrue(callable(ContinuitySecurityAwareProjectChatService))
        self.assertTrue(callable(SecurityE2EApplication))

    def test_console_entrypoints_reference_only_canonical_chat_modules(self):
        pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(
            encoding="utf-8"
        )
        self.assertIn('workspace-chat = "three_agent.chat_gateway:main"', pyproject)
        self.assertIn('three-agent-chat = "three_agent.chat_gateway:main"', pyproject)
        self.assertIn(
            'workspace-chat-acceptance = "three_agent.chat_acceptance:main"',
            pyproject,
        )
        self.assertIn(
            'workspace-chat-multiturn-acceptance = "three_agent.chat_multiturn_acceptance:main"',
            pyproject,
        )


if __name__ == "__main__":
    unittest.main()
