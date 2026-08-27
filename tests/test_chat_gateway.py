import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from three_agent.chat_gateway import (
    ChatService,
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
        bridge = TelegramBridge(Service(), gateway, "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi", {42})
        bridge.handle_update({"message": {"text": "hello", "from": {"id": 7}, "chat": {"id": 7}}})
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


if __name__ == "__main__":
    unittest.main()
