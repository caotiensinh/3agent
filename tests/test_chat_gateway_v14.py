from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from three_agent.chat_gateway_v14 import IntentAwareProjectChatService


class FakeKnowledgeGateway:
    def validate_upload_ids(self, upload_ids):
        return list(dict.fromkeys(str(item) for item in upload_ids))

    def load_upload_sources(self, upload_ids, *, max_sources=8):
        del upload_ids, max_sources
        return [], []


class FakeStore:
    def __init__(self):
        self.activities = []

    def record_activity(self, task_id, agent_id, action, status, details=""):
        self.activities.append((task_id, agent_id, action, status, details))


class FakeLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def generate(self, system_prompt, user_prompt, **kwargs):
        self.calls.append((system_prompt, user_prompt, kwargs))
        if not self.responses:
            raise AssertionError("unexpected extra model call")
        return self.responses.pop(0)


class DirectChatGatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "workspace.db"
        self.services = []

    def tearDown(self):
        # Terminal job status may become visible just before the background worker
        # finishes owner-scoped history persistence. Wait for the actual worker
        # lifecycle instead of racing Windows file locking during temp cleanup.
        for service in self.services:
            service._queue.join()
        self.temp.cleanup()

    def _service(self, responses):
        orchestrator = SimpleNamespace(
            config=SimpleNamespace(database_path=self.db),
            knowledge_gateway=FakeKnowledgeGateway(),
            store=FakeStore(),
            llm=FakeLLM(responses),
        )
        service = IntentAwareProjectChatService(orchestrator, default_language="ja")
        service.start()
        self.services.append(service)
        return service, orchestrator

    @staticmethod
    def _wait(service, job_id):
        deadline = time.time() + 3
        current = service.get(job_id)
        while current and current.status in {"queued", "running"} and time.time() < deadline:
            time.sleep(0.02)
            current = service.get(job_id)
        return current

    def test_normal_chat_does_not_enter_research_workflow(self):
        service, orchestrator = self._service(
            ["Dịch vụ bị lỗi vì cấu hình gateway chưa đúng. Hãy kiểm tra tuyến mạng và DNS."]
        )
        job = service.submit(
            "Hãy trả lời bằng tiếng Việt. Vì sao dịch vụ mạng này bị lỗi?",
            channel="web",
            sender="workspace-user:usr_1234567890abcdef",
            language="ja",
            request_mode="chat",
            effort="standard",
        )
        current = self._wait(service, job.job_id)
        self.assertIsNotNone(current)
        self.assertEqual(current.status, "completed")
        self.assertEqual(current.language, "vi")
        self.assertEqual(len(current.stages), 1)
        self.assertEqual(current.stages[0]["id"], "answer")
        self.assertNotIn("Research", current.answer)
        self.assertEqual(len(orchestrator.llm.calls), 1)
        self.assertFalse(hasattr(orchestrator, "workflow"))
        self.assertTrue(any(row[2] == "direct_chat_completed" for row in orchestrator.store.activities))

    def test_wrong_language_is_retried_once_then_english_is_returned(self):
        service, orchestrator = self._service([
            "このサービスはネットワーク設定の問題で失敗しています。",
            "The service is failing because the network route is missing. Check the gateway and DNS configuration.",
        ])
        job = service.submit(
            "Please reply in English. Why is this service failing?",
            channel="web",
            sender="workspace-user:usr_1234567890abcdef",
            language="ja",
            request_mode="chat",
            effort="high",
        )
        current = self._wait(service, job.job_id)
        self.assertEqual(current.status, "completed")
        self.assertEqual(current.language, "en")
        self.assertTrue(current.answer.startswith("The service"))
        self.assertEqual(len(orchestrator.llm.calls), 2)
        self.assertIn("previous attempt failed", orchestrator.llm.calls[1][0].lower())

    def test_two_wrong_language_attempts_fail_closed(self):
        service, orchestrator = self._service([
            "この回答は日本語です。設定を確認してください。",
            "二回目の回答も日本語です。設定を確認してください。",
        ])
        job = service.submit(
            "Answer in English. Explain the failure.",
            channel="web",
            sender="workspace-user:usr_1234567890abcdef",
            language="auto",
            request_mode="chat",
            effort="standard",
        )
        current = self._wait(service, job.job_id)
        self.assertEqual(current.status, "failed")
        self.assertEqual(current.answer, "")
        self.assertIn("target_language_mismatch", current.error)
        self.assertEqual(len(orchestrator.llm.calls), 2)

    def test_multiline_current_request_reaches_model_without_whitespace_flattening(self):
        service, orchestrator = self._service([
            "The two commands test the interface address and then test external IP connectivity."
        ])
        message = "Please answer in English. Explain:\n```bash\nip addr\nping -c 2 1.1.1.1\n```"
        job = service.submit(
            message,
            channel="web",
            sender="workspace-user:usr_1234567890abcdef",
            language="auto",
            request_mode="chat",
            effort="standard",
        )
        current = self._wait(service, job.job_id)
        self.assertEqual(current.status, "completed")
        self.assertIn("```bash\nip addr\nping -c 2 1.1.1.1\n```", orchestrator.llm.calls[0][1])


if __name__ == "__main__":
    unittest.main()
