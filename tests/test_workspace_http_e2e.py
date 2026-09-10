from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

from three_agent.chat_gateway import (
    ApprovedAssetHTTPHandler,
    ProgressJob,
    _conversation_title,
    _history_owner_key,
    _parse_request_controls,
)
from three_agent.chat_history import ProjectConversationStore
from three_agent.workspace_auth import WorkspaceAuthStore


class _NoExternalKnowledgeGateway:
    """Deterministic no-upload gateway for loopback HTTP acceptance tests."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def validate_upload_ids(self, values):
        values = list(values or [])
        if values:
            raise AssertionError("HTTP E2E test must not grant upload authority")
        return []


class _DeterministicHTTPChatService:
    """Controlled backend preserving the production HTTP/history contract.

    The acceptance suite intentionally does not call a real LLM or external tool.
    It verifies the browser-facing production handler, account boundary, job poll
    lifecycle and durable conversation recovery without introducing network
    nondeterminism into CI.
    """

    def __init__(self, db_path: Path, upload_root: Path) -> None:
        self.default_language = "ja"
        self.history = ProjectConversationStore(db_path)
        self.history.initialize()
        self.orchestrator = SimpleNamespace(
            config=SimpleNamespace(
                product_name="WorkSpace",
                environment="test",
                confidentiality_mode="confidential",
                internet_gateway=SimpleNamespace(
                    enabled=False,
                    public_search_enabled=False,
                ),
                raw={"github": {"enabled": False}},
            ),
            knowledge_gateway=_NoExternalKnowledgeGateway(upload_root),
        )
        self._lock = threading.RLock()
        self._jobs: dict[str, ProgressJob] = {}
        self._job_conversations: dict[str, str] = {}
        self._persisted_results: set[str] = set()
        self.submit_calls: list[dict[str, object]] = []

    @staticmethod
    def _clone(job: ProgressJob) -> ProgressJob:
        return ProgressJob(**asdict(job))

    def submit(
        self,
        message: str,
        *,
        channel: str,
        sender: str,
        language: str | None = None,
        upload_ids: list[str] | None = None,
        request_mode: str = "chat",
        effort: str = "high",
        conversation_id: str | None = None,
    ) -> ProgressJob:
        if upload_ids:
            raise AssertionError("HTTP E2E test must remain local and upload-free")
        text, chosen_language, output_format = _parse_request_controls(
            message,
            language or self.default_language,
        )
        owner_key = _history_owner_key(channel, sender)
        conversation = self.history.ensure_conversation(
            owner_key,
            conversation_id,
            _conversation_title(text),
        )
        with self._lock:
            job_id = f"http-e2e-{len(self._jobs) + 1:04d}"
            job = ProgressJob(
                job_id=job_id,
                channel=channel,
                sender=sender,
                message=text,
                language=chosen_language,
                output_format=output_format,
                stages=[
                    {
                        "id": "answer",
                        "label": "Deterministic HTTP E2E backend",
                        "status": "queued",
                        "detail": "No external model or network authority",
                    }
                ],
            )
            self._jobs[job_id] = job
            self._job_conversations[job_id] = conversation
            self.submit_calls.append(
                {
                    "message": text,
                    "channel": channel,
                    "sender": sender,
                    "language": chosen_language,
                    "output_format": output_format,
                    "request_mode": request_mode,
                    "effort": effort,
                    "conversation_id": conversation,
                }
            )
        self.history.record_message(
            conversation,
            role="user",
            content=text,
            job_id=job_id,
            status="completed",
        )
        return self._clone(job)

    def _finish_for_poll(self, job: ProgressJob) -> None:
        if job.status not in {"queued", "running"}:
            return
        if "simulate backend failure" in job.message.casefold():
            job.status = "failed"
            job.answer = ""
            job.error = "E2E_BACKEND_FAILURE"
            job.stages[0]["status"] = "failed"
            content = "WorkSpace failed: E2E_BACKEND_FAILURE"
        else:
            job.status = "completed"
            job.answer = f"HTTP E2E completed in {job.language}."
            job.error = None
            job.stages[0]["status"] = "completed"
            content = job.answer
        if job.job_id in self._persisted_results:
            return
        conversation = self._job_conversations[job.job_id]
        self.history.record_message(
            conversation,
            role="assistant",
            content=content,
            job_id=job.job_id,
            status=job.status,
        )
        self._persisted_results.add(job.job_id)

    def get(self, job_id: str) -> ProgressJob | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            self._finish_for_poll(job)
            return self._clone(job)

    def recent(self, limit: int = 20) -> list[ProgressJob]:
        with self._lock:
            jobs = list(self._jobs.values())[-max(1, int(limit)) :]
            return [self._clone(job) for job in reversed(jobs)]

    def conversation_for_job(self, job_id: str) -> str:
        with self._lock:
            return self._job_conversations.get(job_id, "")


class WorkspaceProductionHTTPE2ETests(unittest.TestCase):
    ADMIN_PASSWORD = "0123456789abcdef"
    MEMBER_PASSWORD = "abcdefghijklmnop"

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        db_path = root / "workspace.db"

        auth = WorkspaceAuthStore(db_path)
        auth.initialize()
        auth.bootstrap_admin(
            "admin",
            self.ADMIN_PASSWORD,
            display_name="HTTP E2E Admin",
        )
        self.member = auth.create_user(
            username="http.member",
            password=self.MEMBER_PASSWORD,
            display_name="HTTP E2E Member",
        )

        self.service = _DeterministicHTTPChatService(db_path, root / "uploads")
        app = SimpleNamespace(
            service=self.service,
            sessions=auth,
            artifact_root=root / "artifacts",
            external_settings=SimpleNamespace(
                enabled=False,
                providers=(),
                browser_base_url="",
            ),
        )
        app.artifact_root.mkdir(parents=True, exist_ok=True)

        self.httpd = __import__("http.server", fromlist=["ThreadingHTTPServer"]).ThreadingHTTPServer(
            ("127.0.0.1", 0),
            ApprovedAssetHTTPHandler,
        )
        self.httpd.daemon_threads = True
        self.httpd.app = app
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_server)
        self.host, self.port = self.httpd.server_address

    def _stop_server(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
        *,
        cookie: str = "",
    ) -> tuple[int, dict[str, object] | str, dict[str, str]]:
        connection = http.client.HTTPConnection(self.host, self.port, timeout=3)
        headers: dict[str, str] = {}
        body = None
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if cookie:
            headers["Cookie"] = cookie
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        response_headers = {key: value for key, value in response.getheaders()}
        status = response.status
        content_type = response_headers.get("Content-Type", "")
        connection.close()
        if "application/json" in content_type:
            return status, json.loads(raw.decode("utf-8")), response_headers
        return status, raw.decode("utf-8"), response_headers

    def _login(self, username: str, password: str) -> str:
        status, payload, headers = self._request(
            "POST",
            "/api/login",
            {"username": username, "password": password},
        )
        self.assertEqual(status, 200, payload)
        self.assertIsInstance(payload, dict)
        set_cookie = headers.get("Set-Cookie", "")
        self.assertIn("three_agent_session=", set_cookie)
        return set_cookie.split(";", 1)[0]

    def _submit_chat(
        self,
        cookie: str,
        message: str,
        *,
        conversation_id: str = "",
    ) -> dict[str, object]:
        status, payload, _ = self._request(
            "POST",
            "/api/chat",
            {
                "message": message,
                "language": "vi",
                "format": "source",
                "mode": "chat",
                "effort": "standard",
                "upload_ids": [],
                "conversation_id": conversation_id,
            },
            cookie=cookie,
        )
        self.assertEqual(status, 202, payload)
        self.assertIsInstance(payload, dict)
        return payload

    def test_frontend_auth_chat_poll_and_reconnect_use_the_production_http_handler(self) -> None:
        status, html, _ = self._request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIsInstance(html, str)
        for marker in (
            "/api/chat",
            "/api/jobs/",
            "/api/conversations/",
            "conversation_id",
            "credentials:'same-origin'",
        ):
            self.assertIn(marker, html)

        status, payload, _ = self._request("GET", "/api/session")
        self.assertEqual(status, 401)
        self.assertEqual(payload.get("error"), "Authentication required")

        status, payload, _ = self._request(
            "POST",
            "/api/chat",
            {"message": "unauthorized"},
        )
        self.assertEqual(status, 401)
        self.assertEqual(payload.get("error"), "Authentication required")
        self.assertEqual(self.service.submit_calls, [])

        admin_cookie = self._login("admin", self.ADMIN_PASSWORD)
        status, session, _ = self._request("GET", "/api/session", cookie=admin_cookie)
        self.assertEqual(status, 200, session)
        self.assertEqual(session.get("role"), "admin")
        self.assertEqual(session.get("account_scope"), "local_account")

        accepted = self._submit_chat(
            admin_cookie,
            "Kiểm tra vòng đời HTTP của WorkSpace.",
        )
        job_id = str(accepted["job_id"])
        conversation_id = str(accepted["conversation_id"])
        self.assertTrue(job_id)
        self.assertTrue(conversation_id)
        self.assertEqual(accepted["status"], "queued")

        status, completed, _ = self._request(
            "GET",
            f"/api/jobs/{job_id}",
            cookie=admin_cookie,
        )
        self.assertEqual(status, 200, completed)
        self.assertEqual(completed["status"], "completed")
        self.assertIn("HTTP E2E completed", str(completed["answer"]))

        status, conversation, _ = self._request(
            "GET",
            f"/api/conversations/{conversation_id}",
            cookie=admin_cookie,
        )
        self.assertEqual(status, 200, conversation)
        self.assertEqual(len(conversation["messages"]), 2)
        self.assertEqual(
            [item["role"] for item in conversation["messages"]],
            ["user", "assistant"],
        )

        # Every helper call opens a fresh TCP connection. Reusing only the session
        # cookie therefore proves browser-style reconnect/reload recovery.
        status, recovered, _ = self._request(
            "GET",
            f"/api/conversations/{conversation_id}",
            cookie=admin_cookie,
        )
        self.assertEqual(status, 200, recovered)
        self.assertEqual(recovered["conversation_id"], conversation_id)

        follow_up = self._submit_chat(
            admin_cookie,
            "tiếp theo ?",
            conversation_id=conversation_id,
        )
        self.assertEqual(follow_up["conversation_id"], conversation_id)
        status, _, _ = self._request(
            "GET",
            f"/api/jobs/{follow_up['job_id']}",
            cookie=admin_cookie,
        )
        self.assertEqual(status, 200)
        status, conversation, _ = self._request(
            "GET",
            f"/api/conversations/{conversation_id}",
            cookie=admin_cookie,
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(conversation["messages"]), 4)
        self.assertEqual(conversation["messages"][2]["content"], "tiếp theo ?")

    def test_job_and_conversation_reads_fail_closed_across_accounts(self) -> None:
        admin_cookie = self._login("admin", self.ADMIN_PASSWORD)
        member_cookie = self._login("http.member", self.MEMBER_PASSWORD)

        accepted = self._submit_chat(admin_cookie, "Kiểm tra ownership boundary.")
        job_id = str(accepted["job_id"])
        conversation_id = str(accepted["conversation_id"])

        status, _, _ = self._request(
            "GET",
            f"/api/jobs/{job_id}",
            cookie=admin_cookie,
        )
        self.assertEqual(status, 200)

        status, payload, _ = self._request(
            "GET",
            f"/api/jobs/{job_id}",
            cookie=member_cookie,
        )
        self.assertEqual(status, 404)
        self.assertEqual(payload.get("error"), "Unknown job")

        status, payload, _ = self._request(
            "GET",
            f"/api/conversations/{conversation_id}",
            cookie=member_cookie,
        )
        self.assertEqual(status, 404)
        self.assertEqual(payload.get("error"), "Conversation not found")

    def test_failed_job_is_terminal_and_recoverable_from_conversation_history(self) -> None:
        admin_cookie = self._login("admin", self.ADMIN_PASSWORD)
        accepted = self._submit_chat(
            admin_cookie,
            "simulate backend failure",
        )
        job_id = str(accepted["job_id"])
        conversation_id = str(accepted["conversation_id"])

        status, failed, _ = self._request(
            "GET",
            f"/api/jobs/{job_id}",
            cookie=admin_cookie,
        )
        self.assertEqual(status, 200, failed)
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["error"], "E2E_BACKEND_FAILURE")

        status, conversation, _ = self._request(
            "GET",
            f"/api/conversations/{conversation_id}",
            cookie=admin_cookie,
        )
        self.assertEqual(status, 200, conversation)
        self.assertEqual(conversation["messages"][-1]["status"], "failed")
        self.assertIn(
            "WorkSpace failed: E2E_BACKEND_FAILURE",
            conversation["messages"][-1]["content"],
        )

        # Invalid options must be rejected before the service receives a new job.
        before = len(self.service.submit_calls)
        status, payload, _ = self._request(
            "POST",
            "/api/chat",
            {
                "message": "bad option",
                "language": "vi",
                "format": "source",
                "mode": "invented_mode",
                "effort": "standard",
                "upload_ids": [],
            },
            cookie=admin_cookie,
        )
        self.assertEqual(status, 400)
        self.assertIn("Unsupported WorkSpace request mode", str(payload.get("error")))
        self.assertEqual(len(self.service.submit_calls), before)


if __name__ == "__main__":
    unittest.main()
