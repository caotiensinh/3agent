from __future__ import annotations

import inspect
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from three_agent import chat_gateway
from three_agent.chat_context import CONTEXT_MODE_FOLLOW_UP, ConversationContextPlan
from three_agent.chat_gateway import (
    CONVERSATION_CONTEXT_POLICY_VERSION,
    MAX_UPLOAD_REQUEST_BYTES,
    ChatService,
    ContextAwareProjectChatService,
    ContinuitySecurityAwareProjectChatService,
    SecurityE2EApplication,
    SecurityE2EHTTPHandler,
    SessionStore,
    TelegramBridge,
    _parse_allowed_ids,
    _parse_request_controls,
    _recent_uploads,
    _request_purpose,
    _private_client,
    _validate_owned_uploads,
    _validate_request_options,
    workspace_ui_capabilities,
)
from three_agent.knowledge_gateway import (
    MAX_UPLOAD_BYTES,
    MAX_UPLOADS_PER_TASK,
    UPLOAD_EXTENSIONS,
    UploadSecurityError,
)
from three_agent.privacy import redact_sensitive_text
from three_agent.workspace_frontend import WORKSPACE_HTML


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


def workspace_config(*, public_search: bool, mode: str) -> SimpleNamespace:
    return SimpleNamespace(
        product_name="WorkSpace",
        environment="public-research-zone" if mode == "public-research" else "secure-local",
        confidentiality_mode=mode,
        internet_gateway=SimpleNamespace(
            enabled=True,
            public_search_enabled=public_search,
        ),
        raw={"github": {"enabled": False, "push_mode": "operator_only"}},
    )


class StubUploadGateway:
    def __init__(self, root: Path) -> None:
        self.root = root

    def validate_upload_ids(self, values):
        result = []
        for value in values:
            value = str(value)
            if not (self.root / value / "manifest.json").is_file():
                raise UploadSecurityError(f"Unknown upload_id: {value}")
            if value not in result:
                result.append(value)
        return result


def write_upload_manifest(
    root: Path,
    upload_id: str,
    *,
    sender: str,
    name: str = "notes.txt",
    documents: int = 1,
    images: int = 0,
) -> None:
    folder = root / upload_id
    folder.mkdir(parents=True)
    (folder / "original.txt").write_text("safe", encoding="utf-8")
    payload = {
        "schema_version": 1,
        "upload_id": upload_id,
        "name": name,
        "size": 4,
        "sha256": "sha256:" + "a" * 64,
        "sender": sender,
        "documents": [
            {"name": f"doc-{index}.txt", "kind": "text", "text_file": "doc.txt", "chars": 4}
            for index in range(documents)
        ],
        "images": [
            {"name": f"image-{index}.png", "kind": "image", "width": 1, "height": 1}
            for index in range(images)
        ],
        "warnings": ["metadata-only warning"],
    }
    (folder / "manifest.json").write_text(
        json.dumps(payload),
        encoding="utf-8",
    )


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

    def test_workspace_composer_and_server_upload_contract_are_present(self):
        for value in (
            'id="plusBtn"',
            'id="micBtn"',
            'id="sendBtn"',
            'placeholder="Ask WorkSpace"',
            'data-action="upload"',
            'data-action="library"',
            'data-action="web_search"',
            'data-action="deep_research"',
            'data-action="image_generation"',
            'data-action="github"',
            "/api/upload",
            "/api/uploads",
            "/api/capabilities",
            "/api/chat",
            "upload_ids",
            "mode:state.requestMode",
            "effort:document.getElementById('effort').value",
        ):
            self.assertIn(value, WORKSPACE_HTML)
        self.assertNotIn("Ask 3Agent", WORKSPACE_HTML)
        self.assertNotIn("SpeechRecognition", WORKSPACE_HTML)
        self.assertNotIn("webkitSpeechRecognition", WORKSPACE_HTML)
        self.assertEqual(
            UPLOAD_EXTENSIONS,
            {
                ".txt",
                ".md",
                ".markdown",
                ".html",
                ".htm",
                ".zip",
                ".png",
                ".jpg",
                ".jpeg",
                ".webp",
            },
        )
        self.assertLess(MAX_UPLOAD_BYTES, MAX_UPLOAD_REQUEST_BYTES)
        self.assertEqual(MAX_UPLOADS_PER_TASK, 8)

    def test_capability_manifest_fails_closed_for_external_or_unconfigured_features(self):
        secure = workspace_ui_capabilities(
            workspace_config(public_search=False, mode="confidential")
        )
        self.assertEqual(secure["product_name"], "WorkSpace")
        self.assertTrue(secure["features"]["upload"]["enabled"])
        self.assertTrue(secure["features"]["library"]["enabled"])
        self.assertTrue(secure["features"]["deep_research"]["enabled"])
        self.assertFalse(secure["features"]["web_search"]["enabled"])
        self.assertFalse(secure["features"]["image_generation"]["enabled"])
        self.assertFalse(secure["features"]["voice_input"]["enabled"])
        self.assertFalse(secure["features"]["github"]["enabled"])

        public = workspace_ui_capabilities(
            workspace_config(public_search=True, mode="public-research")
        )
        self.assertTrue(public["features"]["web_search"]["enabled"])

    def test_request_mode_and_effort_are_real_server_side_controls(self):
        secure = workspace_config(public_search=False, mode="confidential")
        self.assertEqual(
            _validate_request_options("deep_research", "high", secure),
            ("deep_research", "high"),
        )
        with self.assertRaisesRegex(ValueError, "Web search is disabled"):
            _validate_request_options("web_search", "high", secure)
        with self.assertRaisesRegex(ValueError, "Unsupported WorkSpace request mode"):
            _validate_request_options("invented", "high", secure)
        with self.assertRaisesRegex(ValueError, "Unsupported WorkSpace effort"):
            _validate_request_options("chat", "unbounded", secure)

        public = workspace_config(public_search=True, mode="public-research")
        self.assertEqual(
            _validate_request_options("web_search", "standard", public),
            ("web_search", "standard"),
        )
        self.assertNotEqual(
            _request_purpose("chat", "standard"),
            _request_purpose("deep_research", "high"),
        )
        self.assertIn("deterministic budgets", _request_purpose("deep_research", "high"))

    def test_library_is_metadata_only_and_scoped_to_same_lan_client(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            own_id = "a" * 16
            foreign_id = "b" * 16
            write_upload_manifest(root, own_id, sender="192.168.11.20")
            write_upload_manifest(root, foreign_id, sender="192.168.11.21", name="foreign.txt")
            gateway = StubUploadGateway(root)

            rows = _recent_uploads(gateway, "192.168.11.20")
            self.assertEqual([row["upload_id"] for row in rows], [own_id])
            self.assertNotIn("sender", rows[0])
            self.assertNotIn("path", rows[0])
            self.assertNotIn("documents", rows[0])
            self.assertNotIn("images", rows[0])

            self.assertEqual(
                _validate_owned_uploads(gateway, [own_id], "192.168.11.20"),
                [own_id],
            )
            with self.assertRaisesRegex(UploadSecurityError, "not owned"):
                _validate_owned_uploads(
                    gateway,
                    [foreign_id],
                    "192.168.11.20",
                )

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
