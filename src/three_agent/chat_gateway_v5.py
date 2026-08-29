from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from dataclasses import asdict
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .chat_gateway import (
    SessionStore,
    TelegramBridge,
    _lan_hint,
    _parse_allowed_ids,
    _parse_request_controls,
)
from .chat_gateway_v2 import ProgressApplication, ProgressJob
from .chat_gateway_v4 import (
    KnowledgeChatService,
    KnowledgeHTTPHandler,
    _validate_owned_uploads,
    _validate_request_options,
)
from .chat_history import ChatHistoryStore
from .config import load_config
from .knowledge_gateway import MAX_UPLOADS_PER_TASK, UploadSecurityError
from .orchestrator import Orchestrator
from .privacy import redact_sensitive_text
from .workspace_frontend_v2 import WORKSPACE_HTML_V2

HTML_V5 = WORKSPACE_HTML_V2


def _history_owner_key(channel: str, sender: str) -> str:
    """Create a pseudonymous local owner key without persisting a LAN address."""

    raw = f"{str(channel or '').strip().lower()}:{str(sender or '').strip()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _conversation_title(message: str) -> str:
    text = " ".join(str(message or "").split()).strip()
    return (text or "New chat")[:96]


class SidebarKnowledgeChatService(KnowledgeChatService):
    """Knowledge chat service with persistent owner-scoped conversation history."""

    def __init__(self, orchestrator: Any, default_language: str = "ja") -> None:
        super().__init__(orchestrator, default_language=default_language)
        self.history = ChatHistoryStore(orchestrator.config.database_path)
        self.history.initialize()
        self._job_conversations: dict[str, str] = {}

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
        text, chosen_language, output_format = _parse_request_controls(
            message,
            language or self.default_language,
        )
        validated_uploads = self.orchestrator.knowledge_gateway.validate_upload_ids(
            upload_ids or []
        )
        mode, effort_level = _validate_request_options(
            request_mode,
            effort,
            self.orchestrator.config,
        )
        owner_key = _history_owner_key(channel, sender)
        conversation = self.history.ensure_conversation(
            owner_key,
            conversation_id,
            _conversation_title(text),
        )
        job = ProgressJob(
            job_id=uuid.uuid4().hex[:16],
            channel=channel,
            sender=redact_sensitive_text(sender)[:120],
            message=text,
            language=chosen_language,
            output_format=output_format,
        )
        job.stages = [
            {"id": "research", "label": "Research", "status": "queued", "detail": ""},
            {
                "id": "presentation",
                "label": "Presentation",
                "status": "queued",
                "detail": "",
            },
            {
                "id": "daily_report",
                "label": "Human Report",
                "status": "queued",
                "detail": "",
            },
        ]
        self.history.record_message(
            conversation,
            role="user",
            content=text,
            job_id=job.job_id,
            status="completed",
        )
        with self._lock:
            self._jobs[job.job_id] = job
            self._job_uploads[job.job_id] = validated_uploads
            self._job_options[job.job_id] = (mode, effort_level)
            self._job_conversations[job.job_id] = conversation
        self._queue.put(job.job_id)
        return ProgressJob(**asdict(job))

    def conversation_for_job(self, job_id: str) -> str:
        with self._lock:
            return str(self._job_conversations.get(job_id) or "")

    def _execute(self, job_id: str) -> None:
        super()._execute(job_id)
        job = self.get(job_id)
        if job is None:
            return
        with self._lock:
            conversation_id = self._job_conversations.get(job_id)
        if not conversation_id:
            return
        try:
            if job.task_id:
                self.history.link_task(conversation_id, job_id, job.task_id)
            if job.status in {"queued", "running"}:
                return
            if job.answer:
                content = job.answer
            elif job.error:
                content = f"WorkSpace failed: {job.error}"
            else:
                content = str(job.status or "completed")
            self.history.record_message(
                conversation_id,
                role="assistant",
                content=content,
                job_id=job_id,
                task_id=job.task_id or "",
                status=job.status,
            )
        except Exception as exc:
            if job.task_id:
                try:
                    self.orchestrator.store.record_activity(
                        job.task_id,
                        "chat_history",
                        "history_persist_failed",
                        "warning",
                        redact_sensitive_text(f"{type(exc).__name__}: {exc}")[:500],
                    )
                except Exception:
                    pass


class SidebarKnowledgeHTTPHandler(KnowledgeHTTPHandler):
    server_version = "WorkSpaceChat/0.6"

    def _owner_key(self) -> str:
        return _history_owner_key("web", self.client_address[0])

    def _authorized_local(self) -> bool:
        if not self._private_or_reject():
            return False
        if not self._authorized():
            self._json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "Authentication required"},
            )
            return False
        return True

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/":
            if not self._private_or_reject():
                return
            body = HTML_V5.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/api/health":
            if not self._private_or_reject():
                return
            self._json(
                HTTPStatus.OK,
                {"status": "ok", "service": "WorkSpace Chat", "version": "0.6"},
            )
            return
        if path == "/api/session":
            if not self._authorized_local():
                return
            display_name = (
                os.getenv("WORKSPACE_USER_DISPLAY_NAME", "WorkSpace User").strip()
                or "WorkSpace User"
            )[:80]
            initials = "".join(
                part[0].upper()
                for part in display_name.split()
                if part
            )[:2] or "W"
            self._json(
                HTTPStatus.OK,
                {
                    "display_name": display_name,
                    "subtitle": "Local LAN session",
                    "initials": initials,
                    "account_scope": "lan_session",
                },
            )
            return
        if path == "/api/conversations":
            if not self._authorized_local():
                return
            query = parse_qs(parsed.query).get("q", [""])[0]
            rows = self.app.service.history.list_conversations(
                self._owner_key(),
                query=str(query)[:200],
            )
            self._json(HTTPStatus.OK, {"conversations": rows})
            return
        if path.startswith("/api/conversations/"):
            if not self._authorized_local():
                return
            parts = [part for part in path.split("/") if part]
            if len(parts) != 3:
                self._json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
                return
            try:
                payload = self.app.service.history.get_conversation(
                    self._owner_key(),
                    parts[2],
                )
            except (KeyError, ValueError):
                self._json(HTTPStatus.NOT_FOUND, {"error": "Conversation not found"})
                return
            self._json(HTTPStatus.OK, payload)
            return
        super().do_GET()

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path.startswith("/api/conversations/") and path.endswith("/pin"):
            if not self._authorized_local():
                return
            parts = [part for part in path.split("/") if part]
            if len(parts) != 4 or parts[-1] != "pin":
                self._json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
                return
            try:
                payload = self._read_json_large(32 * 1024)
                pinned = payload.get("pinned")
                if not isinstance(pinned, bool):
                    raise ValueError("pinned must be a boolean")
                conversation = self.app.service.history.set_pinned(
                    self._owner_key(),
                    parts[2],
                    pinned,
                )
                self._json(HTTPStatus.OK, conversation)
            except KeyError:
                self._json(HTTPStatus.NOT_FOUND, {"error": "Conversation not found"})
            except ValueError as exc:
                self._json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": redact_sensitive_text(str(exc))[:400]},
                )
            return

        if path != "/api/chat":
            super().do_POST()
            return
        if not self._private_or_reject():
            return
        if not self._authorized():
            self._json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "Authentication required"},
            )
            return

        try:
            payload = self._read_json_large(128 * 1024)
            message = str(payload.get("message") or "")
            language = str(
                payload.get("language") or self.app.service.default_language
            )
            if language not in {"ja", "vi", "en"}:
                raise ValueError("Unsupported response language")
            fmt = str(payload.get("format") or "source")
            if fmt not in {"source", "pptx", "pdf", "all"}:
                raise ValueError("Unsupported output format")
            mode, effort = _validate_request_options(
                payload.get("mode"),
                payload.get("effort"),
                self.app.service.orchestrator.config,
            )
            raw_uploads = payload.get("upload_ids") or []
            if not isinstance(raw_uploads, list):
                raise UploadSecurityError("upload_ids must be an array")
            if len(raw_uploads) > MAX_UPLOADS_PER_TASK:
                raise UploadSecurityError(
                    f"At most {MAX_UPLOADS_PER_TASK} uploads may be attached to one task"
                )
            upload_ids = _validate_owned_uploads(
                self.app.service.orchestrator.knowledge_gateway,
                [str(item) for item in raw_uploads],
                self.client_address[0],
            )
            raw_conversation = str(payload.get("conversation_id") or "").strip()
            conversation_id = raw_conversation or None
            prefix = "" if fmt == "source" else f"/{fmt} "
            job = self.app.service.submit(
                prefix + message,
                channel="web",
                sender=self.client_address[0],
                language=language,
                upload_ids=upload_ids,
                request_mode=mode,
                effort=effort,
                conversation_id=conversation_id,
            )
            response = job.public_dict()
            response["conversation_id"] = self.app.service.conversation_for_job(
                job.job_id
            )
            self._json(HTTPStatus.ACCEPTED, response)
        except (ValueError, UploadSecurityError) as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": redact_sensitive_text(str(exc))[:800]},
            )


def main() -> int:
    config = load_config()
    orchestrator = Orchestrator(config)
    orchestrator.initialize()

    access_token = os.getenv("THREE_AGENT_WEB_ACCESS_TOKEN", "")
    host = os.getenv("THREE_AGENT_WEB_HOST", "0.0.0.0")
    port = int(os.getenv("THREE_AGENT_WEB_PORT", "8787"))
    language = os.getenv("THREE_AGENT_CHAT_LANGUAGE", "ja")

    service = SidebarKnowledgeChatService(orchestrator, default_language=language)
    service.start()
    sessions = SessionStore(access_token)
    app = ProgressApplication(service, sessions, config.artifact_root)

    telegram_token = os.getenv("THREE_AGENT_TELEGRAM_BOT_TOKEN", "").strip()
    allowed_ids = _parse_allowed_ids(
        os.getenv("THREE_AGENT_TELEGRAM_ALLOWED_USER_IDS", "")
    )
    if telegram_token:
        bridge = TelegramBridge(
            service,
            orchestrator.internet_gateway,
            telegram_token,
            allowed_ids,
        )
        threading.Thread(
            target=bridge.run_forever,
            name="workspace-telegram",
            daemon=True,
        ).start()
        print(
            f"[WorkSpace] Telegram enabled; authorized users={len(allowed_ids)}.",
            flush=True,
        )
    else:
        print(
            "[WorkSpace] Telegram disabled (no bot token configured).",
            flush=True,
        )

    httpd = ThreadingHTTPServer((host, port), SidebarKnowledgeHTTPHandler)
    httpd.app = app  # type: ignore[attr-defined]
    print(f"[WorkSpace] LAN UI: {_lan_hint(host, port)}", flush=True)
    print(
        "[WorkSpace] Persistent owner-scoped chat history and collapsible sidebar enabled.",
        flush=True,
    )
    print(
        "[WorkSpace] Secure uploads remain enabled; public web search remains policy-controlled.",
        flush=True,
    )
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
