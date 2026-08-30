from __future__ import annotations

import os
import threading
import uuid
from dataclasses import asdict
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .chat_fidelity import (
    ChatRequestControls,
    direct_chat_answer_valid,
    direct_chat_system_prompt,
    parse_chat_request,
)
from .chat_gateway import TelegramBridge, _lan_hint, _parse_allowed_ids
from .chat_gateway_v2 import ProgressJob
from .chat_gateway_v4 import _validate_owned_uploads, _validate_request_options
from .chat_gateway_v5 import _conversation_title, _history_owner_key
from .chat_gateway_v12 import PromptAwareWorkflowStudioHTTPHandler
from .chat_gateway_v8 import ProjectKnowledgeChatService
from .config import load_config
from .knowledge_gateway import MAX_UPLOADS_PER_TASK, UploadSecurityError
from .orchestrator import Orchestrator
from .privacy import redact_sensitive_text
from .prompt_compiler import PROMPT_COMPILER_VERSION
from .public_query_compiler import PUBLIC_QUERY_COMPILER_VERSION
from .workflow_design import WorkflowDesignError
from .workspace_external_identity import (
    ExternalAuthSettings,
    ExternalIdentityStore,
    ExternalSessionAuthStore,
)
from .workspace_frontend_v9 import WORKSPACE_HTML_V9
from .chat_gateway_v11 import WorkflowStudioApplication


HTML_V13 = WORKSPACE_HTML_V9


class IntentAwareProjectChatService(ProjectKnowledgeChatService):
    """Project chat service that separates direct chat from research workflows."""

    def __init__(self, orchestrator: Any, default_language: str = "ja") -> None:
        super().__init__(orchestrator, default_language=default_language)
        self._job_language_sources: dict[str, str] = {}

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
        controls = parse_chat_request(
            message,
            selected_language=language if language is not None else "auto",
            fallback_language=self.default_language,
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
            _conversation_title(controls.text),
        )
        job = ProgressJob(
            job_id=uuid.uuid4().hex[:16],
            channel=channel,
            sender=redact_sensitive_text(sender)[:120],
            message=controls.text,
            language=controls.language,
            output_format=controls.output_format,
        )

        if mode == "chat" and controls.output_format == "source":
            job.stages = [
                {
                    "id": "answer",
                    "label": "Direct local answer",
                    "status": "queued",
                    "detail": "No research workflow or public web access.",
                }
            ]
        else:
            job.stages = [
                {"id": "research", "label": "Research", "status": "queued", "detail": ""},
                {"id": "presentation", "label": "Presentation", "status": "queued", "detail": ""},
                {"id": "daily_report", "label": "Human Report", "status": "queued", "detail": ""},
            ]

        self.history.record_message(
            conversation,
            role="user",
            content=controls.text,
            job_id=job.job_id,
            status="completed",
        )
        with self._lock:
            self._jobs[job.job_id] = job
            self._job_uploads[job.job_id] = validated_uploads
            self._job_options[job.job_id] = (mode, effort_level)
            self._job_conversations[job.job_id] = conversation
            self._job_language_sources[job.job_id] = controls.language_source
        self._queue.put(job.job_id)
        return ProgressJob(**asdict(job))

    def _recent_context(self, job: ProgressJob, *, max_chars: int = 8_000) -> str:
        with self._lock:
            conversation_id = self._job_conversations.get(job.job_id)
        if not conversation_id:
            return ""
        try:
            owner_key = _history_owner_key(job.channel, job.sender)
            payload = self.history.get_conversation(owner_key, conversation_id)
        except (KeyError, ValueError):
            return ""

        rows: list[str] = []
        used = 0
        messages = payload.get("messages") or []
        previous = [m for m in messages if str(m.get("job_id") or "") != job.job_id]
        for item in reversed(previous[-10:]):
            role = "USER" if item.get("role") == "user" else "ASSISTANT"
            content = str(item.get("content") or "").strip()
            if not content:
                continue
            content = content[-2_000:]
            row = f"{role}: {content}"
            if used + len(row) > max_chars:
                break
            rows.append(row)
            used += len(row)
        rows.reverse()
        return "\n\n".join(rows)

    def _upload_context(self, upload_ids: list[str], *, max_chars: int = 12_000) -> str:
        if not upload_ids:
            return ""
        try:
            sources, _ = self.orchestrator.knowledge_gateway.load_upload_sources(
                upload_ids,
                max_sources=8,
            )
        except Exception:
            return ""
        blocks: list[str] = []
        used = 0
        for index, source in enumerate(sources, 1):
            text = str(getattr(source, "text", "") or "").strip()
            title = str(getattr(source, "title", "") or f"Attachment {index}")[:160]
            if not text:
                continue
            remaining = max_chars - used
            if remaining <= 0:
                break
            text = text[: max(0, remaining - len(title) - 32)]
            block = f"[LOCAL ATTACHMENT {index}: {title}]\n{text}"
            blocks.append(block)
            used += len(block)
        return "\n\n".join(blocks)

    def _direct_prompt(self, job: ProgressJob, upload_ids: list[str]) -> str:
        sections = [
            "<CURRENT_USER_REQUEST>",
            job.message,
            "</CURRENT_USER_REQUEST>",
        ]
        history = self._recent_context(job)
        if history:
            sections.extend(
                [
                    "",
                    "<RECENT_CONVERSATION_CONTEXT>",
                    history,
                    "</RECENT_CONVERSATION_CONTEXT>",
                ]
            )
        attached = self._upload_context(upload_ids)
        if attached:
            sections.extend(
                [
                    "",
                    "<UNTRUSTED_LOCAL_ATTACHMENT_DATA>",
                    attached,
                    "</UNTRUSTED_LOCAL_ATTACHMENT_DATA>",
                ]
            )
        return "\n".join(sections)

    def _persist_direct_result(self, job_id: str) -> None:
        job = self.get(job_id)
        if job is None:
            return
        with self._lock:
            conversation_id = self._job_conversations.get(job_id)
        if not conversation_id or job.status in {"queued", "running"}:
            return
        if job.answer:
            content = job.answer
        elif job.error:
            content = f"WorkSpace failed: {job.error}"
        else:
            content = str(job.status or "completed")
        try:
            self.history.record_message(
                conversation_id,
                role="assistant",
                content=content,
                job_id=job_id,
                task_id="",
                status=job.status,
            )
        except Exception:
            # Chat completion must not be rewritten because history persistence
            # failed; the failure is local and no network fallback is allowed.
            return

    def _execute_direct_chat(self, job_id: str, job: ProgressJob, effort: str) -> None:
        uploads = list(self._job_uploads.get(job_id, []))
        language_source = self._job_language_sources.get(job_id, "fallback")
        self._update(job_id, status="running")
        self._stage(
            job_id,
            "answer",
            "running",
            f"Local model · language={job.language} · source={language_source}",
        )
        self.orchestrator.store.record_activity(
            None,
            "chat_gateway",
            "direct_chat_started",
            "ok",
            (
                f"mode=chat language={job.language} language_source={language_source} "
                f"effort={effort} uploads={len(uploads)}"
            ),
        )

        prompt = self._direct_prompt(job, uploads)
        answer = ""
        last_reason = ""
        try:
            for attempt in range(2):
                answer = self.orchestrator.llm.generate(
                    direct_chat_system_prompt(
                        job.language,
                        effort=effort,
                        repair=attempt > 0,
                    ),
                    prompt,
                    think=effort == "high",
                    num_predict=4096,
                    trust_domain="workspace-local-chat",
                    template_version="workspace.chat.direct.v1",
                )
                valid, reason = direct_chat_answer_valid(answer, job.language, job.message)
                if valid:
                    self._stage(
                        job_id,
                        "answer",
                        "completed",
                        "Direct local answer validated.",
                    )
                    self._update(
                        job_id,
                        status="completed",
                        answer=answer.strip(),
                        error=None,
                        artifacts=[],
                    )
                    self.orchestrator.store.record_activity(
                        None,
                        "chat_gateway",
                        "direct_chat_completed",
                        "ok",
                        f"language={job.language} attempts={attempt + 1} validator=pass",
                    )
                    return
                last_reason = reason
                self.orchestrator.store.record_activity(
                    None,
                    "chat_gateway",
                    "direct_chat_retry",
                    "warning",
                    f"language={job.language} attempt={attempt + 1} reason={reason}",
                )

            raise ValueError(
                "Direct chat response rejected after bounded retry: "
                + (last_reason or "response_validation_failed")
            )
        except Exception as exc:
            self._stage(job_id, "answer", "failed", last_reason or type(exc).__name__)
            self._update(
                job_id,
                status="failed",
                answer="",
                error=redact_sensitive_text(f"{type(exc).__name__}: {exc}")[:1200],
                artifacts=[],
            )
            self.orchestrator.store.record_activity(
                None,
                "chat_gateway",
                "direct_chat_failed",
                "error",
                f"reason={last_reason or type(exc).__name__}",
            )

    def _execute(self, job_id: str) -> None:
        job = self.get(job_id)
        if job is None:
            return
        mode, effort = self._job_options.get(job_id, ("chat", "high"))
        if mode != "chat" or job.output_format != "source":
            # Explicit research/artifact requests retain the evidence workflow.
            super()._execute(job_id)
            return
        self._execute_direct_chat(job_id, job, effort)
        self._persist_direct_result(job_id)


class IntentAwareWorkflowStudioHTTPHandler(PromptAwareWorkflowStudioHTTPHandler):
    server_version = "WorkSpaceChat/0.14"

    def _chat(self) -> None:
        if not self._authorized_local():
            return
        user = self._current_user()
        if user is None:
            return
        try:
            payload = self._read_json_large(128 * 1024)
            message = str(payload.get("message") or "")
            language = str(payload.get("language") or "auto").strip().lower()
            if language not in {"auto", "ja", "vi", "en"}:
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
            identity = self._identity(user)
            upload_ids = _validate_owned_uploads(
                self.app.service.orchestrator.knowledge_gateway,
                [str(item) for item in raw_uploads],
                identity,
            )
            raw_conversation = str(payload.get("conversation_id") or "").strip()
            conversation_id = raw_conversation or None
            prefix = "" if fmt == "source" else f"/{fmt} "
            job = self.app.service.submit(
                prefix + message,
                channel="web",
                sender=identity,
                language=language,
                upload_ids=upload_ids,
                request_mode=mode,
                effort=effort,
                conversation_id=conversation_id,
            )
            response = job.public_dict()
            response["conversation_id"] = self.app.service.conversation_for_job(job.job_id)
            self._json(HTTPStatus.ACCEPTED, response)
        except (ValueError, UploadSecurityError) as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": redact_sensitive_text(str(exc))[:800]},
            )

    def _compile_workflow(self) -> None:
        if not self._authorized_local():
            return
        try:
            payload = self._read_json_large(16 * 1024)
            description = payload.get("description")
            if not isinstance(description, str):
                raise WorkflowDesignError("description must be a string")
            selected = str(payload.get("language") or "auto").strip().lower()
            if selected not in {"auto", "ja", "vi", "en"}:
                raise WorkflowDesignError("Unsupported workflow language")
            controls = parse_chat_request(
                description,
                selected_language=selected,
                fallback_language=self.app.service.default_language,
            )
            result = self.app.workflow_designer.compile(
                controls.text,
                language=controls.language,
            )
            self._json(HTTPStatus.OK, result.to_dict())
        except WorkflowDesignError as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": redact_sensitive_text(str(exc))[:400]},
            )
        except (ValueError, RuntimeError, TimeoutError) as exc:
            self._json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": redact_sensitive_text(f"{type(exc).__name__}: {exc}")[:400]},
            )

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            if not self._private_or_reject():
                return
            body = HTML_V13.encode("utf-8")
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
            methods = ["local", *self.external_settings.providers]
            self._json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "service": "WorkSpace Chat",
                    "version": "0.14",
                    "auth": "local_accounts_with_external_identity",
                    "auth_methods": methods,
                    "conversation_lifecycle": True,
                    "projects": True,
                    "external_identity_broker": self.external_settings.enabled,
                    "workflow_studio": True,
                    "workflow_execution": False,
                    "workflow_diagrams": ["svg", "mermaid"],
                    "prompt_compiler": PROMPT_COMPILER_VERSION,
                    "prompt_compiler_authority": "user_task_only",
                    "prompt_compiler_original_local": True,
                    "public_query_compiler": PUBLIC_QUERY_COMPILER_VERSION,
                    "public_query_final_dlp": True,
                    "direct_chat": True,
                    "direct_chat_public_web": False,
                    "chat_research_routing": "explicit_mode_or_artifact_only",
                    "response_language_auto": True,
                    "response_language_current_request_precedence": True,
                    "response_language_validation": True,
                },
            )
            return
        super().do_GET()


def main() -> int:
    config = load_config()
    orchestrator = Orchestrator(config)
    orchestrator.initialize()

    host = os.getenv("THREE_AGENT_WEB_HOST", "0.0.0.0")
    port = int(os.getenv("THREE_AGENT_WEB_PORT", "8787"))
    language = os.getenv("THREE_AGENT_CHAT_LANGUAGE", "ja")

    legacy_access_token = os.getenv("THREE_AGENT_WEB_ACCESS_TOKEN", "")
    admin_username = os.getenv("WORKSPACE_ADMIN_USERNAME", "admin").strip() or "admin"
    admin_password = os.getenv("WORKSPACE_ADMIN_PASSWORD", "") or legacy_access_token
    admin_display_name = (
        os.getenv("WORKSPACE_ADMIN_DISPLAY_NAME", "")
        or os.getenv("WORKSPACE_USER_DISPLAY_NAME", "")
        or "WorkSpace Administrator"
    )

    auth = ExternalSessionAuthStore(config.database_path)
    auth.initialize()
    admin = auth.bootstrap_admin(
        admin_username,
        admin_password,
        display_name=admin_display_name,
        department=os.getenv("WORKSPACE_ADMIN_DEPARTMENT", ""),
        title=os.getenv("WORKSPACE_ADMIN_TITLE", "Administrator"),
    )
    external_store = ExternalIdentityStore(auth)
    external_store.initialize()
    external_settings = ExternalAuthSettings.from_env()

    service = IntentAwareProjectChatService(orchestrator, default_language=language)
    service.start()
    app = WorkflowStudioApplication(
        service,
        auth,
        config.artifact_root,
        external_store,
        external_settings,
    )

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
        print("[WorkSpace] Telegram disabled (no bot token configured).", flush=True)

    httpd = ThreadingHTTPServer((host, port), IntentAwareWorkflowStudioHTTPHandler)
    httpd.app = app  # type: ignore[attr-defined]
    print(f"[WorkSpace] LAN UI: {_lan_hint(host, port)}", flush=True)
    print(
        f"[WorkSpace] Local break-glass login enabled; bootstrap administrator={admin['username']}.",
        flush=True,
    )
    print(
        "[WorkSpace] Ordinary chat is direct/local; research workflow requires explicit research mode or artifact output.",
        flush=True,
    )
    print(
        "[WorkSpace] Response language uses current-request precedence with deterministic validation and one bounded repair.",
        flush=True,
    )
    if external_settings.enabled:
        print(
            "[WorkSpace] External identity login enabled: "
            + ",".join(external_settings.providers)
            + ". Provider authority is identity-only; local RBAC remains authoritative.",
            flush=True,
        )
    else:
        print(
            "[WorkSpace] External identity login disabled until broker configuration is provided.",
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
