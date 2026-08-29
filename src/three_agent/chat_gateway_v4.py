from __future__ import annotations

import base64
import json
import os
import threading
import uuid
from dataclasses import asdict
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .chat_gateway import (
    SessionStore,
    TelegramBridge,
    _lan_hint,
    _parse_allowed_ids,
    _parse_request_controls,
)
from .chat_gateway_v2 import ProgressApplication, ProgressJob
from .chat_gateway_v3 import HumanReportChatService, HumanReportHTTPHandler
from .config import AppConfig, load_config
from .human_report import create_human_report
from .knowledge_gateway import MAX_UPLOAD_BYTES, MAX_UPLOADS_PER_TASK, UploadSecurityError
from .models import TaskStatus
from .orchestrator import Orchestrator
from .privacy import redact_sensitive_text
from .workspace_frontend import WORKSPACE_HTML

MAX_UPLOAD_REQUEST_BYTES = 24 * 1024 * 1024
REQUEST_MODES = frozenset({"chat", "web_search", "deep_research"})
EFFORT_LEVELS = frozenset({"standard", "high"})
HTML_V4 = WORKSPACE_HTML


def workspace_ui_capabilities(config: AppConfig) -> dict[str, Any]:
    """Return UI capabilities without granting runtime authority.

    A feature is enabled only when a real local/runtime path exists and trusted
    configuration authorizes it. The frontend must not infer capabilities from
    decorative controls.
    """

    internet = config.internet_gateway
    mode = str(config.confidentiality_mode or "").strip().lower()
    web_enabled = bool(
        internet.enabled
        and internet.public_search_enabled
        and mode in {"public", "public-research"}
    )
    github_raw = config.raw.get("github") if isinstance(config.raw, dict) else {}
    github_configured = bool(
        isinstance(github_raw, dict) and github_raw.get("enabled", False)
    )

    return {
        "schema_version": "workspace-chat-capabilities/v1",
        "product_name": config.product_name or "WorkSpace",
        "environment": config.environment,
        "confidentiality_mode": config.confidentiality_mode,
        "limits": {
            "max_upload_bytes": MAX_UPLOAD_BYTES,
            "max_uploads_per_task": MAX_UPLOADS_PER_TASK,
            "max_message_chars": 12000,
        },
        "features": {
            "upload": {
                "enabled": True,
                "state_label": "Ready",
                "reason": "",
            },
            "library": {
                "enabled": True,
                "state_label": "Ready",
                "reason": "",
            },
            "deep_research": {
                "enabled": True,
                "state_label": "Ready",
                "reason": (
                    "Uses the existing evidence-bounded WorkSpace workflow. "
                    "It does not grant extra network, model, or tool authority."
                ),
            },
            "web_search": {
                "enabled": web_enabled,
                "state_label": "Policy off" if not web_enabled else "Ready",
                "reason": (
                    ""
                    if web_enabled
                    else "Public web search is disabled by the active WorkSpace policy."
                ),
            },
            "image_generation": {
                "enabled": False,
                "state_label": "Not configured",
                "reason": (
                    "Local image generation is not configured. WorkSpace will not "
                    "send confidential prompts to an external image service."
                ),
            },
            "voice_input": {
                "enabled": False,
                "state_label": "Not configured",
                "reason": (
                    "Local speech-to-text is not configured. WorkSpace will not use "
                    "browser/cloud speech recognition for confidential audio."
                ),
            },
            "github": {
                "enabled": False,
                "state_label": "Operator only",
                "reason": (
                    "GitHub is configured for operator/deployment use only; the web "
                    "chat has no repository mutation authority."
                    if github_configured
                    else "GitHub runtime access is not enabled for WorkSpace web chat."
                ),
            },
        },
    }


def _validate_request_options(
    request_mode: Any,
    effort: Any,
    config: AppConfig,
) -> tuple[str, str]:
    mode = str(request_mode or "chat").strip().lower()
    level = str(effort or "high").strip().lower()
    if mode not in REQUEST_MODES:
        raise ValueError("Unsupported WorkSpace request mode")
    if level not in EFFORT_LEVELS:
        raise ValueError("Unsupported WorkSpace effort level")
    if mode == "web_search" and not workspace_ui_capabilities(config)["features"][
        "web_search"
    ]["enabled"]:
        raise ValueError("Web search is disabled by the active WorkSpace policy")
    return mode, level


def _request_purpose(mode: str, effort: str) -> str:
    if mode == "web_search":
        base = (
            "answer the user request with evidence; prefer policy-authorized public-web "
            "evidence where available"
        )
    elif mode == "deep_research":
        base = (
            "perform thorough evidence-bounded research and answer the user request; "
            "preserve unresolved items instead of inventing evidence"
        )
    else:
        base = "answer the user request with evidence"

    if effort == "high":
        return base + "; use thorough analysis within existing deterministic budgets"
    return base + "; use standard analysis within existing deterministic budgets"


def _owned_upload_manifest(gateway: Any, upload_id: str, sender: str) -> dict[str, Any]:
    folder = Path(gateway.root) / upload_id
    manifest = folder / "manifest.json"
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UploadSecurityError(f"Upload metadata is unavailable: {upload_id}") from exc
    if not isinstance(payload, dict) or str(payload.get("upload_id") or "") != upload_id:
        raise UploadSecurityError(f"Upload metadata is invalid: {upload_id}")
    if str(payload.get("sender") or "") != sender:
        raise UploadSecurityError("Upload is not owned by this LAN client")
    return payload


def _validate_owned_uploads(
    gateway: Any,
    upload_ids: list[str],
    sender: str,
) -> list[str]:
    validated = gateway.validate_upload_ids(upload_ids)
    for upload_id in validated:
        _owned_upload_manifest(gateway, upload_id, sender)
    return validated


def _recent_uploads(
    gateway: Any,
    sender: str,
    *,
    limit: int = 40,
) -> list[dict[str, Any]]:
    """List metadata-only uploads owned by one LAN client.

    Raw text, raw image bytes, filesystem paths, sender identity, and extracted
    content are never returned by this endpoint.
    """

    maximum = max(1, min(100, int(limit)))
    rows: list[tuple[float, dict[str, Any]]] = []
    root = Path(gateway.root)
    if not root.is_dir():
        return []

    for manifest in root.glob("*/manifest.json"):
        upload_id = manifest.parent.name
        try:
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            if (
                not isinstance(payload, dict)
                or str(payload.get("upload_id") or "") != upload_id
                or str(payload.get("sender") or "") != sender
            ):
                continue
            size = max(0, int(payload.get("size") or 0))
            name = str(payload.get("name") or upload_id)[:160]
            documents = payload.get("documents")
            images = payload.get("images")
            document_count = len(documents) if isinstance(documents, list) else 0
            image_count = len(images) if isinstance(images, list) else 0
            originals = list(manifest.parent.glob("original.*"))
            suffix = originals[0].suffix.casefold() if originals else ""
            if suffix == ".zip":
                kind = "zip"
            elif suffix in {".png", ".jpg", ".jpeg", ".webp"}:
                kind = "image"
            else:
                kind = "document"
            warnings_raw = payload.get("warnings")
            warnings = (
                [
                    redact_sensitive_text(str(item))[:240]
                    for item in warnings_raw[:8]
                    if str(item).strip()
                ]
                if isinstance(warnings_raw, list)
                else []
            )
            row = {
                "upload_id": upload_id,
                "name": name,
                "size": size,
                "kind": kind,
                "document_count": document_count,
                "image_count": image_count,
                "warnings": warnings,
            }
            rows.append((manifest.stat().st_mtime, row))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            continue

    rows.sort(key=lambda item: item[0], reverse=True)
    return [row for _, row in rows[:maximum]]


class KnowledgeChatService(HumanReportChatService):
    def __init__(self, orchestrator: Orchestrator, default_language: str = "ja") -> None:
        super().__init__(orchestrator, default_language=default_language)
        self._job_uploads: dict[str, list[str]] = {}
        self._job_options: dict[str, tuple[str, str]] = {}

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
        with self._lock:
            self._jobs[job.job_id] = job
            self._job_uploads[job.job_id] = validated_uploads
            self._job_options[job.job_id] = (mode, effort_level)
        self._queue.put(job.job_id)
        return ProgressJob(**asdict(job))

    def _execute(self, job_id: str) -> None:
        job = self.get(job_id)
        if job is None:
            return
        self._update(job_id, status="running")
        task = self.orchestrator.store.create_task(job.message[:96], job.message)
        uploads = list(self._job_uploads.get(job_id, []))
        mode, effort = self._job_options.get(job_id, ("chat", "high"))
        self.orchestrator.store.record_activity(
            task.task_id,
            "chat_gateway",
            "workspace_request_options",
            "ok",
            f"mode={mode} effort={effort}",
        )
        if uploads:
            self.orchestrator.store.attach_uploads(task.task_id, uploads)
            self.orchestrator.store.record_activity(
                task.task_id,
                "knowledge_gateway",
                "uploads_attached",
                "ok",
                f"count={len(uploads)}",
            )
        self._update(job_id, task_id=task.task_id)
        if mode == "web_search":
            stage_detail = (
                "WorkSpace is validating evidence and using policy-authorized public research."
            )
        elif mode == "deep_research":
            stage_detail = "WorkSpace is performing thorough evidence-bounded research."
        else:
            stage_detail = "WorkSpace is validating evidence for this request."
        self._stage(job_id, "research", "running", stage_detail)
        stop = threading.Event()
        monitor = threading.Thread(
            target=self._monitor,
            args=(job_id, task.task_id, stop),
            name=f"workspace-stage-{job_id}",
            daemon=True,
        )
        monitor.start()
        try:
            result = self.orchestrator.workflow.run_task(
                task.task_id,
                live=True,
                audience="R&D internal",
                purpose=_request_purpose(mode, effort),
                language=job.language,
                slide_count=6,
                output_format=job.output_format,
            )
            handoff = next(
                (item for item in result.research_artifacts if item.endswith("_handoff.json")),
                "",
            )

            report_paths: list[str] = []
            answer = ""
            report_warnings: list[str] = []
            if handoff:
                bundle = create_human_report(
                    task_id=task.task_id,
                    title=task.title,
                    request=task.request,
                    handoff_path=handoff,
                    artifact_root=self.orchestrator.artifacts.root,
                    language=job.language,
                )
                answer = bundle.markdown
                report_paths = list(bundle.paths)
                report_warnings = list(bundle.warnings)
                for path in report_paths:
                    suffix = Path(path).suffix.lower().lstrip(".") or "file"
                    self.orchestrator.store.record_artifact(
                        task.task_id,
                        "daily_report",
                        f"human_report_{suffix}",
                        path,
                    )
                self.orchestrator.store.record_activity(
                    task.task_id,
                    "daily_report",
                    "human_report_created",
                    "ok" if not report_warnings else "warning",
                    "outputs=" + ",".join(Path(x).suffix.lstrip(".") for x in report_paths),
                )
            else:
                answer = (
                    "# WorkSpace Report\n\n"
                    "The workflow did not produce a validated research handoff, so a "
                    "reader-facing report could not be generated without inventing content.\n"
                )

            if report_warnings:
                answer += "\n\n> " + " | ".join(report_warnings)

            artifacts = list(
                dict.fromkeys(
                    report_paths
                    + list(result.presentation_artifacts)
                    + list(result.research_artifacts)
                    + list(result.daily_report_artifacts)
                )
            )
            status = "completed" if result.status == "completed" else result.status
            if status == "completed":
                self._stage(job_id, "research", "completed")
                self._stage(job_id, "presentation", "completed")
                self._stage(
                    job_id,
                    "daily_report",
                    "completed",
                    "Reader report and audit log are ready.",
                )
            elif status == "blocked":
                self._stage(job_id, "research", "blocked")
                self._stage(job_id, "presentation", "skipped")
                self._stage(
                    job_id,
                    "daily_report",
                    "completed",
                    "Blocker report recorded.",
                )
            elif status == "failed":
                current = self.orchestrator.store.get_task(task.task_id)
                if current.status == TaskStatus.FAILED:
                    running_presentation = any(
                        stage["id"] == "presentation" and stage["status"] == "running"
                        for stage in self._jobs[job_id].stages
                    )
                    if running_presentation:
                        self._stage(job_id, "presentation", "failed")
                self._stage(
                    job_id,
                    "daily_report",
                    "completed",
                    "Failure evidence recorded.",
                )

            self._update(
                job_id,
                status=status,
                answer=answer,
                error=redact_sensitive_text(result.error) if result.error else None,
                artifacts=artifacts,
            )
        except Exception as exc:
            self._stage(job_id, "daily_report", "failed")
            self._update(
                job_id,
                status="failed",
                error=redact_sensitive_text(f"{type(exc).__name__}: {exc}")[:1200],
            )
        finally:
            stop.set()
            monitor.join(timeout=1)


class KnowledgeHTTPHandler(HumanReportHTTPHandler):
    server_version = "WorkSpaceChat/0.5"

    def _read_json_large(self, maximum: int) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or "0")
        if length <= 0 or length > maximum:
            raise ValueError("Invalid request body size")
        raw = self.rfile.read(length)
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON object required")
        return value

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            if not self._private_or_reject():
                return
            body = HTML_V4.encode("utf-8")
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
                {"status": "ok", "service": "WorkSpace Chat", "version": "0.5"},
            )
            return
        if path in {"/api/capabilities", "/api/uploads"}:
            if not self._private_or_reject():
                return
            if not self._authorized():
                self._json(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": "Authentication required"},
                )
                return
            if path == "/api/capabilities":
                self._json(
                    HTTPStatus.OK,
                    workspace_ui_capabilities(self.app.service.orchestrator.config),
                )
            else:
                self._json(
                    HTTPStatus.OK,
                    {
                        "uploads": _recent_uploads(
                            self.app.service.orchestrator.knowledge_gateway,
                            self.client_address[0],
                        )
                    },
                )
            return
        super().do_GET()

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path not in {"/api/upload", "/api/chat"}:
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
            payload = self._read_json_large(
                MAX_UPLOAD_REQUEST_BYTES if path == "/api/upload" else 128 * 1024
            )
            if path == "/api/upload":
                encoded = str(payload.get("data_base64") or "")
                if not encoded:
                    raise UploadSecurityError("Upload body is empty")
                try:
                    data = base64.b64decode(encoded, validate=True)
                except Exception as exc:
                    raise UploadSecurityError("Upload is not valid base64") from exc
                if len(data) > MAX_UPLOAD_BYTES:
                    raise UploadSecurityError("Upload exceeds 16 MiB per-file limit")
                record = self.app.service.orchestrator.knowledge_gateway.ingest_upload(
                    str(payload.get("name") or ""),
                    data,
                    content_type=str(payload.get("type") or ""),
                    sender=self.client_address[0],
                )
                response = record.public_dict()
                response["status"] = "accepted"
                self._json(HTTPStatus.CREATED, response)
                return

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
            prefix = "" if fmt == "source" else f"/{fmt} "
            job = self.app.service.submit(
                prefix + message,
                channel="web",
                sender=self.client_address[0],
                language=language,
                upload_ids=upload_ids,
                request_mode=mode,
                effort=effort,
            )
            self._json(HTTPStatus.ACCEPTED, job.public_dict())
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
    service = KnowledgeChatService(orchestrator, default_language=language)
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
        print("[WorkSpace] Telegram disabled (no bot token configured).", flush=True)
    httpd = ThreadingHTTPServer((host, port), KnowledgeHTTPHandler)
    httpd.app = app  # type: ignore[attr-defined]
    print(f"[WorkSpace] LAN UI: {_lan_hint(host, port)}", flush=True)
    print(
        "[WorkSpace] Secure uploads enabled. Public web search remains policy-controlled.",
        flush=True,
    )
    print(
        "[WorkSpace] Image generation and voice input stay fail-closed until local runtimes are configured.",
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
