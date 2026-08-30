from __future__ import annotations

import os
import threading
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from urllib.parse import urlparse

from .chat_gateway import TelegramBridge, _lan_hint, _parse_allowed_ids
from .chat_gateway_v8 import ProjectKnowledgeChatService
from .chat_gateway_v10 import ExternalAuthApplication, FourWayLoginHTTPHandler
from .config import load_config
from .orchestrator import Orchestrator
from .privacy import redact_sensitive_text
from .workflow_dispatch import WorkflowDispatchError, WorkflowDispatchService
from .workspace_external_identity import ExternalAuthSettings, ExternalIdentityStore, ExternalSessionAuthStore
from .workspace_frontend_v8 import WORKSPACE_HTML_V8


HTML_V11 = WORKSPACE_HTML_V8


class DispatchHTTPHandler(FourWayLoginHTTPHandler):
    """External-identity gateway plus owner-scoped WorkSpace Dispatch."""

    server_version = "WorkSpaceChat/0.12"

    def _dispatch_error(self, status: HTTPStatus, exc: Exception) -> None:
        self._json(status, {"error": redact_sensitive_text(str(exc))[:400]})

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            if not self._private_or_reject():
                return
            body = HTML_V11.encode("utf-8")
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
                {
                    "status": "ok",
                    "service": "WorkSpace Chat",
                    "version": "0.12",
                    "auth": "local_accounts_with_external_identity",
                    "auth_methods": ["local", *self.external_settings.providers],
                    "conversation_lifecycle": True,
                    "projects": True,
                    "external_identity_broker": self.external_settings.enabled,
                    "dispatch_workflow_designer": True,
                    "dispatch_requires_approval": True,
                    "dispatch_max_nodes": 12,
                    "dispatch_max_parallel": 2,
                    "dispatch_custom_dag_execution": False,
                },
            )
            return
        if path.startswith("/api/dispatch/"):
            if not self._authorized_local():
                return
            parts = [part for part in path.split("/") if part]
            if len(parts) == 3:
                try:
                    result = self.app.dispatch.status(self._owner_key(), parts[2])
                    self._json(HTTPStatus.OK, result)
                except KeyError:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "Workflow not found"})
                except WorkflowDispatchError as exc:
                    self._dispatch_error(HTTPStatus.BAD_REQUEST, exc)
                return
        super().do_GET()

    def _compile_dispatch(self) -> None:
        if not self._authorized_local():
            return
        try:
            payload = self._read_json_large(32 * 1024)
            description = payload.get("description")
            if not isinstance(description, str):
                raise WorkflowDispatchError("description must be a string")
            result = self.app.dispatch.compile(self._owner_key(), description)
            self._json(HTTPStatus.CREATED, result)
        except WorkflowDispatchError as exc:
            self._dispatch_error(HTTPStatus.BAD_REQUEST, exc)
        except Exception as exc:
            self._dispatch_error(HTTPStatus.UNPROCESSABLE_ENTITY, exc)

    def _run_dispatch(self, workflow_id: str) -> None:
        if not self._authorized_local():
            return
        try:
            payload = self._read_json_large(8 * 1024)
            if payload.get("approved") is not True:
                raise WorkflowDispatchError("approved=true is required to dispatch this workflow")
            language = payload.get("language", "ja")
            output_format = payload.get("output_format", "pptx")
            if not isinstance(language, str) or not isinstance(output_format, str):
                raise WorkflowDispatchError("language and output_format must be strings")
            result = self.app.dispatch.dispatch(
                self._owner_key(), workflow_id, approved=True,
                language=language, output_format=output_format,
            )
            self._json(HTTPStatus.ACCEPTED, result)
        except KeyError:
            self._json(HTTPStatus.NOT_FOUND, {"error": "Workflow not found"})
        except WorkflowDispatchError as exc:
            self._dispatch_error(HTTPStatus.CONFLICT, exc)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/dispatch/compile":
            self._compile_dispatch()
            return
        if path.startswith("/api/dispatch/"):
            parts = [part for part in path.split("/") if part]
            if len(parts) == 4 and parts[3] == "run":
                self._run_dispatch(parts[2])
                return
        super().do_POST()


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
    admin_display_name = os.getenv("WORKSPACE_ADMIN_DISPLAY_NAME", "") or os.getenv("WORKSPACE_USER_DISPLAY_NAME", "") or "WorkSpace Administrator"

    auth = ExternalSessionAuthStore(config.database_path)
    auth.initialize()
    admin = auth.bootstrap_admin(
        admin_username, admin_password, display_name=admin_display_name,
        department=os.getenv("WORKSPACE_ADMIN_DEPARTMENT", ""),
        title=os.getenv("WORKSPACE_ADMIN_TITLE", "Administrator"),
    )
    external_store = ExternalIdentityStore(auth)
    external_store.initialize()
    external_settings = ExternalAuthSettings.from_env()
    service = ProjectKnowledgeChatService(orchestrator, default_language=language)
    service.start()
    app = ExternalAuthApplication(service, auth, config.artifact_root, external_store, external_settings)
    app.dispatch = WorkflowDispatchService(orchestrator, config.artifact_root)  # type: ignore[attr-defined]

    telegram_token = os.getenv("THREE_AGENT_TELEGRAM_BOT_TOKEN", "").strip()
    allowed_ids = _parse_allowed_ids(os.getenv("THREE_AGENT_TELEGRAM_ALLOWED_USER_IDS", ""))
    if telegram_token:
        bridge = TelegramBridge(service, orchestrator.internet_gateway, telegram_token, allowed_ids)
        threading.Thread(target=bridge.run_forever, name="workspace-telegram", daemon=True).start()
        print(f"[WorkSpace] Telegram enabled; authorized users={len(allowed_ids)}.", flush=True)
    else:
        print("[WorkSpace] Telegram disabled (no bot token configured).", flush=True)

    httpd = ThreadingHTTPServer((host, port), DispatchHTTPHandler)
    httpd.app = app  # type: ignore[attr-defined]
    print(f"[WorkSpace] LAN UI: {_lan_hint(host, port)}", flush=True)
    print(f"[WorkSpace] Local break-glass login enabled; bootstrap administrator={admin['username']}.", flush=True)
    if external_settings.enabled:
        print("[WorkSpace] External identity login enabled: " + ",".join(external_settings.providers) + ". Provider authority is identity-only; local RBAC remains authoritative.", flush=True)
    else:
        print("[WorkSpace] External identity login disabled until broker configuration is provided.", flush=True)
    print("[WorkSpace] Dispatch designer enabled. Custom DAGs are preview-only until an audited execution adapter exists.", flush=True)
    print("[WorkSpace] Dispatch execution requires explicit authenticated-owner approval and reuses existing WorkSpace runtime validators/budgets.", flush=True)
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
