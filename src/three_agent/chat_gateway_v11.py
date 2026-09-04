from __future__ import annotations

import os
import threading
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .chat_gateway import SESSION_TTL_SECONDS, TelegramBridge, _lan_hint, _parse_allowed_ids
from .chat_gateway_v10 import ExternalAuthApplication, FourWayLoginHTTPHandler
from .chat_gateway_v8 import ProjectKnowledgeChatService
from .config import load_config
from .orchestrator import Orchestrator
from .privacy import redact_sensitive_text
from .workflow_design import WorkflowDesignCompiler, WorkflowDesignError
from .workspace_external_identity import (
    ExternalAuthSettings,
    ExternalIdentityStore,
    ExternalSessionAuthStore,
)
from .workspace_frontend import WORKSPACE_HTML


HTML_V11 = WORKSPACE_HTML


class WorkflowStudioApplication(ExternalAuthApplication):
    def __init__(
        self,
        service: Any,
        auth: ExternalSessionAuthStore,
        artifact_root,
        external_store: ExternalIdentityStore,
        external_settings: ExternalAuthSettings,
    ) -> None:
        super().__init__(
            service,
            auth,
            artifact_root,
            external_store,
            external_settings,
        )
        self.workflow_designer = WorkflowDesignCompiler(service.orchestrator.llm)


class WorkflowStudioHTTPHandler(FourWayLoginHTTPHandler):
    server_version = "WorkSpaceChat/0.12"

    def _compile_workflow(self) -> None:
        if not self._authorized_local():
            return
        try:
            payload = self._read_json_large(16 * 1024)
            description = payload.get("description")
            language = str(payload.get("language") or "ja").strip().lower()
            if language not in {"ja", "vi", "en"}:
                raise WorkflowDesignError("Unsupported workflow language")
            if not isinstance(description, str):
                raise WorkflowDesignError("description must be a string")
            result = self.app.workflow_designer.compile(
                description,
                language=language,
            )
            self._json(HTTPStatus.OK, result.to_dict())
        except WorkflowDesignError as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": redact_sensitive_text(str(exc))[:400]},
            )
        except (RuntimeError, TimeoutError) as exc:
            self._json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": redact_sensitive_text(f"{type(exc).__name__}: {exc}")[:400]},
            )

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
            methods = ["local", *self.external_settings.providers]
            self._json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "service": "WorkSpace Chat",
                    "version": "0.12",
                    "auth": "local_accounts_with_external_identity",
                    "auth_methods": methods,
                    "conversation_lifecycle": True,
                    "projects": True,
                    "external_identity_broker": self.external_settings.enabled,
                    "workflow_studio": True,
                    "workflow_execution": False,
                    "workflow_diagrams": ["svg", "mermaid"],
                },
            )
            return
        super().do_GET()

    def do_POST(self) -> None:
        if urlparse(self.path).path == "/api/workflows/compile":
            self._compile_workflow()
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

    service = ProjectKnowledgeChatService(orchestrator, default_language=language)
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

    httpd = ThreadingHTTPServer((host, port), WorkflowStudioHTTPHandler)
    httpd.app = app  # type: ignore[attr-defined]
    print(f"[WorkSpace] LAN UI: {_lan_hint(host, port)}", flush=True)
    print(
        f"[WorkSpace] Local break-glass login enabled; bootstrap administrator={admin['username']}.",
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
    print(
        "[WorkSpace] Workflow Studio enabled in design-only mode; compile/diagram never grants execution authority.",
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
