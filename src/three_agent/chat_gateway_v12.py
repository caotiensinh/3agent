from __future__ import annotations

import os
import threading
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .chat_gateway import SESSION_TTL_SECONDS, TelegramBridge, _lan_hint, _parse_allowed_ids
from .chat_gateway_v11 import WorkflowStudioApplication, WorkflowStudioHTTPHandler
from .chat_gateway_v8 import ProjectKnowledgeChatService
from .config import load_config
from .orchestrator import Orchestrator
from .privacy import redact_sensitive_text
from .workflow_dispatch import WorkflowDispatchController, WorkflowDispatchError
from .workspace_external_identity import (
    ExternalAuthSettings,
    ExternalIdentityStore,
    ExternalSessionAuthStore,
)
from .workspace_frontend_v9 import WORKSPACE_HTML_V9


HTML_V12 = WORKSPACE_HTML_V9


class WorkflowDispatchApplication(WorkflowStudioApplication):
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
        self.workflow_dispatch = WorkflowDispatchController(service.orchestrator)


class WorkflowDispatchHTTPHandler(WorkflowStudioHTTPHandler):
    server_version = "WorkSpaceChat/0.13"

    @staticmethod
    def _public_dispatch_result(payload: dict[str, Any]) -> dict[str, Any]:
        """Return only browser-safe dispatch metadata; never expose server paths."""
        raw_result = payload.get("result")
        result = raw_result if isinstance(raw_result, dict) else {}
        raw_error = result.get("error")
        public_result = {
            "task_id": str(payload.get("task_id") or ""),
            "status": str(result.get("status") or "unknown"),
            "task_status": str(result.get("task_status") or "unknown"),
            "stage": str(result.get("stage") or "unknown"),
            "error": (
                redact_sensitive_text(str(raw_error))[:400]
                if raw_error not in {None, ""}
                else None
            ),
        }
        return {
            "schema_version": str(payload.get("schema_version") or ""),
            "task_id": str(payload.get("task_id") or ""),
            "dispatch_status": str(payload.get("dispatch_status") or "unknown"),
            "execution_profile": str(payload.get("execution_profile") or ""),
            "result": public_result,
        }

    def _prepare_dispatch(self) -> None:
        admin = self._require_admin()
        if admin is None:
            return
        try:
            payload = self._read_json_large(64 * 1024)
            contract = payload.get("contract")
            if not isinstance(contract, dict):
                raise WorkflowDispatchError("contract must be an object")
            result = self.app.workflow_dispatch.prepare(
                contract,
                language=str(payload.get("language") or "ja"),
                audience=str(payload.get("audience") or "R&D internal"),
                purpose=str(payload.get("purpose") or "inform"),
                slide_count=payload.get("slide_count", 6),
                output_format=str(payload.get("output_format") or "pptx"),
            )
            self._json(HTTPStatus.CREATED, result)
        except WorkflowDispatchError as exc:
            self._json(
                HTTPStatus.CONFLICT,
                {
                    "error": redact_sensitive_text(str(exc))[:400],
                    "code": "BLOCKED_BY_ADMISSION",
                },
            )
        except (RuntimeError, ValueError) as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": redact_sensitive_text(f"{type(exc).__name__}: {exc}")[:400]},
            )

    def _execute_dispatch(self, task_id: str) -> None:
        admin = self._require_admin()
        if admin is None:
            return
        try:
            payload = self._read_json_large(16 * 1024)
            result = self.app.workflow_dispatch.execute(
                task_id,
                approval_fingerprint=str(payload.get("approval_fingerprint") or ""),
                confirmation=str(payload.get("confirmation") or ""),
                approver_id=str(admin["user_id"]),
            )
            self._json(HTTPStatus.OK, self._public_dispatch_result(result))
        except WorkflowDispatchError as exc:
            self._json(
                HTTPStatus.CONFLICT,
                {"error": redact_sensitive_text(str(exc))[:400]},
            )
        except (RuntimeError, TimeoutError, ValueError) as exc:
            self._json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": redact_sensitive_text(f"{type(exc).__name__}: {exc}")[:400]},
            )

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            if not self._private_or_reject():
                return
            body = HTML_V12.encode("utf-8")
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
                    "version": "0.13",
                    "auth": "local_accounts_with_external_identity",
                    "auth_methods": methods,
                    "conversation_lifecycle": True,
                    "projects": True,
                    "external_identity_broker": self.external_settings.enabled,
                    "workflow_studio": True,
                    "workflow_diagrams": ["svg", "mermaid"],
                    "workflow_execution": True,
                    "workflow_execution_profile": "workspace-fixed-analysis/v1",
                    "workflow_execution_risk": "low_only",
                    "workflow_execution_trigger": "manual_only",
                    "workflow_execution_admin_approval": True,
                },
            )
            return
        super().do_GET()

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/workflows/prepare-dispatch":
            self._prepare_dispatch()
            return
        if path.startswith("/api/workflows/") and path.endswith("/execute"):
            parts = [part for part in path.split("/") if part]
            if (
                len(parts) == 4
                and parts[0] == "api"
                and parts[1] == "workflows"
                and parts[3] == "execute"
            ):
                self._execute_dispatch(parts[2])
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
    app = WorkflowDispatchApplication(
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

    httpd = ThreadingHTTPServer((host, port), WorkflowDispatchHTTPHandler)
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
        "[WorkSpace] Workflow Dispatch V2 enabled: manual low-risk fixed profile only; administrator approval required.",
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
