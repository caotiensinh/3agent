from __future__ import annotations

import json
import os
import threading
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .chat_gateway import TelegramBridge, _lan_hint, _parse_allowed_ids
from .chat_gateway_v13 import WorkflowDispatchApplication
from .chat_gateway_v14 import (
    IntentAwareProjectChatService,
    IntentAwareWorkflowDispatchHTTPHandler,
)
from .config import load_config
from .orchestrator import Orchestrator
from .privacy import redact_sensitive_text
from .prompt_compiler import PROMPT_COMPILER_VERSION
from .public_query_compiler import PUBLIC_QUERY_COMPILER_VERSION
from .chat_fidelity import resolve_response_language
from .workflow_design import WorkflowDesignCompilerV3
from .workflow_state_machine import (
    EXECUTION_PROFILE,
    WORKFLOW_V3_MAX_WALL_TIME_MS,
    WorkflowStateError,
    WorkflowStateMachineController,
)
from .workspace_external_identity import (
    ExternalAuthSettings,
    ExternalIdentityStore,
    ExternalSessionAuthStore,
)
from .workspace_frontend_v11 import WORKSPACE_HTML_V11


HTML_V15 = WORKSPACE_HTML_V11


class WorkflowV3Application(WorkflowDispatchApplication):
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
        self.workflow_designer = WorkflowDesignCompilerV3(service.orchestrator.llm)
        self.workflow_v3 = WorkflowStateMachineController(service.orchestrator)


class WorkflowV3HTTPHandler(IntentAwareWorkflowDispatchHTTPHandler):
    """Current-request chat fidelity plus bounded durable Workflow V3."""

    server_version = "WorkSpaceChat/0.16"

    def _prepare_dispatch(self) -> None:
        if self._require_admin() is None:
            return
        try:
            payload = self._read_json_large(64 * 1024)
            contract = payload.get("contract")
            if not isinstance(contract, dict):
                raise WorkflowStateError("contract must be an object")
            selected = str(payload.get("language") or "auto").strip().lower()
            if selected not in {"auto", "ja", "vi", "en"}:
                raise WorkflowStateError("unsupported language")
            language_text = " ".join(
                str(contract.get(key) or "") for key in ("title", "objective")
            ).strip() or json.dumps(contract, ensure_ascii=False)[:2000]
            language, _ = resolve_response_language(
                language_text,
                selected_language=selected,
                fallback_language=self.app.service.default_language,
            )
            result = self.app.workflow_v3.prepare(
                contract,
                language=language,
                audience=str(payload.get("audience") or "R&D internal"),
                purpose=str(payload.get("purpose") or "inform"),
                slide_count=payload.get("slide_count", 6),
                output_format=str(payload.get("output_format") or "pptx"),
            )
            self._json(HTTPStatus.CREATED, result)
        except WorkflowStateError as exc:
            self._json(
                HTTPStatus.CONFLICT,
                {
                    "error": redact_sensitive_text(str(exc))[:400],
                    "code": "BLOCKED_BY_V3_ADMISSION",
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
            result = self.app.workflow_v3.start(
                task_id,
                approval_fingerprint=str(payload.get("approval_fingerprint") or ""),
                confirmation=str(payload.get("confirmation") or ""),
                approver_id=str(admin["user_id"]),
            )
            self._json(HTTPStatus.OK, result)
        except WorkflowStateError as exc:
            self._json(
                HTTPStatus.CONFLICT,
                {"error": redact_sensitive_text(str(exc))[:400]},
            )
        except (RuntimeError, TimeoutError, ValueError) as exc:
            self._json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": redact_sensitive_text(f"{type(exc).__name__}: {exc}")[:400]},
            )

    def _checkpoint(self, task_id: str) -> None:
        admin = self._require_admin()
        if admin is None:
            return
        try:
            payload = self._read_json_large(16 * 1024)
            result = self.app.workflow_v3.decide_checkpoint(
                task_id,
                checkpoint_fingerprint=str(payload.get("checkpoint_fingerprint") or ""),
                decision=str(payload.get("decision") or ""),
                confirmation=str(payload.get("confirmation") or ""),
                approver_id=str(admin["user_id"]),
            )
            self._json(HTTPStatus.OK, result)
        except WorkflowStateError as exc:
            self._json(
                HTTPStatus.CONFLICT,
                {"error": redact_sensitive_text(str(exc))[:400]},
            )
        except (RuntimeError, TimeoutError, ValueError) as exc:
            self._json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": redact_sensitive_text(f"{type(exc).__name__}: {exc}")[:400]},
            )

    def _workflow_state(self, task_id: str) -> None:
        if self._require_admin() is None:
            return
        try:
            self._json(HTTPStatus.OK, self.app.workflow_v3.status(task_id))
        except WorkflowStateError as exc:
            self._json(
                HTTPStatus.NOT_FOUND,
                {"error": redact_sensitive_text(str(exc))[:400]},
            )

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            if not self._private_or_reject():
                return
            body = HTML_V15.encode("utf-8")
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
                    "version": "0.16",
                    "auth": "local_accounts_with_external_identity",
                    "auth_methods": methods,
                    "conversation_lifecycle": True,
                    "projects": True,
                    "external_identity_broker": self.external_settings.enabled,
                    "workflow_studio": True,
                    "workflow_diagrams": ["svg", "mermaid"],
                    "workflow_execution": True,
                    "workflow_execution_version": "v3",
                    "workflow_execution_profile": EXECUTION_PROFILE,
                    "workflow_execution_risk": "low_only",
                    "workflow_execution_trigger": "manual_only",
                    "workflow_execution_admin_approval": True,
                    "workflow_pause_resume": True,
                    "workflow_persistent_checkpoint": True,
                    "workflow_branching": "deterministic_only",
                    "workflow_decision_conditions": ["passed", "failed"],
                    "workflow_approval_conditions": ["approved", "rejected"],
                    "workflow_failure_rejection_terminal": True,
                    "workflow_branch_joins": False,
                    "workflow_checkpoint_wall_time_ms": WORKFLOW_V3_MAX_WALL_TIME_MS,
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
        if path.startswith("/api/workflows/") and path.endswith("/state"):
            parts = [part for part in path.split("/") if part]
            if (
                len(parts) == 4
                and parts[0] == "api"
                and parts[1] == "workflows"
                and parts[3] == "state"
            ):
                self._workflow_state(parts[2])
                return
        super().do_GET()

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/workflows/prepare-dispatch":
            self._prepare_dispatch()
            return
        if path.startswith("/api/workflows/"):
            parts = [part for part in path.split("/") if part]
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "workflows":
                if parts[3] == "execute":
                    self._execute_dispatch(parts[2])
                    return
                if parts[3] == "checkpoint":
                    self._checkpoint(parts[2])
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

    service = IntentAwareProjectChatService(orchestrator, default_language=language)
    service.start()
    app = WorkflowV3Application(
        service, auth, config.artifact_root, external_store, external_settings
    )

    telegram_token = os.getenv("THREE_AGENT_TELEGRAM_BOT_TOKEN", "").strip()
    allowed_ids = _parse_allowed_ids(
        os.getenv("THREE_AGENT_TELEGRAM_ALLOWED_USER_IDS", "")
    )
    if telegram_token:
        bridge = TelegramBridge(
            service, orchestrator.internet_gateway, telegram_token, allowed_ids
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

    httpd = ThreadingHTTPServer((host, port), WorkflowV3HTTPHandler)
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
        f"[WorkSpace] Prompt compiler active: {PROMPT_COMPILER_VERSION}; original prompt remains local.",
        flush=True,
    )
    print(
        f"[WorkSpace] Public query compiler active: {PUBLIC_QUERY_COMPILER_VERSION}; strict egress DLP remains final authority.",
        flush=True,
    )
    print(
        "[WorkSpace] Workflow V3 enabled: manual low-risk deterministic branches, persistent approval checkpoints, and exact-node resume.",
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
