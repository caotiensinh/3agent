from __future__ import annotations

import json
import os
import sqlite3
import threading
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .chat_context import DEFAULT_CONTEXT_MAX_CHARS, DEFAULT_CONTEXT_MAX_MESSAGES
from .chat_fidelity import resolve_response_language
from .chat_gateway import TelegramBridge, _lan_hint, _parse_allowed_ids
from .chat_gateway_v15 import WorkflowV3Application
from .chat_gateway_v16 import (
    CONVERSATION_CONTEXT_POLICY_VERSION,
    ContextAwareWorkflowV3HTTPHandler,
)
from .chat_service_fidelity_v2 import (
    OUTPUT_CONTRACT_POLICY_VERSION,
    ContractAwareProjectChatService,
)
from .config import load_config
from .orchestrator import Orchestrator
from .privacy import redact_sensitive_text
from .prompt_compiler import PROMPT_COMPILER_VERSION
from .public_query_compiler import PUBLIC_QUERY_COMPILER_VERSION
from .security_monitoring.contracts import MonitoringContractError
from .security_monitoring.ui_read_model import SecurityMonitoringUIReadModel
from .version import DISPLAY_VERSION, RELEASE_GENERATION, VERSION_SCHEME
from .workflow_design import WorkflowDesignCompilerV4
from .workflow_state_machine import WorkflowStateError
from .workflow_state_machine_v4 import (
    EXECUTION_PROFILE_V4,
    WORKFLOW_V4_MAX_PARALLEL_BRANCHES,
    WORKFLOW_V4_MAX_PARALLEL_WORKERS,
    WORKFLOW_V4_MAX_WALL_TIME_MS,
)
from .workflow_state_machine_v4_budgeted import BudgetedWorkflowStateMachineV4Controller
from .workspace_external_identity import (
    ExternalAuthSettings,
    ExternalIdentityStore,
    ExternalSessionAuthStore,
)
from .workspace_frontend_v13 import WORKSPACE_HTML_V13


HTML_V17 = WORKSPACE_HTML_V13


class WorkflowV4ContextApplication(WorkflowV3Application):
    """Current context-aware chat plus bounded V4 and read-only security monitoring."""

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
        self.workflow_designer = WorkflowDesignCompilerV4(service.orchestrator.llm)
        self.workflow_v4 = BudgetedWorkflowStateMachineV4Controller(service.orchestrator)
        # Inherited V3 mutation handlers address app.workflow_v3. Point that stable
        # HTTP boundary at the sole production V4 controller rather than retaining
        # a second executable workflow runtime.
        self.workflow_v3 = self.workflow_v4
        # The Security Analyst UI reads one validated monitoring config at startup.
        # It does not discover paths, open a write connection, or acquire monitoring
        # execution authority from the chat process.
        self.security_monitoring = SecurityMonitoringUIReadModel.from_environment()


class WorkflowV4ContextHTTPHandler(ContextAwareWorkflowV3HTTPHandler):
    """ver.0.0.2: V4 plus current-request output-contract fidelity."""

    server_version = "WorkSpaceChat/ver.0.0.2"

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
            result = self.app.workflow_v4.prepare(
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
                    "code": "BLOCKED_BY_V4_ADMISSION",
                },
            )
        except (RuntimeError, ValueError) as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": redact_sensitive_text(f"{type(exc).__name__}: {exc}")[:400]},
            )

    def _security_get(self, view: str) -> None:
        admin_only = view == "admin"
        if admin_only:
            if self._require_admin() is None:
                return
        elif not self._authorized_local():
            return

        try:
            model = self.app.security_monitoring
            if view == "summary":
                payload = model.summary()
            elif view == "assets":
                payload = model.assets()
            elif view == "admin":
                payload = model.admin_status()
            else:
                query = parse_qs(urlparse(self.path).query, keep_blank_values=False)
                limit = query.get("limit", ["50"])[0]
                offset = query.get("offset", ["0"])[0]
                if view == "network":
                    payload = model.network(limit=limit, offset=offset)
                elif view == "findings":
                    payload = model.findings(limit=limit, offset=offset)
                elif view == "events":
                    payload = model.events(limit=limit, offset=offset)
                elif view == "reports":
                    payload = model.reports(limit=limit, offset=offset)
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "Unknown security view"})
                    return
            self._json(HTTPStatus.OK, payload)
        except (MonitoringContractError, TypeError, ValueError):
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Invalid security query", "code": "SECURITY_QUERY_INVALID"},
            )
        except (OSError, sqlite3.DatabaseError):
            self._json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "Security monitoring data unavailable", "code": "SECURITY_DATA_UNAVAILABLE"},
            )

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            if not self._private_or_reject():
                return
            body = HTML_V17.encode("utf-8")
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
                    "version": DISPLAY_VERSION,
                    "version_scheme": VERSION_SCHEME,
                    "release_generation": RELEASE_GENERATION,
                    "auth": "local_accounts_with_external_identity",
                    "auth_methods": methods,
                    "conversation_lifecycle": True,
                    "projects": True,
                    "external_identity_broker": self.external_settings.enabled,
                    "workflow_studio": True,
                    "workflow_diagrams": ["svg", "mermaid"],
                    "workflow_execution": True,
                    "workflow_execution_version": "v4",
                    "workflow_execution_profile": EXECUTION_PROFILE_V4,
                    "workflow_execution_risk": "low_only",
                    "workflow_execution_trigger": "manual_only",
                    "workflow_schedule_execution": False,
                    "workflow_event_execution": False,
                    "workflow_execution_admin_approval": True,
                    "workflow_pause_resume": True,
                    "workflow_persistent_checkpoint": True,
                    "workflow_branching": "deterministic_only",
                    "workflow_decision_conditions": ["passed", "failed"],
                    "workflow_approval_conditions": ["approved", "rejected"],
                    "workflow_failure_rejection_terminal": True,
                    "workflow_branch_joins": True,
                    "workflow_bounded_parallel_dag": True,
                    "workflow_parallel_regions": 1,
                    "workflow_parallel_max_branches": WORKFLOW_V4_MAX_PARALLEL_BRANCHES,
                    "workflow_parallel_max_workers": WORKFLOW_V4_MAX_PARALLEL_WORKERS,
                    "workflow_parallel_lane_profile": "research_then_presentation",
                    "workflow_parallel_join_policy": "all_children_complete_then_deterministic_validator",
                    "workflow_parallel_budget_scope": "atomic_parent_and_child",
                    "workflow_parallel_budget_dimensions": [
                        "steps",
                        "tool_calls",
                        "retries",
                        "escalations",
                        "wall_time",
                    ],
                    "workflow_parallel_budget_multiplication": False,
                    "workflow_parallel_nested": False,
                    "workflow_parallel_active_replay": False,
                    "workflow_checkpoint_wall_time_ms": WORKFLOW_V4_MAX_WALL_TIME_MS,
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
                    "response_output_contract": OUTPUT_CONTRACT_POLICY_VERSION,
                    "response_output_contract_current_request_only": True,
                    "response_generation_bounded": True,
                    "conversation_context_policy": CONVERSATION_CONTEXT_POLICY_VERSION,
                    "conversation_context_reference_gated": True,
                    "conversation_context_completed_only": True,
                    "conversation_context_max_messages": DEFAULT_CONTEXT_MAX_MESSAGES,
                    "conversation_context_max_chars": DEFAULT_CONTEXT_MAX_CHARS,
                    "standalone_request_history_injected": False,
                    "follow_up_language_continuity": True,
                    "follow_up_reference_anchoring": True,
                },
            )
            return
        security_routes = {
            "/api/security/summary": "summary",
            "/api/security/network": "network",
            "/api/security/findings": "findings",
            "/api/security/events": "events",
            "/api/security/assets": "assets",
            "/api/security/reports": "reports",
            "/api/security/admin": "admin",
        }
        security_view = security_routes.get(path)
        if security_view is not None:
            self._security_get(security_view)
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

    service = ContractAwareProjectChatService(orchestrator, default_language=language)
    service.start()
    app = WorkflowV4ContextApplication(
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
            f"[WorkSpace {DISPLAY_VERSION}] Telegram enabled; authorized users={len(allowed_ids)}.",
            flush=True,
        )
    else:
        print(
            f"[WorkSpace {DISPLAY_VERSION}] Telegram disabled (no bot token configured).",
            flush=True,
        )

    httpd = ThreadingHTTPServer((host, port), WorkflowV4ContextHTTPHandler)
    httpd.app = app  # type: ignore[attr-defined]
    print(f"[WorkSpace {DISPLAY_VERSION}] LAN UI: {_lan_hint(host, port)}", flush=True)
    print(
        f"[WorkSpace {DISPLAY_VERSION}] Local break-glass login enabled; bootstrap administrator={admin['username']}.",
        flush=True,
    )
    if external_settings.enabled:
        print(
            f"[WorkSpace {DISPLAY_VERSION}] External identity login enabled: "
            + ",".join(external_settings.providers)
            + ". Provider authority is identity-only; local RBAC remains authoritative.",
            flush=True,
        )
    else:
        print(
            f"[WorkSpace {DISPLAY_VERSION}] External identity login disabled until broker configuration is provided.",
            flush=True,
        )
    print(
        f"[WorkSpace {DISPLAY_VERSION}] Conversation context remains reference-gated and current-request authoritative ({CONVERSATION_CONTEXT_POLICY_VERSION}).",
        flush=True,
    )
    print(
        f"[WorkSpace {DISPLAY_VERSION}] Direct chat output is bounded by {OUTPUT_CONTRACT_POLICY_VERSION}.",
        flush=True,
    )
    print(
        f"[WorkSpace {DISPLAY_VERSION}] Prompt compiler active: {PROMPT_COMPILER_VERSION}; public query compiler: {PUBLIC_QUERY_COMPILER_VERSION}; strict egress DLP remains final authority.",
        flush=True,
    )
    print(
        f"[WorkSpace {DISPLAY_VERSION}] Workflow V4 enabled: one bounded two-lane parallel DAG with atomic aggregate parent/child execution budgets. Scheduler/event authority remains disabled.",
        flush=True,
    )
    print(
        f"[WorkSpace {DISPLAY_VERSION}] Security Analyst UI enabled as authenticated query-only local view; monitoring execution authority remains separate.",
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
