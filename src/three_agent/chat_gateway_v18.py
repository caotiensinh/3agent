from __future__ import annotations

import os
import threading
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .chat_gateway import TelegramBridge, _lan_hint, _parse_allowed_ids
from .chat_gateway_v16 import ContextAwareProjectChatService
from .chat_gateway_v17 import (
    HTML_V17,
    WorkflowV4ContextApplication,
    WorkflowV4ContextHTTPHandler,
)
from .config import load_config
from .orchestrator import Orchestrator
from .security_monitoring.contracts import MonitoringContractError
from .security_monitoring.incident_capture import (
    IncidentCapturePolicy,
    approve_capture_request,
    persist_capture_approval,
)
from .version import DISPLAY_VERSION
from .workspace_external_identity import (
    ExternalAuthSettings,
    ExternalIdentityStore,
    ExternalSessionAuthStore,
)


HTML_V18 = HTML_V17
PCAP_APPROVAL_CONFIRMATION = "APPROVE_PCAP"


class SecurityApprovalApplication(WorkflowV4ContextApplication):
    """Read-only Security Analyst plus admin-only incident-capture approval metadata."""

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
        try:
            self.security_pcap_policy = IncidentCapturePolicy.from_environment()
            self.security_pcap_state = "configured"
        except (MonitoringContractError, OSError, ValueError):
            # Optional PCAP misconfiguration must fail closed without taking down chat.
            self.security_pcap_policy = None
            self.security_pcap_state = "configuration_error"


class SecurityApprovalHTTPHandler(WorkflowV4ContextHTTPHandler):
    """ver.0.0.1 admin approval boundary; packet execution remains out-of-process."""

    def _security_pcap_status(self) -> None:
        if self._require_admin() is None:
            return
        policy = self.app.security_pcap_policy
        self._json(
            HTTPStatus.OK,
            {
                "status": self.app.security_pcap_state,
                "enabled": bool(policy.enabled) if policy is not None else False,
                "approved_interface_count": len(policy.approved_interfaces) if policy else 0,
                "admin_approval_required": True,
                "approval_confirmation": PCAP_APPROVAL_CONFIRMATION,
                "execution_in_web": False,
                "dedicated_runner_required": True,
                "model_authority": False,
            },
        )

    def _security_pcap_approve(self) -> None:
        admin = self._require_admin()
        if admin is None:
            return
        config = self.app.security_monitoring.config
        policy = self.app.security_pcap_policy
        if config is None:
            self._json(
                HTTPStatus.CONFLICT,
                {"error": "Monitoring configuration unavailable", "code": "PCAP_MONITORING_CONFIG_UNAVAILABLE"},
            )
            return
        if policy is None:
            self._json(
                HTTPStatus.CONFLICT,
                {"error": "Incident capture configuration unavailable", "code": "PCAP_CONFIGURATION_ERROR"},
            )
            return
        if not policy.enabled:
            self._json(
                HTTPStatus.FORBIDDEN,
                {"error": "Incident capture is disabled", "code": "PCAP_DISABLED"},
            )
            return
        try:
            payload = self._read_json_large(16 * 1024)
            confirmation = str(payload.pop("confirmation", ""))
            if confirmation != PCAP_APPROVAL_CONFIRMATION:
                raise PermissionError("PCAP_APPROVAL_CONFIRMATION_REQUIRED")
            approval = approve_capture_request(
                payload,
                approver_user_id=str(admin["user_id"]),
                policy=policy,
                config=config,
            )
            persist_capture_approval(approval, policy=policy)
            self._json(
                HTTPStatus.CREATED,
                {
                    "status": "approved",
                    "approval": approval.public_dict(),
                    "execution": "dedicated_runner_required",
                },
            )
        except PermissionError as exc:
            self._json(
                HTTPStatus.FORBIDDEN,
                {"error": "Incident capture approval denied", "code": str(exc)[:80]},
            )
        except (MonitoringContractError, TypeError, ValueError, OSError):
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Invalid incident capture request", "code": "PCAP_REQUEST_INVALID"},
            )

    def do_GET(self) -> None:
        if urlparse(self.path).path == "/api/security/pcap/status":
            self._security_pcap_status()
            return
        super().do_GET()

    def do_POST(self) -> None:
        if urlparse(self.path).path == "/api/security/pcap/approve":
            self._security_pcap_approve()
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

    service = ContextAwareProjectChatService(orchestrator, default_language=language)
    service.start()
    app = SecurityApprovalApplication(
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

    httpd = ThreadingHTTPServer((host, port), SecurityApprovalHTTPHandler)
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
        f"[WorkSpace {DISPLAY_VERSION}] Security incident capture remains disabled by default; web authority is approval-only and execution is delegated to the dedicated bounded runner.",
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
