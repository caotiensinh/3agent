from __future__ import annotations

import json
import sqlite3
from http import HTTPStatus
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import chat_gateway_v4 as _v4
from . import chat_gateway_v17 as _v17
from .chat_context_v2 import (
    CONTEXT_MODE_FOLLOW_UP,
    DEFAULT_CONTEXT_MAX_CHARS,
    DEFAULT_CONTEXT_MAX_MESSAGES,
    ConversationContextPlan,
    build_conversation_context,
    classify_context_request,
    infer_recent_user_language,
)
from .chat_fidelity import parse_chat_request
from .chat_gateway_v5 import _history_owner_key
from .chat_service_fidelity_v2 import ContractAwareProjectChatService
from .security_monitoring.config_center import SecurityConfigurationStore
from .security_monitoring.contracts import MonitoringContractError
from .security_monitoring.incident_capture import (
    IncidentCapturePolicy,
    approve_capture_request,
    persist_capture_approval,
)
from .security_monitoring.ui_read_model import SecurityMonitoringUIReadModel
from .workspace_frontend_v15 import WORKSPACE_HTML_V15


_BASE_WORKSPACE_UI_CAPABILITIES = _v4.workspace_ui_capabilities
_BASE_WORKFLOW_V4_APPLICATION = _v17.WorkflowV4ContextApplication
_BASE_WORKFLOW_V4_HANDLER = _v17.WorkflowV4ContextHTTPHandler
PCAP_APPROVAL_CONFIRMATION = "APPROVE_PCAP"


def workspace_ui_capabilities(config: Any) -> dict[str, Any]:
    """Add connector discovery metadata without granting execution authority."""
    payload = _BASE_WORKSPACE_UI_CAPABILITIES(config)
    features = payload.setdefault("features", {})
    for name, label in (("figma", "Figma"), ("canva", "Canva"), ("gmail", "Gmail")):
        features[name] = {
            "enabled": False,
            "state_label": "Connect",
            "reason": f"{label} is not configured for WorkSpace web chat. No connector authority has been granted.",
        }
    return payload


class CurrentRequestProjectChatService(ContractAwareProjectChatService):
    """Use current-request language and explicit prior-artifact references only."""

    def _language_for_follow_up(self, message: str, *, channel: str, sender: str, language: str | None, conversation_id: str | None) -> str | None:
        selected = str(language or "auto").strip().lower()
        if selected not in {"", "auto"}:
            return language
        controls = parse_chat_request(message, selected_language="auto", fallback_language=self.default_language)
        if controls.language_source != "fallback":
            return language
        mode, _, cue_language = classify_context_request(controls.text)
        if mode != CONTEXT_MODE_FOLLOW_UP:
            return language
        if cue_language in {"vi", "ja", "en"}:
            return cue_language
        if not conversation_id:
            return language
        try:
            owner_key = _history_owner_key(channel, sender)
            payload = self.history.get_conversation(owner_key, conversation_id)
        except (KeyError, ValueError):
            return language
        inferred = infer_recent_user_language(payload.get("messages", []))
        return inferred or language

    def _context_plan(self, job: Any) -> ConversationContextPlan:
        with self._lock:
            conversation_id = self._job_conversations.get(job.job_id)
        if not conversation_id:
            return build_conversation_context([], job.message, current_job_id=job.job_id)
        try:
            owner_key = _history_owner_key(job.channel, job.sender)
            payload = self.history.get_conversation(owner_key, conversation_id)
        except (KeyError, ValueError):
            return build_conversation_context([], job.message, current_job_id=job.job_id)
        return build_conversation_context(
            payload.get("messages", []), job.message, current_job_id=job.job_id,
            max_chars=DEFAULT_CONTEXT_MAX_CHARS, max_messages=DEFAULT_CONTEXT_MAX_MESSAGES,
        )


class SecurityMonitoringApplication(_BASE_WORKFLOW_V4_APPLICATION):
    """Current WorkSpace runtime with bounded admin config and query-only monitoring."""

    def __init__(self, service: Any, auth: Any, artifact_root: Any, external_store: Any, external_settings: Any) -> None:
        super().__init__(service, auth, artifact_root, external_store, external_settings)
        self.security_monitoring = SecurityMonitoringUIReadModel.from_environment()
        self.security_config_store = SecurityConfigurationStore.from_environment()
        try:
            self.security_pcap_policy = IncidentCapturePolicy.from_environment()
            self.security_pcap_state = "configured"
        except (MonitoringContractError, OSError, ValueError):
            self.security_pcap_policy = None
            self.security_pcap_state = "configuration_error"


class SecurityMonitoringHTTPHandler(_BASE_WORKFLOW_V4_HANDLER):
    """Security Analyst reads plus admin-bounded config/approval metadata."""

    def _security_get(self, view: str) -> None:
        if view == "admin":
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
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Invalid security query", "code": "SECURITY_QUERY_INVALID"})
        except (OSError, sqlite3.DatabaseError):
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Security monitoring data unavailable", "code": "SECURITY_DATA_UNAVAILABLE"})

    def _security_config_get(self) -> None:
        if self._require_admin() is None:
            return
        try:
            self._json(HTTPStatus.OK, self.app.security_config_store.public_state())
        except (MonitoringContractError, OSError, ValueError, json.JSONDecodeError):
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Security configuration unavailable", "code": "SECURITY_CONFIG_UNAVAILABLE"})

    def _security_config_audit(self) -> None:
        if self._require_admin() is None:
            return
        try:
            query = parse_qs(urlparse(self.path).query, keep_blank_values=False)
            limit = query.get("limit", ["50"])[0]
            self._json(HTTPStatus.OK, self.app.security_config_store.audit(limit=limit))
        except (MonitoringContractError, OSError, ValueError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Invalid security configuration audit query", "code": "SECURITY_CONFIG_AUDIT_INVALID"})

    def _security_config_save(self) -> None:
        admin = self._require_admin()
        if admin is None:
            return
        try:
            request = self._read_json_large(80 * 1024)
            if not isinstance(request, dict):
                raise MonitoringContractError("security configuration request must be an object")
            config = request.get("config")
            confirmation = str(request.get("confirmation") or "")
            if not isinstance(config, dict):
                raise MonitoringContractError("config must be an object")
            payload = self.app.security_config_store.save(config, actor_user_id=str(admin["user_id"]), confirmation=confirmation)
            self.app.security_monitoring = SecurityMonitoringUIReadModel.from_environment()
            self._json(HTTPStatus.OK, payload)
        except PermissionError as exc:
            self._json(HTTPStatus.FORBIDDEN, {"error": "Explicit real-network confirmation required", "code": str(exc)[:96]})
        except (MonitoringContractError, TypeError, ValueError, json.JSONDecodeError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Security configuration rejected", "code": "SECURITY_CONFIG_INVALID"})
        except OSError:
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Security configuration could not be committed", "code": "SECURITY_CONFIG_WRITE_FAILED"})

    def _security_pcap_status(self) -> None:
        if self._require_admin() is None:
            return
        policy = self.app.security_pcap_policy
        self._json(HTTPStatus.OK, {
            "status": self.app.security_pcap_state,
            "enabled": bool(policy.enabled) if policy is not None else False,
            "approved_interface_count": len(policy.approved_interfaces) if policy else 0,
            "admin_approval_required": True,
            "approval_confirmation": PCAP_APPROVAL_CONFIRMATION,
            "execution_in_web": False,
            "dedicated_runner_required": True,
            "model_authority": False,
        })

    def _security_pcap_approve(self) -> None:
        admin = self._require_admin()
        if admin is None:
            return
        config = self.app.security_monitoring.config
        policy = self.app.security_pcap_policy
        if config is None:
            self._json(HTTPStatus.CONFLICT, {"error": "Monitoring configuration unavailable", "code": "PCAP_MONITORING_CONFIG_UNAVAILABLE"})
            return
        if policy is None:
            self._json(HTTPStatus.CONFLICT, {"error": "Incident capture configuration unavailable", "code": "PCAP_CONFIGURATION_ERROR"})
            return
        if not policy.enabled:
            self._json(HTTPStatus.FORBIDDEN, {"error": "Incident capture is disabled", "code": "PCAP_DISABLED"})
            return
        try:
            payload = self._read_json_large(16 * 1024)
            confirmation = str(payload.pop("confirmation", ""))
            if confirmation != PCAP_APPROVAL_CONFIRMATION:
                raise PermissionError("PCAP_APPROVAL_CONFIRMATION_REQUIRED")
            approval = approve_capture_request(payload, approver_user_id=str(admin["user_id"]), policy=policy, config=config)
            persist_capture_approval(approval, policy=policy)
            self._json(HTTPStatus.CREATED, {"status": "approved", "approval": approval.public_dict(), "execution": "dedicated_runner_required"})
        except PermissionError as exc:
            self._json(HTTPStatus.FORBIDDEN, {"error": "Incident capture approval denied", "code": str(exc)[:80]})
        except (MonitoringContractError, TypeError, ValueError, OSError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Invalid incident capture request", "code": "PCAP_REQUEST_INVALID"})

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        security_routes = {
            "/api/security/summary": "summary", "/api/security/network": "network",
            "/api/security/findings": "findings", "/api/security/events": "events",
            "/api/security/assets": "assets", "/api/security/reports": "reports",
            "/api/security/admin": "admin",
        }
        view = security_routes.get(path)
        if view is not None:
            self._security_get(view)
            return
        if path == "/api/security/config":
            self._security_config_get()
            return
        if path == "/api/security/config/audit":
            self._security_config_audit()
            return
        if path == "/api/security/pcap/status":
            self._security_pcap_status()
            return
        super().do_GET()

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/security/config":
            self._security_config_save()
            return
        if path == "/api/security/pcap/approve":
            self._security_pcap_approve()
            return
        super().do_POST()


_v4.workspace_ui_capabilities = workspace_ui_capabilities
_v17.workspace_ui_capabilities = workspace_ui_capabilities
_v17.ContractAwareProjectChatService = CurrentRequestProjectChatService
_v17.HTML_V17 = WORKSPACE_HTML_V15
_v17.WorkflowV4ContextApplication = SecurityMonitoringApplication
_v17.WorkflowV4ContextHTTPHandler = SecurityMonitoringHTTPHandler


def main() -> int:
    return _v17.main()


if __name__ == "__main__":
    raise SystemExit(main())
