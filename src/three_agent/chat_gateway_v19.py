from __future__ import annotations

import json
from http import HTTPStatus
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import chat_gateway_v17 as _v17
from . import chat_gateway_v18 as _v18
from .security_monitoring.config_governance import SecurityMonitoringConfigGovernance
from .security_monitoring.contracts import MonitoringContractError
from .security_monitoring.ui_config import ENV_CONFIG, SecurityMonitoringUIConfigManager
from .security_monitoring.ui_read_model import SecurityMonitoringUIReadModel
from .workspace_frontend_v15 import WORKSPACE_HTML_V15


_BASE_APPLICATION = _v18.SecurityMonitoringApplication
_BASE_HANDLER = _v18.SecurityMonitoringHTTPHandler


class SecurityMonitoringConfigApplication(_BASE_APPLICATION):
    """Security monitoring read model plus governed admin configuration boundary."""

    def __init__(
        self,
        service: Any,
        auth: Any,
        artifact_root: Any,
        external_store: Any,
        external_settings: Any,
    ) -> None:
        super().__init__(service, auth, artifact_root, external_store, external_settings)
        self.security_config = SecurityMonitoringUIConfigManager.from_environment()
        self.security_governance = SecurityMonitoringConfigGovernance(self.security_config)
        self.refresh_security_monitoring()

    def refresh_security_monitoring(self) -> None:
        # The manager has an explicit safe default path when the environment
        # variable is absent. Feeding the resolved absolute path to the existing
        # read model keeps one authoritative validation contract after restart.
        self.security_monitoring = SecurityMonitoringUIReadModel.from_environment(
            {ENV_CONFIG: str(self.security_config.path)}
        )


class SecurityMonitoringConfigHTTPHandler(_BASE_HANDLER):
    """Admin config endpoints. They never execute collectors or network actions."""

    @staticmethod
    def _admin_actor(admin: dict[str, Any]) -> str:
        return str(admin.get("user_id") or "local-admin")[:160]

    def _security_config_get(self) -> None:
        if self._require_admin() is None:
            return
        try:
            result = self.app.security_config.get()
            result["governance"] = self.app.security_governance.status()
            self._json(HTTPStatus.OK, result)
        except (MonitoringContractError, OSError, ValueError, json.JSONDecodeError):
            self._json(
                HTTPStatus.BAD_REQUEST,
                {
                    "error": "Security monitoring configuration unavailable or invalid",
                    "code": "SECURITY_CONFIG_INVALID",
                },
            )

    def _security_history_get(self) -> None:
        if self._require_admin() is None:
            return
        try:
            query = parse_qs(urlparse(self.path).query, keep_blank_values=False)
            limit = int(query.get("limit", ["50"])[0])
            self._json(
                HTTPStatus.OK,
                {
                    "governance": self.app.security_governance.status(),
                    "history": self.app.security_governance.history(limit=limit),
                },
            )
        except (MonitoringContractError, TypeError, ValueError):
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Invalid configuration history query", "code": "SECURITY_CONFIG_HISTORY_INVALID"},
            )

    def _governance_blocked_readiness(self, readiness: dict[str, Any]) -> dict[str, Any]:
        governance = self.app.security_governance.status()
        if governance["change_state"] in {"drift", "audit_invalid", "adoption_required"}:
            result = dict(readiness)
            issues = list(result.get("issues") or [])
            issues.append(
                {
                    "code": "CONFIG_GOVERNANCE_BLOCKED",
                    "message": f"Configuration governance state is {governance['change_state']}; resolve it before monitoring.",
                }
            )
            result["issues"] = issues
            result["ready"] = False
            result["status"] = "blocked"
            result["governance"] = governance
            return result
        result = dict(readiness)
        result["governance"] = governance
        return result

    def _security_config_post(self, action: str) -> None:
        admin = self._require_admin()
        if admin is None:
            return
        try:
            payload = self._read_json_large(256 * 1024)
            actor = self._admin_actor(admin)
            if action == "validate":
                result = self.app.security_config.validate(payload.get("config"))
                result["governance"] = self.app.security_governance.status()
            elif action == "readiness":
                result = self._governance_blocked_readiness(self.app.security_config.readiness())
            elif action == "save":
                result = self.app.security_governance.apply_change(
                    payload.get("config"),
                    actor=actor,
                    reason=payload.get("change_reason"),
                    expected_revision=payload.get("expected_revision"),
                )
                self.app.refresh_security_monitoring()
            elif action == "adopt":
                result = self.app.security_governance.adopt_existing(
                    actor=actor,
                    reason=payload.get("change_reason"),
                )
                self.app.refresh_security_monitoring()
            elif action == "rollback":
                result = self.app.security_governance.rollback(
                    payload.get("source_revision"),
                    actor=actor,
                    reason=payload.get("change_reason"),
                    expected_revision=payload.get("expected_revision"),
                )
                self.app.refresh_security_monitoring()
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "Unknown configuration action"})
                return
            self._json(HTTPStatus.OK, result)
        except MonitoringContractError as exc:
            message = str(exc)[:240] or "Monitoring configuration rejected"
            conflict_markers = (
                "revision conflict",
                "drift detected",
                "explicit adoption",
                "audit chain",
                "already has a tracked revision",
            )
            status = HTTPStatus.CONFLICT if any(marker in message.lower() for marker in conflict_markers) else HTTPStatus.BAD_REQUEST
            self._json(status, {"error": message, "code": "SECURITY_CONFIG_REJECTED"})
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            message = str(exc)[:240] or "Monitoring configuration rejected"
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": message, "code": "SECURITY_CONFIG_REJECTED"},
            )

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/security/config":
            self._security_config_get()
            return
        if path == "/api/security/config/history":
            self._security_history_get()
            return
        super().do_GET()

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        actions = {
            "/api/security/config/validate": "validate",
            "/api/security/config/readiness": "readiness",
            "/api/security/config/save": "save",
            "/api/security/config/adopt": "adopt",
            "/api/security/config/rollback": "rollback",
        }
        action = actions.get(path)
        if action is not None:
            self._security_config_post(action)
            return
        super().do_POST()


# Preserve the complete hardened v18 runtime. Only the UI document and the
# application/handler subclasses move forward; v18 remains a rollback boundary.
_v17.HTML_V17 = WORKSPACE_HTML_V15
_v17.WorkflowV4ContextApplication = SecurityMonitoringConfigApplication
_v17.WorkflowV4ContextHTTPHandler = SecurityMonitoringConfigHTTPHandler


def main() -> int:
    return _v17.main()


if __name__ == "__main__":
    raise SystemExit(main())
