from __future__ import annotations

import sqlite3
from http import HTTPStatus
from pathlib import Path
from urllib.parse import urlparse

from . import chat_gateway_v17 as _v17
from .chat_gateway_v21 import (
    SecurityAwareProjectChatService,
    SecurityE2EApplication,
    SecurityE2EHTTPHandler,
)
from .security_monitoring.contracts import MonitoringContractError
from .security_monitoring.locking import MonitoringRunAlreadyLocked
from .security_monitoring.service import SecurityMonitoringService
from .workspace_frontend_security_actions_v1 import WORKSPACE_HTML_SECURITY_ACTIONS_V1


READONLY_MONITORING_CONFIRMATION = "RUN_READONLY_MONITORING"
READONLY_MONITORING_ACTION_HEADER = "security-readonly-monitoring"


def _runtime_block_code(exc: RuntimeError) -> str:
    value = str(exc)
    if value == "MONITORING_DISABLED":
        return "MONITORING_DISABLED"
    if value == "REAL_NETWORK_NOT_ALLOWED_BY_CONFIG":
        return "REAL_NETWORK_NOT_ALLOWED_BY_CONFIG"
    if value == "EXPLICIT_READONLY_EXECUTION_FLAG_REQUIRED":
        return "EXPLICIT_READONLY_EXECUTION_FLAG_REQUIRED"
    if value.startswith("MONITORING_READINESS_BLOCKED:"):
        return "MONITORING_READINESS_BLOCKED"
    return "SECURITY_MONITORING_RUN_BLOCKED"


class SecurityActionHTTPHandler(SecurityE2EHTTPHandler):
    """V21 plus one admin-confirmed, server-scoped read-only monitoring action."""

    server_version = "WorkSpaceChat/ver.0.0.2-security-actions-v1"

    def _security_run_readonly(self) -> None:
        if self._require_admin() is None:
            return

        if self.headers.get("X-Workspace-Action", "") != READONLY_MONITORING_ACTION_HEADER:
            self._json(
                HTTPStatus.FORBIDDEN,
                {
                    "error": "Explicit WorkSpace action confirmation is required",
                    "code": "SECURITY_ACTION_HEADER_REQUIRED",
                },
            )
            return

        try:
            payload = self._read_json_large(1024)
        except (TypeError, ValueError):
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Invalid monitoring action request", "code": "SECURITY_ACTION_INVALID"},
            )
            return

        if set(payload) != {"confirmation"} or str(payload.get("confirmation") or "") != READONLY_MONITORING_CONFIRMATION:
            self._json(
                HTTPStatus.FORBIDDEN,
                {
                    "error": "Explicit read-only monitoring confirmation is required",
                    "code": "READONLY_MONITORING_CONFIRMATION_REQUIRED",
                },
            )
            return

        config_path = Path(self.app.security_config.path)
        if not config_path.is_absolute() or config_path.is_symlink() or not config_path.is_file():
            self._json(
                HTTPStatus.CONFLICT,
                {
                    "error": "Monitoring configuration is unavailable",
                    "code": "MONITORING_CONFIG_UNAVAILABLE",
                },
            )
            return

        try:
            receipt = SecurityMonitoringService(config_path).run_hourly(execute_readonly=True)
            self.app.refresh_security_monitoring()
            self._json(
                HTTPStatus.OK,
                {
                    "status": "completed",
                    "read_only": True,
                    "server_configured_scope": True,
                    "receipt": receipt,
                },
            )
        except MonitoringRunAlreadyLocked:
            self._json(
                HTTPStatus.CONFLICT,
                {
                    "error": "A monitoring run is already active for this slot",
                    "code": "HOURLY_SLOT_ALREADY_LOCKED",
                },
            )
        except RuntimeError as exc:
            self._json(
                HTTPStatus.CONFLICT,
                {
                    "error": "Read-only monitoring is blocked by runtime policy or readiness",
                    "code": _runtime_block_code(exc),
                },
            )
        except (MonitoringContractError, OSError, ValueError, sqlite3.DatabaseError):
            self._json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "error": "Read-only monitoring could not complete safely",
                    "code": "SECURITY_MONITORING_RUN_UNAVAILABLE",
                },
            )

    def do_POST(self) -> None:
        if urlparse(self.path).path == "/api/security/monitoring/run-readonly":
            self._security_run_readonly()
            return
        super().do_POST()


# V21 remains an intact rollback boundary. V22 only adds the explicit operator
# action route and its matching frontend surface; chat/AI authority is unchanged.
_v17.HTML_V17 = WORKSPACE_HTML_SECURITY_ACTIONS_V1
_v17.ContractAwareProjectChatService = SecurityAwareProjectChatService
_v17.WorkflowV4ContextApplication = SecurityE2EApplication
_v17.WorkflowV4ContextHTTPHandler = SecurityActionHTTPHandler


def main() -> int:
    return _v17.main()


if __name__ == "__main__":
    raise SystemExit(main())
