from __future__ import annotations

import json
from http import HTTPStatus
from typing import Any
from urllib.parse import urlparse

from . import chat_gateway_v17 as _v17
from . import chat_gateway_v21 as _v21
from .security_monitoring.asset_onboarding import (
    SecurityAssetOnboardingConflict,
    SecurityMonitoringAssetOnboarding,
)
from .security_monitoring.contracts import MonitoringContractError
from .workspace_frontend_v18 import WORKSPACE_HTML_V18


class ApprovedAssetApplication(_v21.SecurityE2EApplication):
    """V21 runtime plus typed approved-asset configuration mutations."""

    def __init__(
        self,
        service: Any,
        auth: Any,
        artifact_root: Any,
        external_store: Any,
        external_settings: Any,
    ) -> None:
        super().__init__(service, auth, artifact_root, external_store, external_settings)
        self.security_assets = SecurityMonitoringAssetOnboarding(self.security_config)


class ApprovedAssetHTTPHandler(_v21.SecurityE2EHTTPHandler):
    """Admin-only exact asset onboarding; configuration changes never execute network actions."""

    server_version = "WorkSpaceChat/ver.0.0.2-security-assets-v1"

    def _security_asset_snapshot(self) -> None:
        if self._require_admin() is None:
            return
        try:
            self._json(HTTPStatus.OK, self.app.security_assets.snapshot())
        except (MonitoringContractError, OSError, ValueError, json.JSONDecodeError) as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {
                    "error": str(exc)[:240] or "Approved asset inventory unavailable",
                    "code": "SECURITY_ASSET_INVENTORY_INVALID",
                },
            )

    def _security_asset_post(self, action: str) -> None:
        admin = self._require_admin()
        if admin is None:
            return
        try:
            payload = self._read_json_large(64 * 1024)
            expected = str(payload.get("expected_config_fingerprint") or "")
            confirmation = str(payload.get("confirmation") or "")
            if action == "upsert":
                result = self.app.security_assets.upsert(
                    payload.get("asset"),
                    actor_id=str(admin["user_id"]),
                    expected_config_fingerprint=expected,
                    confirmation=confirmation,
                )
            elif action == "disable":
                result = self.app.security_assets.disable(
                    str(payload.get("asset_id") or ""),
                    actor_id=str(admin["user_id"]),
                    expected_config_fingerprint=expected,
                    confirmation=confirmation,
                )
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "Unknown approved asset action"})
                return
            self.app.refresh_security_monitoring()
            self._json(HTTPStatus.OK, result.public_dict())
        except SecurityAssetOnboardingConflict:
            self._json(
                HTTPStatus.CONFLICT,
                {
                    "error": "Approved asset configuration changed; reload before retrying",
                    "code": "SECURITY_ASSET_CONFIG_STALE",
                },
            )
        except PermissionError:
            self._json(
                HTTPStatus.FORBIDDEN,
                {
                    "error": "Strong confirmation is required for this monitoring authority change",
                    "code": "REAL_NETWORK_CONFIRMATION_REQUIRED",
                },
            )
        except (MonitoringContractError, OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {
                    "error": str(exc)[:240] or "Approved asset mutation rejected",
                    "code": "SECURITY_ASSET_REJECTED",
                },
            )

    def do_GET(self) -> None:
        if urlparse(self.path).path == "/api/security/assets/config":
            self._security_asset_snapshot()
            return
        super().do_GET()

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/security/assets/upsert":
            self._security_asset_post("upsert")
            return
        if path == "/api/security/assets/disable":
            self._security_asset_post("disable")
            return
        super().do_POST()


# V21/V17 remain intact rollback boundaries. V22 only swaps the final composed
# application/handler/document consumed by the existing local gateway bootstrap.
_v17.HTML_V17 = WORKSPACE_HTML_V18
_v17.ContractAwareProjectChatService = _v21.SecurityAwareProjectChatService
_v17.WorkflowV4ContextApplication = ApprovedAssetApplication
_v17.WorkflowV4ContextHTTPHandler = ApprovedAssetHTTPHandler


def main() -> int:
    return _v17.main()


if __name__ == "__main__":
    raise SystemExit(main())
