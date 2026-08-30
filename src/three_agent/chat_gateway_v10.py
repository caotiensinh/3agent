from __future__ import annotations

import os
import threading
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .chat_gateway import SESSION_TTL_SECONDS, TelegramBridge, _lan_hint, _parse_allowed_ids
from .chat_gateway_v2 import ProgressApplication
from .chat_gateway_v8 import ProjectKnowledgeChatService
from .chat_gateway_v9 import ProjectUIHTTPHandler
from .config import load_config
from .orchestrator import Orchestrator
from .privacy import redact_sensitive_text
from .workspace_external_identity import (
    ExternalAuthSettings,
    ExternalIdentityStore,
    ExternalSessionAuthStore,
    IdentityBrokerClient,
)
from .workspace_frontend_v7 import WORKSPACE_HTML_V7

HTML_V10 = WORKSPACE_HTML_V7


class ExternalAuthApplication(ProgressApplication):
    def __init__(
        self,
        service: Any,
        auth: ExternalSessionAuthStore,
        artifact_root,
        external_store: ExternalIdentityStore,
        external_settings: ExternalAuthSettings,
    ) -> None:
        super().__init__(service, auth, artifact_root)
        self.external_store = external_store
        self.external_settings = external_settings
        self.identity_broker = IdentityBrokerClient(external_settings)


class FourWayLoginHTTPHandler(ProjectUIHTTPHandler):
    server_version = "WorkSpaceChat/0.11"

    @property
    def auth(self) -> ExternalSessionAuthStore:
        return self.app.sessions

    @property
    def external_store(self) -> ExternalIdentityStore:
        return self.app.external_store

    @property
    def external_settings(self) -> ExternalAuthSettings:
        return self.app.external_settings

    def _session_cookie(self, token: str) -> str:
        return (
            f"three_agent_session={token}; HttpOnly; SameSite=Strict; "
            f"Path=/; Max-Age={SESSION_TTL_SECONDS}"
        )

    def _external_login(self) -> None:
        if not self._private_or_reject():
            return
        if not self.external_settings.enabled:
            self._json(HTTPStatus.NOT_FOUND, {"error": "External login is not configured"})
            return
        try:
            payload = self._read_json_large(16 * 1024)
            assertion = self.app.identity_broker.redeem(str(payload.get("ticket") or ""))
            identity = self.external_store.record_assertion(
                assertion["provider"], assertion["external_key"], assertion["display_name"]
            )
            status = str(identity["status"])
            if status == "rejected":
                self._json(
                    HTTPStatus.FORBIDDEN,
                    {"error": "This external identity is not approved for WorkSpace"},
                )
                return
            if status != "approved" or not identity.get("user_id"):
                self._json(
                    HTTPStatus.ACCEPTED,
                    {
                        "status": "pending",
                        "provider": identity["provider"],
                        "identity_id": identity["identity_id"],
                        "approval_required": True,
                    },
                )
                return
            token, user = self.auth.issue_session_for_user(
                str(identity["user_id"]), self.client_address[0]
            )
            self._json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "user": user,
                    "login_method": identity["provider"],
                },
                {"Set-Cookie": self._session_cookie(token)},
            )
        except (ValueError, PermissionError) as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": redact_sensitive_text(str(exc))[:400]},
            )
        except RuntimeError as exc:
            self._json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": redact_sensitive_text(str(exc))[:400]},
            )

    def _approve_external(self, identity_id: str) -> None:
        if self._require_admin() is None:
            return
        try:
            payload = self._read_json_large(16 * 1024)
            identity = self.external_store.approve(
                identity_id, str(payload.get("user_id") or "")
            )
            self._json(HTTPStatus.OK, {"identity": identity})
        except KeyError:
            self._json(HTTPStatus.NOT_FOUND, {"error": "External identity not found"})
        except ValueError as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": redact_sensitive_text(str(exc))[:400]},
            )

    def _reject_external(self, identity_id: str) -> None:
        if self._require_admin() is None:
            return
        try:
            identity = self.external_store.reject(identity_id)
            self._json(HTTPStatus.OK, {"identity": identity})
        except (KeyError, ValueError):
            self._json(HTTPStatus.NOT_FOUND, {"error": "External identity not found"})

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            if not self._private_or_reject():
                return
            body = HTML_V10.encode("utf-8")
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
                    "version": "0.11",
                    "auth": "local_accounts_with_external_identity",
                    "auth_methods": methods,
                    "conversation_lifecycle": True,
                    "projects": True,
                    "external_identity_broker": self.external_settings.enabled,
                },
            )
            return
        if path == "/api/auth/providers":
            if not self._private_or_reject():
                return
            self._json(
                HTTPStatus.OK,
                {
                    "local": True,
                    "external": list(self.external_settings.providers),
                    "broker_url": self.external_settings.browser_base_url,
                    "external_authority": "identity_only",
                },
            )
            return
        if path == "/api/external-identities":
            if self._require_admin() is None:
                return
            self._json(
                HTTPStatus.OK,
                {"identities": self.external_store.list_identities()},
            )
            return
        super().do_GET()

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/external/login":
            self._external_login()
            return
        if path.startswith("/api/external-identities/"):
            parts = [part for part in path.split("/") if part]
            if len(parts) == 4 and parts[3] == "approve":
                self._approve_external(parts[2])
                return
            if len(parts) == 4 and parts[3] == "reject":
                self._reject_external(parts[2])
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
    app = ExternalAuthApplication(
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

    httpd = ThreadingHTTPServer((host, port), FourWayLoginHTTPHandler)
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
        print("[WorkSpace] External identity login disabled until broker configuration is provided.", flush=True)
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
