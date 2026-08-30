from __future__ import annotations

import base64
import os
import threading
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .chat_gateway import (
    SESSION_TTL_SECONDS,
    TelegramBridge,
    _lan_hint,
    _parse_allowed_ids,
)
from .chat_gateway_v2 import ProgressApplication
from .chat_gateway_v4 import (
    MAX_UPLOAD_REQUEST_BYTES,
    _recent_uploads,
    _validate_owned_uploads,
    _validate_request_options,
)
from .chat_gateway_v5 import (
    SidebarKnowledgeChatService,
    SidebarKnowledgeHTTPHandler,
    _history_owner_key,
)
from .config import load_config
from .knowledge_gateway import (
    MAX_UPLOAD_BYTES,
    MAX_UPLOADS_PER_TASK,
    UploadSecurityError,
)
from .orchestrator import Orchestrator
from .privacy import redact_sensitive_text
from .workspace_auth import WorkspaceAuthStore
from .workspace_frontend_v3 import WORKSPACE_HTML_V3

HTML_V6 = WORKSPACE_HTML_V3


class AccountKnowledgeHTTPHandler(SidebarKnowledgeHTTPHandler):
    server_version = "WorkSpaceChat/0.7"

    @property
    def auth(self) -> WorkspaceAuthStore:
        return self.app.sessions

    def _current_user(self) -> dict[str, Any] | None:
        return self.auth.user_for_session(self._session_id(), self.client_address[0])

    def _identity(self, user: dict[str, Any] | None = None) -> str:
        current = user or self._current_user()
        if current is None:
            raise PermissionError("Authentication required")
        return "workspace-user:" + str(current["user_id"])

    def _owner_key(self) -> str:
        return _history_owner_key("web", self._identity())

    def _authorized_local(self) -> bool:
        if not self._private_or_reject():
            return False
        if self._current_user() is None:
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required"})
            return False
        return True

    def _require_admin(self) -> dict[str, Any] | None:
        if not self._authorized_local():
            return None
        user = self._current_user()
        if user is None:
            return None
        if user.get("role") != "admin":
            self._json(HTTPStatus.FORBIDDEN, {"error": "Administrator role required"})
            return None
        return user

    def _claim_legacy_history(self, user: dict[str, Any]) -> int:
        """Move old IP-scoped history only to the bootstrap administrator."""
        if not self.auth.is_bootstrap_admin(str(user["user_id"])):
            return 0
        legacy_owner = _history_owner_key("web", self.client_address[0])
        user_owner = _history_owner_key("web", self._identity(user))
        if legacy_owner == user_owner:
            return 0
        with self.app.service.history.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                "UPDATE chat_conversations SET owner_key=? WHERE owner_key=?",
                (user_owner, legacy_owner),
            )
            return max(0, int(cursor.rowcount or 0))

    def _login(self) -> None:
        if not self._private_or_reject():
            return
        try:
            payload = self._read_json_large(64 * 1024)
            username = str(
                payload.get("username")
                or os.getenv("WORKSPACE_ADMIN_USERNAME", "admin")
            )
            password = str(payload.get("password") or payload.get("token") or "")
            result = self.auth.login(username, password, self.client_address[0])
            if result is None:
                self._json(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": "Invalid username or password"},
                )
                return
            session_token, user = result
            migrated = self._claim_legacy_history(user)
            cookie = (
                f"three_agent_session={session_token}; HttpOnly; SameSite=Strict; "
                f"Path=/; Max-Age={SESSION_TTL_SECONDS}"
            )
            self._json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "user": user,
                    "legacy_history_migrated": migrated,
                },
                {"Set-Cookie": cookie},
            )
        except ValueError as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": redact_sensitive_text(str(exc))[:400]},
            )

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            if not self._private_or_reject():
                return
            body = HTML_V6.encode("utf-8")
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
            self._json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "service": "WorkSpace Chat",
                    "version": "0.7",
                    "auth": "local_accounts",
                },
            )
            return
        if path == "/api/session":
            if not self._authorized_local():
                return
            user = self._current_user()
            if user is None:
                return
            payload = dict(user)
            payload["subtitle"] = (
                "Administrator"
                if user["role"] == "admin"
                else (user.get("department") or "WorkSpace user")
            )
            payload["account_scope"] = "local_account"
            self._json(HTTPStatus.OK, payload)
            return
        if path == "/api/users":
            if self._require_admin() is None:
                return
            self._json(HTTPStatus.OK, {"users": self.auth.list_users()})
            return
        if path == "/api/uploads":
            if not self._authorized_local():
                return
            user = self._current_user()
            if user is None:
                return
            self._json(
                HTTPStatus.OK,
                {
                    "uploads": _recent_uploads(
                        self.app.service.orchestrator.knowledge_gateway,
                        self._identity(user),
                    )
                },
            )
            return
        super().do_GET()

    def _create_user(self) -> None:
        if self._require_admin() is None:
            return
        try:
            payload = self._read_json_large(64 * 1024)
            user = self.auth.create_user(
                username=str(payload.get("username") or ""),
                password=str(payload.get("password") or ""),
                display_name=str(payload.get("display_name") or ""),
                department=str(payload.get("department") or ""),
                title=str(payload.get("title") or ""),
                role=str(payload.get("role") or "user"),
            )
            self._json(HTTPStatus.CREATED, {"user": user})
        except ValueError as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": redact_sensitive_text(str(exc))[:400]},
            )

    def _update_user(self, user_id: str) -> None:
        if self._require_admin() is None:
            return
        try:
            payload = self._read_json_large(64 * 1024)
            kwargs: dict[str, Any] = {}
            for key in ("display_name", "department", "title", "role"):
                if key in payload:
                    kwargs[key] = str(payload.get(key) or "")
            if "enabled" in payload:
                if not isinstance(payload["enabled"], bool):
                    raise ValueError("enabled must be a boolean")
                kwargs["enabled"] = payload["enabled"]
            if "new_password" in payload and str(payload["new_password"] or ""):
                kwargs["new_password"] = str(payload["new_password"])
            user = self.auth.update_user(user_id, **kwargs)
            self._json(HTTPStatus.OK, {"user": user})
        except KeyError:
            self._json(HTTPStatus.NOT_FOUND, {"error": "User not found"})
        except ValueError as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": redact_sensitive_text(str(exc))[:400]},
            )

    def _change_password(self) -> None:
        if not self._authorized_local():
            return
        user = self._current_user()
        if user is None:
            return
        try:
            payload = self._read_json_large(32 * 1024)
            self.auth.change_password(
                str(user["user_id"]),
                str(payload.get("current_password") or ""),
                str(payload.get("new_password") or ""),
            )
            self._json(
                HTTPStatus.OK,
                {"status": "password_changed", "reauthentication_required": True},
                {
                    "Set-Cookie": (
                        "three_agent_session=; HttpOnly; SameSite=Strict; "
                        "Path=/; Max-Age=0"
                    )
                },
            )
        except ValueError as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": redact_sensitive_text(str(exc))[:400]},
            )

    def _upload(self) -> None:
        if not self._authorized_local():
            return
        user = self._current_user()
        if user is None:
            return
        try:
            payload = self._read_json_large(MAX_UPLOAD_REQUEST_BYTES)
            encoded = str(payload.get("data_base64") or "")
            if not encoded:
                raise UploadSecurityError("Upload body is empty")
            try:
                data = base64.b64decode(encoded, validate=True)
            except Exception as exc:
                raise UploadSecurityError("Upload is not valid base64") from exc
            if len(data) > MAX_UPLOAD_BYTES:
                raise UploadSecurityError("Upload exceeds 16 MiB per-file limit")
            record = self.app.service.orchestrator.knowledge_gateway.ingest_upload(
                str(payload.get("name") or ""),
                data,
                content_type=str(payload.get("type") or ""),
                sender=self._identity(user),
            )
            response = record.public_dict()
            response["status"] = "accepted"
            self._json(HTTPStatus.CREATED, response)
        except (ValueError, UploadSecurityError) as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": redact_sensitive_text(str(exc))[:800]},
            )

    def _chat(self) -> None:
        if not self._authorized_local():
            return
        user = self._current_user()
        if user is None:
            return
        try:
            payload = self._read_json_large(128 * 1024)
            message = str(payload.get("message") or "")
            language = str(
                payload.get("language") or self.app.service.default_language
            )
            if language not in {"ja", "vi", "en"}:
                raise ValueError("Unsupported response language")
            fmt = str(payload.get("format") or "source")
            if fmt not in {"source", "pptx", "pdf", "all"}:
                raise ValueError("Unsupported output format")
            mode, effort = _validate_request_options(
                payload.get("mode"),
                payload.get("effort"),
                self.app.service.orchestrator.config,
            )
            raw_uploads = payload.get("upload_ids") or []
            if not isinstance(raw_uploads, list):
                raise UploadSecurityError("upload_ids must be an array")
            if len(raw_uploads) > MAX_UPLOADS_PER_TASK:
                raise UploadSecurityError(
                    f"At most {MAX_UPLOADS_PER_TASK} uploads may be attached to one task"
                )
            identity = self._identity(user)
            upload_ids = _validate_owned_uploads(
                self.app.service.orchestrator.knowledge_gateway,
                [str(item) for item in raw_uploads],
                identity,
            )
            raw_conversation = str(payload.get("conversation_id") or "").strip()
            conversation_id = raw_conversation or None
            prefix = "" if fmt == "source" else f"/{fmt} "
            job = self.app.service.submit(
                prefix + message,
                channel="web",
                sender=identity,
                language=language,
                upload_ids=upload_ids,
                request_mode=mode,
                effort=effort,
                conversation_id=conversation_id,
            )
            response = job.public_dict()
            response["conversation_id"] = self.app.service.conversation_for_job(job.job_id)
            self._json(HTTPStatus.ACCEPTED, response)
        except (ValueError, UploadSecurityError) as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": redact_sensitive_text(str(exc))[:800]},
            )

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/login":
            self._login()
            return
        if path == "/api/users":
            self._create_user()
            return
        if path == "/api/account/password":
            self._change_password()
            return
        if path == "/api/upload":
            self._upload()
            return
        if path == "/api/chat":
            self._chat()
            return
        if path.startswith("/api/users/"):
            parts = [part for part in path.split("/") if part]
            if len(parts) == 3:
                self._update_user(parts[2])
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
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

    auth = WorkspaceAuthStore(config.database_path)
    auth.initialize()
    admin = auth.bootstrap_admin(
        admin_username,
        admin_password,
        display_name=admin_display_name,
        department=os.getenv("WORKSPACE_ADMIN_DEPARTMENT", ""),
        title=os.getenv("WORKSPACE_ADMIN_TITLE", "Administrator"),
    )

    service = SidebarKnowledgeChatService(orchestrator, default_language=language)
    service.start()
    app = ProgressApplication(service, auth, config.artifact_root)

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

    httpd = ThreadingHTTPServer((host, port), AccountKnowledgeHTTPHandler)
    httpd.app = app  # type: ignore[attr-defined]
    print(f"[WorkSpace] LAN UI: {_lan_hint(host, port)}", flush=True)
    print(
        f"[WorkSpace] Local accounts enabled; bootstrap administrator={admin['username']}.",
        flush=True,
    )
    print(
        "[WorkSpace] Passwords use local scrypt hashes; sessions are IP-bound and fail closed.",
        flush=True,
    )
    print(
        "[WorkSpace] User chat history and upload ownership are account-scoped.",
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
