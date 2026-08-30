from __future__ import annotations

import os
import threading
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .chat_gateway import TelegramBridge, _lan_hint, _parse_allowed_ids
from .chat_gateway_v2 import ProgressApplication
from .chat_gateway_v5 import SidebarKnowledgeChatService
from .chat_gateway_v6 import AccountKnowledgeHTTPHandler
from .chat_history_v2 import ConversationHistoryStore
from .config import load_config
from .orchestrator import Orchestrator
from .privacy import redact_sensitive_text
from .workspace_auth import WorkspaceAuthStore
from .workspace_frontend_v4 import WORKSPACE_HTML_V4

HTML_V7 = WORKSPACE_HTML_V4


class ConversationKnowledgeChatService(SidebarKnowledgeChatService):
    """Account-scoped chat service with archive-aware conversation history."""

    def __init__(self, orchestrator: Any, default_language: str = "ja") -> None:
        super().__init__(orchestrator, default_language=default_language)
        self.history = ConversationHistoryStore(orchestrator.config.database_path)
        self.history.initialize()


class ConversationKnowledgeHTTPHandler(AccountKnowledgeHTTPHandler):
    server_version = "WorkSpaceChat/0.9"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/":
            if not self._private_or_reject():
                return
            body = HTML_V7.encode("utf-8")
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
                    "version": "0.9",
                    "auth": "local_accounts",
                    "conversation_lifecycle": True,
                },
            )
            return
        if path == "/api/conversations":
            if not self._authorized_local():
                return
            params = parse_qs(parsed.query)
            query = str(params.get("q", [""])[0])[:200]
            view = str(params.get("view", ["active"])[0]).strip().lower()
            if view not in {"active", "archived", "all"}:
                self._json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "view must be active, archived or all"},
                )
                return
            archived: bool | None
            if view == "active":
                archived = False
            elif view == "archived":
                archived = True
            else:
                archived = None
            rows = self.app.service.history.list_conversations(
                self._owner_key(),
                query=query,
                archived=archived,
            )
            self._json(
                HTTPStatus.OK,
                {"conversations": rows, "view": view, "query": query},
            )
            return
        super().do_GET()

    def _conversation_action(self, conversation_id: str, action: str) -> None:
        if not self._authorized_local():
            return
        try:
            if action == "rename":
                payload = self._read_json_large(32 * 1024)
                conversation = self.app.service.history.rename_conversation(
                    self._owner_key(),
                    conversation_id,
                    str(payload.get("title") or ""),
                )
                self._json(HTTPStatus.OK, conversation)
                return
            if action == "archive":
                payload = self._read_json_large(32 * 1024)
                archived = payload.get("archived")
                if not isinstance(archived, bool):
                    raise ValueError("archived must be a boolean")
                conversation = self.app.service.history.set_archived(
                    self._owner_key(),
                    conversation_id,
                    archived,
                )
                self._json(HTTPStatus.OK, conversation)
                return
            if action == "delete":
                self._read_json_large(32 * 1024)
                result = self.app.service.history.delete_conversation(
                    self._owner_key(),
                    conversation_id,
                )
                self._json(HTTPStatus.OK, result)
                return
            self._json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
        except KeyError:
            self._json(HTTPStatus.NOT_FOUND, {"error": "Conversation not found"})
        except ValueError as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": redact_sensitive_text(str(exc))[:400]},
            )

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path.startswith("/api/conversations/"):
            parts = [part for part in path.split("/") if part]
            if len(parts) == 4 and parts[3] in {"rename", "archive", "delete"}:
                self._conversation_action(parts[2], parts[3])
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

    service = ConversationKnowledgeChatService(
        orchestrator,
        default_language=language,
    )
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

    httpd = ThreadingHTTPServer((host, port), ConversationKnowledgeHTTPHandler)
    httpd.app = app  # type: ignore[attr-defined]
    print(f"[WorkSpace] LAN UI: {_lan_hint(host, port)}", flush=True)
    print(
        f"[WorkSpace] Local accounts enabled; bootstrap administrator={admin['username']}.",
        flush=True,
    )
    print(
        "[WorkSpace] Conversation rename/archive/delete are owner-scoped and fail closed.",
        flush=True,
    )
    print(
        "[WorkSpace] Archived conversations must be restored before new messages can be added.",
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
