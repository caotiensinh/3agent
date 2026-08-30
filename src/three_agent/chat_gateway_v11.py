from __future__ import annotations

import os
import threading
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from urllib.parse import urlparse

from .chat_gateway import TelegramBridge, _lan_hint, _parse_allowed_ids
from .chat_gateway_v10 import ExternalAuthApplication, FourWayLoginHTTPHandler
from .chat_gateway_v8 import ProjectKnowledgeChatService
from .config import load_config
from .orchestrator import Orchestrator
from .prompt_compiler import PROMPT_COMPILER_VERSION
from .public_query_compiler import PUBLIC_QUERY_COMPILER_VERSION
from .workspace_external_identity import (
    ExternalAuthSettings,
    ExternalIdentityStore,
    ExternalSessionAuthStore,
)


class PromptCompilerHTTPHandler(FourWayLoginHTTPHandler):
    server_version = "WorkSpaceChat/0.12"

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/health":
            if not self._private_or_reject():
                return
            methods = ["local", *self.external_settings.providers]
            self._json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "service": "WorkSpace Chat",
                    "version": "0.12",
                    "auth": "local_accounts_with_external_identity",
                    "auth_methods": methods,
                    "conversation_lifecycle": True,
                    "projects": True,
                    "external_identity_broker": self.external_settings.enabled,
                    "prompt_compiler": PROMPT_COMPILER_VERSION,
                    "prompt_compiler_authority": "user_task_only",
                    "prompt_compiler_original_local": True,
                    "public_query_compiler": PUBLIC_QUERY_COMPILER_VERSION,
                    "public_query_final_dlp": True,
                },
            )
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

    httpd = ThreadingHTTPServer((host, port), PromptCompilerHTTPHandler)
    httpd.app = app  # type: ignore[attr-defined]
    print(f"[WorkSpace] LAN UI: {_lan_hint(host, port)}", flush=True)
    print(
        f"[WorkSpace] Local break-glass login enabled; bootstrap administrator={admin['username']}.",
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
