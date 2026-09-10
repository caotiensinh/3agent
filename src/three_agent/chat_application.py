from __future__ import annotations

import os
import threading

from . import chat_gateway
from .application_bootstrap import build_application_runtime
from .config import load_config


def main() -> int:
    """Start the packaged chat surface through the canonical application composition root."""
    chat_gateway._orchestrator.KnowledgeGateway = chat_gateway.KnowledgeGatewayV2
    config = load_config()
    runtime = build_application_runtime(config)
    orchestrator = runtime.orchestrator
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

    auth = chat_gateway.ExternalSessionAuthStore(config.database_path)
    auth.initialize()
    admin = auth.bootstrap_admin(
        admin_username,
        admin_password,
        display_name=admin_display_name,
        department=os.getenv("WORKSPACE_ADMIN_DEPARTMENT", ""),
        title=os.getenv("WORKSPACE_ADMIN_TITLE", "Administrator"),
    )
    external_store = chat_gateway.ExternalIdentityStore(auth)
    external_store.initialize()
    external_settings = chat_gateway.ExternalAuthSettings.from_env()
    service = chat_gateway.ContinuitySecurityAwareProjectChatService(
        orchestrator,
        default_language=language,
    )
    service.start()
    app = chat_gateway.ApprovedAssetApplication(
        service,
        auth,
        config.artifact_root,
        external_store,
        external_settings,
    )

    telegram_token = os.getenv("THREE_AGENT_TELEGRAM_BOT_TOKEN", "").strip()
    allowed_ids = chat_gateway._parse_allowed_ids(
        os.getenv("THREE_AGENT_TELEGRAM_ALLOWED_USER_IDS", "")
    )
    if telegram_token:
        bridge = chat_gateway.TelegramBridge(
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
            f"[WorkSpace {chat_gateway.DISPLAY_VERSION}] Telegram enabled; authorized users={len(allowed_ids)}.",
            flush=True,
        )
    else:
        print(
            f"[WorkSpace {chat_gateway.DISPLAY_VERSION}] Telegram disabled (no bot token configured).",
            flush=True,
        )

    httpd = chat_gateway.ThreadingHTTPServer(
        (host, port),
        chat_gateway.ApprovedAssetHTTPHandler,
    )
    httpd.app = app
    print(
        f"[WorkSpace {chat_gateway.DISPLAY_VERSION}] LAN UI: {chat_gateway._lan_hint(host, port)}",
        flush=True,
    )
    print(
        f"[WorkSpace {chat_gateway.DISPLAY_VERSION}] Local break-glass login enabled; bootstrap administrator={admin['username']}.",
        flush=True,
    )
    if external_settings.enabled:
        print(
            f"[WorkSpace {chat_gateway.DISPLAY_VERSION}] External identity login enabled: "
            + ",".join(external_settings.providers)
            + ". Provider authority is identity-only; local RBAC remains authoritative.",
            flush=True,
        )
    else:
        print(
            f"[WorkSpace {chat_gateway.DISPLAY_VERSION}] External identity login disabled until broker configuration is provided.",
            flush=True,
        )
    print(
        f"[WorkSpace {chat_gateway.DISPLAY_VERSION}] Conversation context remains reference-gated and current-request authoritative ({chat_gateway.CONVERSATION_CONTEXT_POLICY_VERSION}).",
        flush=True,
    )
    print(
        f"[WorkSpace {chat_gateway.DISPLAY_VERSION}] Direct chat output is bounded by {chat_gateway.OUTPUT_CONTRACT_POLICY_VERSION}.",
        flush=True,
    )
    print(
        f"[WorkSpace {chat_gateway.DISPLAY_VERSION}] Prompt compiler active: {chat_gateway.PROMPT_COMPILER_VERSION}; public query compiler: {chat_gateway.PUBLIC_QUERY_COMPILER_VERSION}; strict egress DLP remains final authority.",
        flush=True,
    )
    print(
        f"[WorkSpace {chat_gateway.DISPLAY_VERSION}] Workflow V4 enabled: one bounded two-lane parallel DAG with atomic aggregate parent/child execution budgets. Scheduler/event authority remains disabled.",
        flush=True,
    )
    print(
        f"[WorkSpace {chat_gateway.DISPLAY_VERSION}] Security Analyst UI enabled as authenticated query-only local view; monitoring execution authority remains separate.",
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
