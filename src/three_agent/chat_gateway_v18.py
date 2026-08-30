from __future__ import annotations

from typing import Any

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
from .workspace_frontend_v13 import WORKSPACE_HTML_V13


_BASE_WORKSPACE_UI_CAPABILITIES = _v4.workspace_ui_capabilities


def workspace_ui_capabilities(config: Any) -> dict[str, Any]:
    """Add connector discovery metadata without granting execution authority."""

    payload = _BASE_WORKSPACE_UI_CAPABILITIES(config)
    features = payload.setdefault("features", {})
    for name, label in (
        ("figma", "Figma"),
        ("canva", "Canva"),
        ("gmail", "Gmail"),
    ):
        features[name] = {
            "enabled": False,
            "state_label": "Connect",
            "reason": (
                f"{label} is not configured for WorkSpace web chat. "
                "No connector authority has been granted."
            ),
        }
    return payload


class CurrentRequestProjectChatService(ContractAwareProjectChatService):
    """Use current-request language and explicit prior-artifact references only."""

    def _language_for_follow_up(
        self,
        message: str,
        *,
        channel: str,
        sender: str,
        language: str | None,
        conversation_id: str | None,
    ) -> str | None:
        selected = str(language or "auto").strip().lower()
        if selected not in {"", "auto"}:
            return language

        controls = parse_chat_request(
            message,
            selected_language="auto",
            fallback_language=self.default_language,
        )
        # Explicit current-message language instructions and current-message
        # language detection always outrank conversation continuity.
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
            payload.get("messages", []),
            job.message,
            current_job_id=job.job_id,
            max_chars=DEFAULT_CONTEXT_MAX_CHARS,
            max_messages=DEFAULT_CONTEXT_MAX_MESSAGES,
        )


# Reuse the fully hardened v17 HTTP/auth/workflow runtime. Only current-request
# language/context behavior, UI document, and disabled connector discovery
# metadata advance here. No connector gets runtime execution authority.
_v4.workspace_ui_capabilities = workspace_ui_capabilities
_v17.workspace_ui_capabilities = workspace_ui_capabilities
_v17.ContractAwareProjectChatService = CurrentRequestProjectChatService
_v17.HTML_V17 = WORKSPACE_HTML_V13


def main() -> int:
    return _v17.main()


if __name__ == "__main__":
    raise SystemExit(main())
