from __future__ import annotations

from typing import Any, Iterable, Sequence

from .chat_context import (
    CONTEXT_MODE_FOLLOW_UP,
    CONTEXT_MODE_STANDALONE,
    ConversationContextPlan,
    infer_recent_user_language,
)
from .chat_context_v2 import classify_context_request

CONTEXT_MODE_CONTINUITY = "continuity"
CONVERSATION_CONTEXT_POLICY_VERSION = "bounded-conversation-continuity/v3"
DEFAULT_CONTEXT_MAX_CHARS = 18_000
DEFAULT_CONTEXT_MAX_MESSAGES = 12
DEFAULT_CONTEXT_PER_MESSAGE_CHARS = 2_400


def _eligible_messages(
    messages: Iterable[dict[str, Any]], *, current_job_id: str
) -> list[dict[str, Any]]:
    current = str(current_job_id or "")
    rows: list[dict[str, Any]] = []
    for raw in messages:
        role = str(raw.get("role") or "")
        if role not in {"user", "assistant"}:
            continue
        if current and str(raw.get("job_id") or "") == current:
            continue
        if str(raw.get("status") or "completed") != "completed":
            continue
        content = str(raw.get("content") or "").strip()
        if content:
            rows.append(raw)
    return rows


def _compact(text: str, limit: int) -> str:
    body = str(text or "").strip()
    maximum = max(80, int(limit))
    if len(body) <= maximum:
        return body
    marker = "\n…[older turn compacted]…\n"
    remaining = maximum - len(marker)
    front = max(32, remaining // 2)
    tail = max(32, remaining - front)
    return body[:front].rstrip() + marker + body[-tail:].lstrip()


def build_conversation_context(
    messages: Sequence[dict[str, Any]],
    current_request: str,
    *,
    current_job_id: str = "",
    max_chars: int = DEFAULT_CONTEXT_MAX_CHARS,
    max_messages: int = DEFAULT_CONTEXT_MAX_MESSAGES,
    per_message_chars: int = DEFAULT_CONTEXT_PER_MESSAGE_CHARS,
) -> ConversationContextPlan:
    explicit_mode, explicit_reason, language_hint = classify_context_request(current_request)
    eligible = _eligible_messages(messages, current_job_id=current_job_id)
    if not eligible:
        return ConversationContextPlan(
            mode=(
                CONTEXT_MODE_FOLLOW_UP
                if explicit_mode == CONTEXT_MODE_FOLLOW_UP
                else CONTEXT_MODE_STANDALONE
            ),
            reason=(
                explicit_reason
                if explicit_mode == CONTEXT_MODE_FOLLOW_UP
                else "no_prior_completed_turn"
            ),
            text="",
            message_count=0,
            source_chars=0,
            language_hint=language_hint,
        )

    total_budget = max(512, int(max_chars))
    message_limit = max(1, min(24, int(max_messages)))
    per_message_limit = max(80, min(total_budget, int(per_message_chars)))
    selected = eligible[-message_limit:]

    packed_reversed: list[tuple[str, str, int]] = []
    used = 0
    for item in reversed(selected):
        role = "PRIOR USER" if str(item.get("role")) == "user" else "PRIOR ASSISTANT"
        raw = str(item.get("content") or "").strip()
        header = f"[{role}]\n"
        separator = 2 if packed_reversed else 0
        available = total_budget - used - separator - len(header)
        if available < 80:
            continue
        body = _compact(raw, min(per_message_limit, available))
        cost = len(header) + len(body) + separator
        if used + cost > total_budget:
            continue
        packed_reversed.append((role, body, len(raw)))
        used += cost

    packed = list(reversed(packed_reversed))
    rendered = "\n\n".join(f"[{role}]\n{body}" for role, body, _ in packed)
    mode = (
        CONTEXT_MODE_FOLLOW_UP
        if explicit_mode == CONTEXT_MODE_FOLLOW_UP
        else CONTEXT_MODE_CONTINUITY
    )
    reason = (
        explicit_reason
        if explicit_mode == CONTEXT_MODE_FOLLOW_UP
        else "same_conversation_recent_turns"
    )
    return ConversationContextPlan(
        mode=mode,
        reason=reason,
        text=rendered,
        message_count=len(packed),
        source_chars=sum(source_chars for _, _, source_chars in packed),
        language_hint=language_hint,
    )


__all__ = [
    "CONTEXT_MODE_CONTINUITY",
    "CONTEXT_MODE_FOLLOW_UP",
    "CONTEXT_MODE_STANDALONE",
    "CONVERSATION_CONTEXT_POLICY_VERSION",
    "DEFAULT_CONTEXT_MAX_CHARS",
    "DEFAULT_CONTEXT_MAX_MESSAGES",
    "DEFAULT_CONTEXT_PER_MESSAGE_CHARS",
    "ConversationContextPlan",
    "build_conversation_context",
    "classify_context_request",
    "infer_recent_user_language",
]
