from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from .chat_fidelity import detect_message_language

CONTEXT_MODE_STANDALONE = "standalone"
CONTEXT_MODE_FOLLOW_UP = "follow_up"

DEFAULT_CONTEXT_MAX_CHARS = 6_000
DEFAULT_CONTEXT_MAX_MESSAGES = 6
DEFAULT_CONTEXT_PER_MESSAGE_CHARS = 1_600


@dataclass(frozen=True)
class ConversationContextPlan:
    mode: str
    reason: str
    text: str
    message_count: int
    source_chars: int
    language_hint: str = ""


# Follow-up classification is deliberately conservative. These cues express a
# dependency on earlier turns rather than merely sharing a topic with them.
_VI_FOLLOW_UP_PATTERNS = (
    r"^(?:rồi\s+)?(?:tiếp\s+theo|tiếp\s+tục)(?:\b|\s|[?.!,;:])",
    r"\b(?:cái|phần|mục|ý|lựa\s+chọn)\s+(?:thứ\s+)?(?:hai|2)\b",
    r"\b(?:phần|đoạn|nội\s+dung|cấu\s+hình|lệnh|code)\s+(?:ở\s+)?(?:trên|bên\s+trên|vừa\s+(?:nói|nêu|đề\s+cập))\b",
    r"\b(?:như|theo)\s+(?:trên|vừa\s+(?:nói|nêu|đề\s+cập))\b",
    r"\b(?:cái|việc|phần)\s+(?:đó|này)\b",
    r"^(?:thế|vậy)\s+(?:còn|thì)\b",
    r"^còn\b.{0,80}\bthì\s+sao\b",
    r"^(?:tại\s+sao|vì\s+sao)\s*[?？!]*$",
    r"\b(?:sửa|đổi|dùng|áp\s+dụng|giữ)\b.{0,60}\b(?:phần\s+trên|ở\s+trên|vừa\s+(?:nói|nêu)|cấu\s+hình\s+vừa\s+nói|cái\s+đó)\b",
)
_EN_FOLLOW_UP_PATTERNS = (
    r"^(?:please\s+)?(?:continue|go\s+on)(?:\b|\s|[?.!,;:])",
    r"^(?:please\s+)?next(?:\s+(?:one|step|part|item|option))?(?:\s*,?\s*please)?\s*[?!.]*$",
    r"\b(?:the\s+)?(?:second|2nd)\s+(?:one|item|option|part|point)\b",
    r"\b(?:the\s+)?(?:above|previous|prior)\s+(?:part|section|answer|config(?:uration)?|command|code|item|one)\b",
    r"\b(?:as|like)\s+(?:above|discussed|mentioned|noted)\b",
    r"\b(?:that|this)\s+(?:one|part|config(?:uration)?|command|code|answer|option)\b",
    r"^(?:what|how)\s+about\b",
    r"^and\s+(?:the\s+)?(?:next|second|other|last|previous)\b",
    r"^why\s*[?？!]*$",
    r"\b(?:use|change|fix|edit|keep|apply)\b.{0,60}\b(?:the\s+)?(?:above|previous|prior|one\s+we\s+(?:discussed|mentioned))\b",
)
_JA_FOLLOW_UP_PATTERNS = (
    r"^(?:では|じゃあ|それでは)?\s*(?:次|次に|続けて|続き)(?:は|を|も|へ|[?？。！!\s]|$)",
    r"(?:2つ目|２つ目|二つ目|第二)(?:の|を|は|について|[?？。！!\s]|$)",
    r"(?:上記|上の|前の|先ほど|さっき)(?:の|と|を|に|で|設定|内容|部分|回答|コマンド|コード)",
    r"(?:それ|その)(?:設定|内容|部分|回答|方法|コマンド|コード|案|項目)",
    r"^(?:それ|その件)(?:は|を|で|について|[?？。！!\s]|$)",
    r"^なぜ\s*[?？!！]*$",
    r"(?:修正|変更|使|適用).{0,32}(?:上記|上の|前の|先ほど|さっき|その設定|その部分)",
)

_LANGUAGE_PATTERNS = {
    "vi": tuple(re.compile(pattern, re.IGNORECASE) for pattern in _VI_FOLLOW_UP_PATTERNS),
    "en": tuple(re.compile(pattern, re.IGNORECASE) for pattern in _EN_FOLLOW_UP_PATTERNS),
    "ja": tuple(re.compile(pattern) for pattern in _JA_FOLLOW_UP_PATTERNS),
}


def _compact_request(value: str) -> str:
    return " ".join(str(value or "").replace("\u3000", " ").split()).strip()


def classify_context_request(request: str) -> tuple[str, str, str]:
    """Return (mode, reason, language_hint) for the current request.

    The classifier never asks an LLM to choose context. A standalone request gets
    no prior chat text. Only explicit cross-turn reference cues unlock bounded
    prior conversation data.
    """

    text = _compact_request(request)
    if not text:
        return CONTEXT_MODE_STANDALONE, "empty_or_missing_reference", ""
    for language in ("vi", "ja", "en"):
        for index, pattern in enumerate(_LANGUAGE_PATTERNS[language], 1):
            if pattern.search(text):
                return CONTEXT_MODE_FOLLOW_UP, f"{language}_reference_{index}", language
    return CONTEXT_MODE_STANDALONE, "no_explicit_cross_turn_reference", ""


def infer_recent_user_language(messages: Sequence[dict[str, Any]]) -> str:
    """Infer language from the newest completed prior user turn only as fallback."""

    for item in reversed(tuple(messages)):
        if str(item.get("role") or "") != "user":
            continue
        if str(item.get("status") or "completed") != "completed":
            continue
        language = detect_message_language(str(item.get("content") or ""))
        if language in {"vi", "ja", "en"}:
            return language
    return ""


def _compact_message(text: str, limit: int) -> str:
    body = str(text or "").strip()
    maximum = max(40, int(limit))
    if len(body) <= maximum:
        return body
    marker = "\n…[deterministically compacted]…\n"
    remaining = maximum - len(marker)
    if remaining <= 24:
        return body[:maximum]
    front = max(12, remaining // 2)
    tail = max(12, remaining - front)
    return body[:front].rstrip() + marker + body[-tail:].lstrip()


def _eligible_messages(
    messages: Iterable[dict[str, Any]],
    *,
    current_job_id: str,
) -> list[dict[str, Any]]:
    eligible: list[dict[str, Any]] = []
    current = str(current_job_id or "")
    for raw in messages:
        role = str(raw.get("role") or "")
        if role not in {"user", "assistant"}:
            continue
        if current and str(raw.get("job_id") or "") == current:
            continue
        if str(raw.get("status") or "completed") != "completed":
            continue
        content = str(raw.get("content") or "").strip()
        if not content:
            continue
        eligible.append(raw)
    return eligible


def build_conversation_context(
    messages: Sequence[dict[str, Any]],
    current_request: str,
    *,
    current_job_id: str = "",
    max_chars: int = DEFAULT_CONTEXT_MAX_CHARS,
    max_messages: int = DEFAULT_CONTEXT_MAX_MESSAGES,
    per_message_chars: int = DEFAULT_CONTEXT_PER_MESSAGE_CHARS,
) -> ConversationContextPlan:
    mode, reason, language_hint = classify_context_request(current_request)
    if mode != CONTEXT_MODE_FOLLOW_UP:
        return ConversationContextPlan(
            mode=mode,
            reason=reason,
            text="",
            message_count=0,
            source_chars=0,
            language_hint=language_hint,
        )

    total_budget = max(256, int(max_chars))
    message_limit = max(1, min(12, int(max_messages)))
    per_message_limit = max(40, min(total_budget, int(per_message_chars)))
    eligible = _eligible_messages(messages, current_job_id=current_job_id)
    selected = eligible[-message_limit:]

    # Pack from newest to oldest so the immediately preceding completed turn is
    # never displaced by older history. Reorder chronologically before rendering.
    packed_reversed: list[tuple[str, str, int]] = []
    used = 0
    for item in reversed(selected):
        role = "PRIOR USER" if str(item.get("role")) == "user" else "PRIOR ASSISTANT"
        raw_content = str(item.get("content") or "").strip()
        separator_cost = 2 if packed_reversed else 0
        header = f"[{role}]\n"
        available = total_budget - used - separator_cost - len(header)
        if available < 40:
            continue
        content = _compact_message(raw_content, min(per_message_limit, available))
        row = header + content
        cost = len(row) + separator_cost
        if used + cost > total_budget:
            continue
        packed_reversed.append((role, content, len(raw_content)))
        used += cost

    packed = list(reversed(packed_reversed))
    rendered = "\n\n".join(f"[{role}]\n{content}" for role, content, _ in packed)
    return ConversationContextPlan(
        mode=mode,
        reason=reason,
        text=rendered,
        message_count=len(packed),
        source_chars=sum(source_chars for _, _, source_chars in packed),
        language_hint=language_hint,
    )
