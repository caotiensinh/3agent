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
    # A numbered item is a cross-turn reference only at the start of the
    # request, optionally under an explicit demonstrative such as それの/その.
    # This preserves `それの2つ目...` while avoiding internal 1つ目/2つ目/3つ目
    # enumerations in otherwise standalone prompts.
    r"^(?:(?:では|じゃあ|それでは)\s*)?(?:(?:それ|その)の?\s*)?(?:2つ目|２つ目|二つ目|第二)(?:だけ|の|を|は|について|[?？。！!\s]|$)",
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


# Internal snapshots preserve the former base/v2 call chain after physical flattening.
_classify_legacy_context = classify_context_request
_build_legacy_context = build_conversation_context

import re
from typing import Any, Sequence


# v2 extends the conservative reference gate only for explicit transform requests
# that name prior/above content. It does not unlock history for generic translate,
# rewrite, summarize, or report requests that can stand alone.
_VI_REFERENCED_TRANSFORM_PATTERNS = (
    r"\b(?:dịch|viết\s+lại|tóm\s+tắt|chuyển|định\s+dạng\s+lại|làm\s+lại)\b.{0,90}\b(?:báo\s+cáo|tài\s+liệu|câu\s+trả\s+lời|nội\s+dung|phần|đoạn)\s+(?:ở\s+)?(?:trên|bên\s+trên|vừa\s+(?:tạo|viết|nói|nêu))\b",
    r"\b(?:báo\s+cáo|tài\s+liệu|câu\s+trả\s+lời|nội\s+dung|phần|đoạn)\s+(?:ở\s+)?(?:trên|bên\s+trên|vừa\s+(?:tạo|viết))\b.{0,90}\b(?:dịch|viết\s+lại|tóm\s+tắt|chuyển|định\s+dạng\s+lại|làm\s+lại)\b",
)
_EN_REFERENCED_TRANSFORM_PATTERNS = (
    r"\b(?:translate|rewrite|summari[sz]e|reformat|convert)\b.{0,90}\b(?:the\s+)?(?:above|previous|prior|last)\s+(?:report|document|answer|content|section|passage|text)\b",
    r"\b(?:the\s+)?(?:above|previous|prior|last)\s+(?:report|document|answer|content|section|passage|text)\b.{0,90}\b(?:translate|rewrite|summari[sz]e|reformat|convert)\b",
)
_JA_REFERENCED_TRANSFORM_PATTERNS = (
    r"(?:上記|上の|前の|先ほど|さっき)(?:の)?(?:レポート|報告書|文書|回答|内容|文章|部分).{0,48}(?:翻訳|訳|書き直|要約|再構成|変換|整形)",
    r"(?:翻訳|訳|書き直|要約|再構成|変換|整形).{0,48}(?:上記|上の|前の|先ほど|さっき)(?:の)?(?:レポート|報告書|文書|回答|内容|文章|部分)",
)

_TRANSFORM_PATTERNS = {
    "vi": tuple(re.compile(pattern, re.IGNORECASE) for pattern in _VI_REFERENCED_TRANSFORM_PATTERNS),
    "en": tuple(re.compile(pattern, re.IGNORECASE) for pattern in _EN_REFERENCED_TRANSFORM_PATTERNS),
    "ja": tuple(re.compile(pattern) for pattern in _JA_REFERENCED_TRANSFORM_PATTERNS),
}


def _compact_request(value: str) -> str:
    return " ".join(str(value or "").replace("\u3000", " ").split()).strip()


def classify_context_request(request: str) -> tuple[str, str, str]:
    """Classify explicit cross-turn references, including prior-artifact transforms."""

    legacy = _classify_legacy_context(request)
    if legacy[0] == CONTEXT_MODE_FOLLOW_UP:
        return legacy

    text = _compact_request(request)
    if not text:
        return legacy
    for language in ("vi", "ja", "en"):
        for index, pattern in enumerate(_TRANSFORM_PATTERNS[language], 1):
            if pattern.search(text):
                return (
                    CONTEXT_MODE_FOLLOW_UP,
                    f"{language}_referenced_transform_{index}",
                    language,
                )
    return legacy


def build_conversation_context(
    messages: Sequence[dict[str, Any]],
    current_request: str,
    *,
    current_job_id: str = "",
    max_chars: int = DEFAULT_CONTEXT_MAX_CHARS,
    max_messages: int = DEFAULT_CONTEXT_MAX_MESSAGES,
    per_message_chars: int = DEFAULT_CONTEXT_PER_MESSAGE_CHARS,
) -> ConversationContextPlan:
    """Use the established bounded packer after the v2 reference decision.

    For legacy-recognized requests we delegate unchanged. For the new explicit
    transform references, a neutral synthetic follow-up cue unlocks the same
    deterministic completed-message packer; only the classification metadata is
    replaced. The current user request itself is never rewritten or inserted into
    prior context.
    """

    mode, reason, language_hint = classify_context_request(current_request)
    legacy_mode, _, _ = _classify_legacy_context(current_request)
    if mode != CONTEXT_MODE_FOLLOW_UP or legacy_mode == CONTEXT_MODE_FOLLOW_UP:
        return _build_legacy_context(
            messages,
            current_request,
            current_job_id=current_job_id,
            max_chars=max_chars,
            max_messages=max_messages,
            per_message_chars=per_message_chars,
        )

    packed = _build_legacy_context(
        messages,
        "continue",
        current_job_id=current_job_id,
        max_chars=max_chars,
        max_messages=max_messages,
        per_message_chars=per_message_chars,
    )
    return ConversationContextPlan(
        mode=CONTEXT_MODE_FOLLOW_UP,
        reason=reason,
        text=packed.text,
        message_count=packed.message_count,
        source_chars=packed.source_chars,
        language_hint=language_hint,
    )


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
    """Pack bounded recent context for every existing conversation.

    The current request remains authoritative. Prior turns are conversation data,
    never executable instructions. Explicit-reference requests keep the stronger
    ``follow_up`` mode; ordinary later turns use ``continuity``. A brand-new chat
    with no eligible prior completed turn remains ``standalone``.
    """

    explicit_mode, explicit_reason, language_hint = classify_context_request(current_request)
    eligible = _eligible_messages(messages, current_job_id=current_job_id)
    if not eligible:
        return ConversationContextPlan(
            mode=(CONTEXT_MODE_FOLLOW_UP if explicit_mode == CONTEXT_MODE_FOLLOW_UP else CONTEXT_MODE_STANDALONE),
            reason=(explicit_reason if explicit_mode == CONTEXT_MODE_FOLLOW_UP else "no_prior_completed_turn"),
            text="",
            message_count=0,
            source_chars=0,
            language_hint=language_hint,
        )

    total_budget = max(80, int(max_chars))
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
    mode = CONTEXT_MODE_FOLLOW_UP if explicit_mode == CONTEXT_MODE_FOLLOW_UP else CONTEXT_MODE_CONTINUITY
    reason = explicit_reason if explicit_mode == CONTEXT_MODE_FOLLOW_UP else "same_conversation_recent_turns"
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
