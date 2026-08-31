from __future__ import annotations

import re
from typing import Any, Sequence

from .chat_context import (
    CONTEXT_MODE_FOLLOW_UP,
    CONTEXT_MODE_STANDALONE,
    DEFAULT_CONTEXT_MAX_CHARS,
    DEFAULT_CONTEXT_MAX_MESSAGES,
    DEFAULT_CONTEXT_PER_MESSAGE_CHARS,
    ConversationContextPlan,
    build_conversation_context as _build_legacy_context,
    classify_context_request as _classify_legacy_context,
    infer_recent_user_language,
)


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


__all__ = [
    "CONTEXT_MODE_FOLLOW_UP",
    "CONTEXT_MODE_STANDALONE",
    "DEFAULT_CONTEXT_MAX_CHARS",
    "DEFAULT_CONTEXT_MAX_MESSAGES",
    "DEFAULT_CONTEXT_PER_MESSAGE_CHARS",
    "ConversationContextPlan",
    "build_conversation_context",
    "classify_context_request",
    "infer_recent_user_language",
]
