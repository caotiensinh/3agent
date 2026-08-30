from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .privacy import assess_public_egress_text, redact_sensitive_text

PUBLIC_QUERY_COMPILER_VERSION = "workspace-public-query-compiler/v1"
_REDACTION_MARKER_RE = re.compile(r"\[REDACTED_[A-Z0-9_]+\]")
_PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"(?ix)"
    r"(?:\b(?:password|passwd|pwd|username|user(?:name)?|login|secret|token|"
    r"api[_ -]?key|client[_ -]?secret|access[_ -]?token|refresh[_ -]?token|authorization)\b"
    r"|パスワード|ユーザー名|認証情報|"
    r"mật\s*khẩu|tên\s*đăng\s*nhập|tài\s*khoản)"
    r"\s*(?:[:=]|\bis\b)?\s*"
    r"(?:\"[^\"\n]{1,512}\"|'[^'\n]{1,512}'|[^\s,;]{1,512})"
)
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_LOCAL_PATH_RE = re.compile(
    r"(?i)(?:[A-Z]:\\(?:Users|ProgramData|Windows)\\[^\s<>\"']+|"
    r"/(?:home|Users|var/lib|srv|etc)/[^\s<>\"']+)"
)
_UUID_RE = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"
)
_HIGH_ENTROPY_LIKE_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+=./:-]{32,}(?![A-Za-z0-9])")
_CONFIDENTIALITY_WORD_RE = re.compile(
    r"(?i)\b(?:confidential|trade\s+secret|internal\s+only|do\s+not\s+distribute|nda)\b"
    r"|社外秘|機密|極秘|内部限定|nội\s+bộ|bí\s*mật|không\s+phát\s+hành"
)


@dataclass(frozen=True)
class PublicQueryCompilation:
    allowed: bool
    query: str
    reasons: tuple[str, ...]
    removed_sensitive_fields: int
    compiler_version: str = PUBLIC_QUERY_COMPILER_VERSION


def _truncate_words(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    candidate = value[:limit]
    if " " in candidate:
        candidate = candidate.rsplit(" ", 1)[0]
    return candidate.strip(" ,;:-")


def compile_public_search_query(value: str, *, max_chars: int = 240) -> PublicQueryCompilation:
    """Derive a minimal public-only query from local text, then re-run strict DLP.

    This function is a declassification gate, not a general text redactor. It never
    returns the original prompt when sensitive material is detected. Known secret
    fields and identifiers are removed, not replaced with values or reversible
    aliases. If anything risky remains after derivation, the final strict DLP check
    blocks egress.
    """

    raw = str(value or "")
    if not raw.strip():
        return PublicQueryCompilation(False, "", ("empty",), 0)

    removed = 0

    def remove(pattern: re.Pattern[str], text: str) -> str:
        nonlocal removed
        text, count = pattern.subn(" ", text)
        removed += count
        return text

    derived = _PRIVATE_KEY_BLOCK_RE.sub(" [REDACTED_PRIVATE_KEY] ", raw)
    derived = remove(_CREDENTIAL_ASSIGNMENT_RE, derived)
    derived = redact_sensitive_text(derived)
    marker_count = len(_REDACTION_MARKER_RE.findall(derived))
    removed += marker_count
    derived = _REDACTION_MARKER_RE.sub(" ", derived)
    derived = remove(_LOCAL_PATH_RE, derived)
    derived = remove(_UUID_RE, derived)
    derived = remove(_URL_RE, derived)
    derived = remove(_HIGH_ENTROPY_LIKE_RE, derived)
    derived = remove(_CONFIDENTIALITY_WORD_RE, derived)

    # Remove punctuation left behind by stripped key/value fields while retaining
    # technical operators/versions that are useful search terms.
    derived = re.sub(r"[\t\r\n]+", " ", derived)
    derived = re.sub(r"\s+", " ", derived).strip(" ,;:-")
    derived = _truncate_words(derived, max_chars)

    if not derived:
        return PublicQueryCompilation(
            False,
            "",
            ("no_public_terms_after_sensitive_removal",),
            removed,
        )

    decision = assess_public_egress_text(derived, max_chars=max_chars)
    if not decision.allowed:
        return PublicQueryCompilation(
            False,
            "",
            tuple(f"post_compile_{reason}" for reason in decision.reasons),
            removed,
        )
    return PublicQueryCompilation(True, decision.normalized, (), removed)


def compile_public_search_queries(
    values: Iterable[str],
    *,
    fallback: str = "",
    max_queries: int = 4,
    max_chars: int = 240,
) -> tuple[list[str], list[str]]:
    """Compile/deduplicate queries; return safe queries and metadata-only diagnostics."""

    queries: list[str] = []
    diagnostics: list[str] = []
    candidates = [str(value) for value in values]
    if fallback:
        candidates.append(str(fallback))
    for candidate in candidates:
        result = compile_public_search_query(candidate, max_chars=max_chars)
        if not result.allowed:
            diagnostics.append(
                "public_query_blocked reasons=" + ",".join(result.reasons)
            )
            continue
        if result.removed_sensitive_fields:
            diagnostics.append(
                f"public_query_sanitized removed_fields={result.removed_sensitive_fields}"
            )
        if result.query not in queries:
            queries.append(result.query)
        if len(queries) >= max_queries:
            break
    return queries, diagnostics
