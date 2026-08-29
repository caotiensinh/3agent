from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from dataclasses import dataclass


_EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
_MAC_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")
_GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")
_OPENAI_STYLE_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b")
_TELEGRAM_BOT_TOKEN_RE = re.compile(r"\d{5,}:[A-Za-z0-9_-]{20,}")
_IPV4_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
_UUID_RE = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b")
_ABSOLUTE_PATH_RE = re.compile(r"(?i)(?:\b[A-Z]:\\Users\\|/home/|/Users/|/var/lib/|/srv/|file://)")
_SENSITIVE_WORD_RE = re.compile(
    r"(?i)\b(?:confidential|secret|trade\s+secret|internal\s+only|do\s+not\s+distribute|nda)\b"
    r"|社外秘|機密|極秘|内部限定|비밀|기밀|nội\s+bộ|bí\s+mật|không\s+phát\s+hành"
)
_LONG_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+=./:-]{32,}(?![A-Za-z0-9])")


class OutboundDLPError(PermissionError):
    pass


@dataclass(frozen=True)
class OutboundDLPDecision:
    allowed: bool
    normalized: str
    reasons: tuple[str, ...]
    sha256: str


def _redact_private_ipv4(match: re.Match[str]) -> str:
    value = match.group(0)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    return "[REDACTED_PRIVATE_IP]" if not address.is_global else value


def redact_sensitive_text(value: str) -> str:
    """Redact common secrets and identifiers before local audit logging."""
    text = str(value)
    text = _GITHUB_TOKEN_RE.sub("[REDACTED_GITHUB_TOKEN]", text)
    text = _OPENAI_STYLE_KEY_RE.sub("[REDACTED_API_KEY]", text)
    text = _AWS_ACCESS_KEY_RE.sub("[REDACTED_AWS_KEY]", text)
    text = _BEARER_RE.sub("Bearer [REDACTED_TOKEN]", text)
    text = _TELEGRAM_BOT_TOKEN_RE.sub("[REDACTED_TELEGRAM_BOT_TOKEN]", text)
    text = _EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = _MAC_RE.sub("[REDACTED_MAC]", text)
    text = _IPV4_RE.sub(_redact_private_ipv4, text)
    return text


def sanitize_research_query(value: str) -> str:
    """Legacy-compatible normalization/redaction before an egress policy decision.

    Redaction is not authorization. WorkSpace strict DLP rejects redaction markers,
    so a query containing sensitive material is blocked instead of searched with
    placeholders.
    """
    return " ".join(redact_sensitive_text(value).split())


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def assess_public_egress_text(value: str, *, max_chars: int = 240) -> OutboundDLPDecision:
    """Fail closed for text proposed for public Internet egress.

    This filter is defense-in-depth. WorkSpace cannot infer every business secret,
    so confidential mode keeps public search disabled entirely by default.
    """
    raw = str(value)
    normalized = " ".join(raw.split())
    reasons: list[str] = []

    if not normalized:
        reasons.append("empty")
    if len(normalized) > max_chars:
        reasons.append("query_too_long")
    if "\n" in raw or "\r" in raw:
        reasons.append("multiline")
    if "[REDACTED_" in normalized:
        reasons.append("redaction_marker")
    if redact_sensitive_text(normalized) != normalized:
        reasons.append("known_identifier_or_secret")
    if _UUID_RE.search(normalized):
        reasons.append("uuid")
    if _ABSOLUTE_PATH_RE.search(normalized):
        reasons.append("local_path")
    if _SENSITIVE_WORD_RE.search(normalized):
        reasons.append("confidentiality_marker")
    if "://" in normalized:
        reasons.append("embedded_url")

    for token in _LONG_TOKEN_RE.findall(normalized):
        if _shannon_entropy(token) >= 4.0:
            reasons.append("high_entropy_token")
            break

    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return OutboundDLPDecision(not reasons, normalized, tuple(sorted(set(reasons))), digest)


def assert_public_egress_text(value: str, *, max_chars: int = 240) -> str:
    decision = assess_public_egress_text(value, max_chars=max_chars)
    if not decision.allowed:
        raise OutboundDLPError(
            "Outbound text blocked by WorkSpace DLP policy: " + ",".join(decision.reasons)
        )
    return decision.normalized
