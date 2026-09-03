from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from dataclasses import dataclass


INTERNET_EGRESS_POLICY_VERSION = "workspace.internet-egress/v1"
SENSITIVITY_PUBLIC = "PUBLIC"
SENSITIVITY_INTERNAL = "INTERNAL"
SENSITIVITY_CONFIDENTIAL = "CONFIDENTIAL"
SENSITIVITY_RESTRICTED = "RESTRICTED"

ACTION_ALLOW = "ALLOW"
ACTION_SANITIZE_WARN_ALLOW = "SANITIZE_WARN_ALLOW"
ACTION_TOKENIZE_GENERALIZE_WARN_ALLOW = "TOKENIZE_GENERALIZE_WARN_ALLOW"
ACTION_DENY_RAW_DERIVE_ABSTRACT_ALLOW = "DENY_RAW_DERIVE_ABSTRACT_ALLOW"
ACTION_BLOCK = "BLOCK"

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
_LOCAL_PATH_VALUE_RE = re.compile(
    r"(?i)(?:[A-Z]:\\(?:Users|ProgramData|Windows)\\[^\s<>\"']+|"
    r"/(?:home|Users|var/lib|srv|etc)/[^\s<>\"']+)"
)
_SENSITIVE_WORD_RE = re.compile(
    r"(?i)\b(?:confidential|secret|trade\s+secret|internal\s+only|do\s+not\s+distribute|nda)\b"
    r"|社外秘|機密|極秘|内部限定|비밀|기밀|nội\s+bộ|bí\s*mật|không\s+phát\s+hành"
)
_LONG_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+=./:-]{32,}(?![A-Za-z0-9])")
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
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
_REDACTION_MARKER_RE = re.compile(r"\[REDACTED_[A-Z0-9_]+\]")


class OutboundDLPError(PermissionError):
    pass


@dataclass(frozen=True)
class OutboundDLPDecision:
    allowed: bool
    normalized: str
    reasons: tuple[str, ...]
    sha256: str


@dataclass(frozen=True)
class InternetEgressPolicyDecision:
    """Four-level declassification decision for public Internet research.

    ``query`` is the only text authorized for a later strict DLP check. The caller
    must never substitute the original input when ``allowed`` is false or when the
    query is empty.
    """

    sensitivity: str
    action: str
    allowed: bool
    query: str
    warning_required: bool
    transformed: bool
    reasons: tuple[str, ...]
    removed_sensitive_fields: int
    sha256: str
    policy_version: str = INTERNET_EGRESS_POLICY_VERSION


def _redact_private_ipv4(match: re.Match[str]) -> str:
    value = match.group(0)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    return "[REDACTED_PRIVATE_IP]" if not address.is_global else value


def _has_private_ipv4(value: str) -> bool:
    for match in _IPV4_RE.finditer(value):
        try:
            if not ipaddress.ip_address(match.group(0)).is_global:
                return True
        except ValueError:
            continue
    return False


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _has_high_entropy_token(value: str) -> bool:
    return any(_shannon_entropy(token) >= 4.0 for token in _LONG_TOKEN_RE.findall(value))


def redact_sensitive_text(value: str) -> str:
    """Redact common secrets and identifiers before local audit logging."""
    text = str(value)
    text = _PRIVATE_KEY_BLOCK_RE.sub("[REDACTED_PRIVATE_KEY]", text)
    text = _GITHUB_TOKEN_RE.sub("[REDACTED_GITHUB_TOKEN]", text)
    text = _OPENAI_STYLE_KEY_RE.sub("[REDACTED_API_KEY]", text)
    text = _AWS_ACCESS_KEY_RE.sub("[REDACTED_AWS_KEY]", text)
    text = _BEARER_RE.sub("Bearer [REDACTED_TOKEN]", text)
    text = _TELEGRAM_BOT_TOKEN_RE.sub("[REDACTED_TELEGRAM_BOT_TOKEN]", text)
    text = _CREDENTIAL_ASSIGNMENT_RE.sub("[REDACTED_CREDENTIAL]", text)
    text = _EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = _MAC_RE.sub("[REDACTED_MAC]", text)
    text = _IPV4_RE.sub(_redact_private_ipv4, text)
    return text


def classify_public_egress_sensitivity(value: str) -> tuple[str, tuple[str, ...]]:
    """Classify proposed research text using deterministic, fail-safe precedence.

    RESTRICTED > CONFIDENTIAL > INTERNAL > PUBLIC. Existing TaskContract ``secret``
    sensitivity must be treated as RESTRICTED by callers when task metadata is
    available; this classifier evaluates the text payload itself.
    """

    text = str(value or "")
    reasons: list[str] = []

    restricted_patterns = (
        ("private_key", _PRIVATE_KEY_BLOCK_RE),
        ("credential_assignment", _CREDENTIAL_ASSIGNMENT_RE),
        ("github_token", _GITHUB_TOKEN_RE),
        ("api_key", _OPENAI_STYLE_KEY_RE),
        ("aws_access_key", _AWS_ACCESS_KEY_RE),
        ("bearer_token", _BEARER_RE),
        ("telegram_token", _TELEGRAM_BOT_TOKEN_RE),
    )
    for reason, pattern in restricted_patterns:
        if pattern.search(text):
            reasons.append(reason)
    if _has_high_entropy_token(text):
        reasons.append("high_entropy_token")
    if reasons:
        return SENSITIVITY_RESTRICTED, tuple(sorted(set(reasons)))

    if _SENSITIVE_WORD_RE.search(text):
        return SENSITIVITY_CONFIDENTIAL, ("confidentiality_marker",)

    internal_reasons: list[str] = []
    if _has_private_ipv4(text):
        internal_reasons.append("private_ip")
    if _EMAIL_RE.search(text):
        internal_reasons.append("email")
    if _MAC_RE.search(text):
        internal_reasons.append("mac")
    if _UUID_RE.search(text):
        internal_reasons.append("uuid")
    if _ABSOLUTE_PATH_RE.search(text) or _LOCAL_PATH_VALUE_RE.search(text):
        internal_reasons.append("local_path")
    if _URL_RE.search(text):
        internal_reasons.append("embedded_url")
    if internal_reasons:
        return SENSITIVITY_INTERNAL, tuple(sorted(set(internal_reasons)))

    return SENSITIVITY_PUBLIC, ()


def _strip_sensitive_for_public_query(value: str) -> tuple[str, int]:
    text = str(value or "")
    removed = 0

    def remove(pattern: re.Pattern[str], current: str) -> str:
        nonlocal removed
        current, count = pattern.subn(" ", current)
        removed += count
        return current

    text = remove(_PRIVATE_KEY_BLOCK_RE, text)
    text = remove(_CREDENTIAL_ASSIGNMENT_RE, text)
    redacted = redact_sensitive_text(text)
    marker_count = len(_REDACTION_MARKER_RE.findall(redacted))
    removed += marker_count
    text = _REDACTION_MARKER_RE.sub(" ", redacted)
    text = remove(_LOCAL_PATH_VALUE_RE, text)
    text = remove(_UUID_RE, text)
    text = remove(_URL_RE, text)
    text = remove(_LONG_TOKEN_RE, text)
    text = remove(_SENSITIVE_WORD_RE, text)
    text = re.sub(r"[\t\r\n]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip(" ,;:-")
    return text, removed


def _truncate_words(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    candidate = value[:limit]
    if " " in candidate:
        candidate = candidate.rsplit(" ", 1)[0]
    return candidate.strip(" ,;:-")


def apply_internet_egress_policy(
    value: str,
    *,
    max_chars: int = 240,
) -> InternetEgressPolicyDecision:
    """Apply WorkSpace's four-level controlled Internet research policy.

    PUBLIC is allowed unchanged after strict DLP. INTERNAL, CONFIDENTIAL and
    RESTRICTED inputs are declassified into a minimum public query and require a
    user warning. RESTRICTED raw material is never authorized. If a safe derived
    query cannot be produced, public egress is blocked while local processing may
    continue.
    """

    raw = str(value or "")
    raw_digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    if not raw.strip():
        return InternetEgressPolicyDecision(
            SENSITIVITY_PUBLIC,
            ACTION_BLOCK,
            False,
            "",
            False,
            False,
            ("empty",),
            0,
            raw_digest,
        )

    sensitivity, classify_reasons = classify_public_egress_sensitivity(raw)
    normalized = " ".join(raw.split())

    if sensitivity == SENSITIVITY_PUBLIC:
        decision = assess_public_egress_text(normalized, max_chars=max_chars)
        if not decision.allowed:
            return InternetEgressPolicyDecision(
                sensitivity,
                ACTION_BLOCK,
                False,
                "",
                False,
                False,
                decision.reasons,
                0,
                raw_digest,
            )
        return InternetEgressPolicyDecision(
            sensitivity,
            ACTION_ALLOW,
            True,
            decision.normalized,
            False,
            False,
            (),
            0,
            raw_digest,
        )

    derived, removed = _strip_sensitive_for_public_query(raw)
    derived = _truncate_words(derived, max_chars)
    if not derived:
        return InternetEgressPolicyDecision(
            sensitivity,
            ACTION_BLOCK,
            False,
            "",
            True,
            True,
            tuple(sorted(set((*classify_reasons, "no_public_terms_after_declassification")))),
            removed,
            raw_digest,
        )

    final = assess_public_egress_text(derived, max_chars=max_chars)
    if not final.allowed:
        return InternetEgressPolicyDecision(
            sensitivity,
            ACTION_BLOCK,
            False,
            "",
            True,
            True,
            tuple(sorted(set((*classify_reasons, *(f"post_compile_{r}" for r in final.reasons))))),
            removed,
            raw_digest,
        )

    action = {
        SENSITIVITY_INTERNAL: ACTION_SANITIZE_WARN_ALLOW,
        SENSITIVITY_CONFIDENTIAL: ACTION_TOKENIZE_GENERALIZE_WARN_ALLOW,
        SENSITIVITY_RESTRICTED: ACTION_DENY_RAW_DERIVE_ABSTRACT_ALLOW,
    }[sensitivity]
    return InternetEgressPolicyDecision(
        sensitivity,
        action,
        True,
        final.normalized,
        True,
        True,
        classify_reasons,
        removed,
        raw_digest,
    )


def sanitize_research_query(value: str) -> str:
    """Return only a policy-authorized public query; never return sensitive raw text."""
    decision = apply_internet_egress_policy(value)
    if not decision.allowed:
        raise OutboundDLPError(
            "Outbound research query blocked by WorkSpace Internet Egress Policy: "
            + ",".join(decision.reasons)
        )
    return decision.query


def assess_public_egress_text(value: str, *, max_chars: int = 240) -> OutboundDLPDecision:
    """Fail closed for the final text proposed for public Internet egress."""
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
