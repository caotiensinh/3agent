from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from typing import Any

TOOL_RESULT_BOUNDARY_SCHEMA = "workspace-tool-result-boundary/v1"
DEFAULT_STDOUT_LIMIT_BYTES = 64 * 1024
DEFAULT_STDERR_LIMIT_BYTES = 8 * 1024
MAX_RESULT_FIELD_BYTES = 256 * 1024

_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|api[_-]?key|secret|authorization)\b"
    r"\s*([:=])\s*(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{6,}")
_BASIC_RE = re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/=]{6,}")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)


class ToolResultBoundaryError(ValueError):
    """A tool result cannot be safely projected through the bounded boundary."""


def _validate_limit(value: int, *, field: str) -> int:
    limit = int(value)
    if not 1 <= limit <= MAX_RESULT_FIELD_BYTES:
        raise ToolResultBoundaryError(
            f"{field} must be within 1..{MAX_RESULT_FIELD_BYTES} bytes"
        )
    return limit


def _strip_unsafe_controls(value: str) -> str:
    return "".join(
        ch for ch in value if ch in "\n\r\t" or ord(ch) >= 0x20
    )


def _redact_common_secret_literals(value: str) -> tuple[str, int]:
    redactions = 0

    def _simple(match: re.Match[str]) -> str:
        nonlocal redactions
        redactions += 1
        prefix = match.group(0).split(None, 1)[0]
        return f"{prefix} [REDACTED]"

    # Scheme credentials must be removed before assignment redaction. Otherwise an
    # Authorization assignment can consume only the word "Bearer"/"Basic" and leave
    # the credential token behind as an apparently unrelated suffix.
    text = _BEARER_RE.sub(_simple, value)
    text = _BASIC_RE.sub(_simple, text)

    def _assignment(match: re.Match[str]) -> str:
        nonlocal redactions
        redactions += 1
        return f"{match.group(1)}{match.group(2)}[REDACTED]"

    text = _SECRET_ASSIGNMENT_RE.sub(_assignment, text)

    def _private_key(_: re.Match[str]) -> str:
        nonlocal redactions
        redactions += 1
        return "[REDACTED PRIVATE KEY]"

    text = _PRIVATE_KEY_RE.sub(_private_key, text)
    return text, redactions


def _utf8_prefix(value: str, max_bytes: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return value, False
    prefix = encoded[:max_bytes]
    while prefix:
        try:
            return prefix.decode("utf-8"), True
        except UnicodeDecodeError as exc:
            prefix = prefix[: exc.start]
    return "", True


@dataclass(frozen=True)
class BoundedTextResult:
    text: str
    original_bytes: int
    returned_bytes: int
    sha256: str
    truncated: bool
    redactions: int
    schema_version: str = TOOL_RESULT_BOUNDARY_SCHEMA

    def metadata(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("text")
        return payload


def bound_text_result(
    value: str | None,
    *,
    max_bytes: int,
    redact_common_secrets: bool = True,
) -> BoundedTextResult:
    """Return an audit-friendly bounded UTF-8 projection of one text field.

    The digest and original byte count are calculated over the exact raw UTF-8
    representation before redaction/truncation. Returned text is control-cleaned,
    optionally redacted for common credential literals, and then hard-bounded by
    UTF-8 byte length. The helper grants no execution or evidence authority.
    """

    limit = _validate_limit(max_bytes, field="max_bytes")
    raw_text = "" if value is None else str(value)
    raw_bytes = raw_text.encode("utf-8", errors="replace")
    digest = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()

    safe_text = _strip_unsafe_controls(raw_text)
    redactions = 0
    if redact_common_secrets:
        safe_text, redactions = _redact_common_secret_literals(safe_text)
    bounded, truncated = _utf8_prefix(safe_text, limit)
    returned_bytes = len(bounded.encode("utf-8"))

    return BoundedTextResult(
        text=bounded,
        original_bytes=len(raw_bytes),
        returned_bytes=returned_bytes,
        sha256=digest,
        truncated=truncated,
        redactions=redactions,
    )


def bound_process_output(
    stdout: str | None,
    stderr: str | None,
    *,
    stdout_limit_bytes: int = DEFAULT_STDOUT_LIMIT_BYTES,
    stderr_limit_bytes: int = DEFAULT_STDERR_LIMIT_BYTES,
) -> dict[str, Any]:
    """Project subprocess text through one deterministic result/egress boundary."""

    stdout_result = bound_text_result(stdout, max_bytes=stdout_limit_bytes)
    stderr_result = bound_text_result(stderr, max_bytes=stderr_limit_bytes)
    return {
        "stdout": stdout_result.text,
        "stderr": stderr_result.text,
        "output_boundary": {
            "schema_version": TOOL_RESULT_BOUNDARY_SCHEMA,
            "stdout": stdout_result.metadata(),
            "stderr": stderr_result.metadata(),
        },
    }
