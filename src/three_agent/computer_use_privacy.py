from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping
from urllib.parse import urlparse, urlunparse

REDACTED = "[REDACTED]"
MAX_PRIVACY_DEPTH = 12
SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "cookie",
        "set_cookie",
        "session_cookie",
        "credential",
        "credentials",
        "api_key",
        "apikey",
        "private_key",
    }
)
SECURE_NODE_MARKERS = frozenset(
    {"password", "current-password", "new-password", "one-time-code"}
)
SECURE_VALUE_KEYS = frozenset(
    {"value", "text", "inner_text", "innertext", "textcontent"}
)
FORBIDDEN_CONTINUOUS_CAPTURE_KEYS = frozenset(
    {
        "continuous_video",
        "video_bytes",
        "recording_bytes",
        "screen_recording",
        "screen_recording_bytes",
    }
)
SENSITIVITIES = frozenset({"public", "internal", "confidential", "restricted", "secret"})


class ComputerPrivacyError(ValueError):
    """Computer-use content violates retention or credential-handling policy."""


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ComputerPrivacyError("COMPUTER_PRIVACY_VALUE_NOT_CANONICAL_JSON") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _safe_url(value: str) -> str:
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return REDACTED
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return REDACTED
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if port is not None:
        host = f"{host}:{port}"
    return urlunparse((parsed.scheme, host, parsed.path, "", "", ""))


def _secure_node(mapping: Mapping[str, Any]) -> bool:
    if any(
        mapping.get(key) is True
        for key in ("secure", "protected", "is_password", "password_field")
    ):
        return True
    for key in ("type", "autocomplete", "role"):
        value = mapping.get(key)
        if isinstance(value, str) and value.strip().lower() in SECURE_NODE_MARKERS:
            return True
    return False


def sanitize_computer_content(
    value: Any,
    *,
    depth: int = 0,
    secure_parent: bool = False,
) -> Any:
    """Return deterministic credential-safe content suitable for retained evidence."""

    if depth > MAX_PRIVACY_DEPTH:
        raise ComputerPrivacyError("COMPUTER_PRIVACY_DEPTH_EXCEEDED")
    if isinstance(value, Mapping):
        secure_here = secure_parent or _secure_node(value)
        sanitized: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            normalized_key = key.strip().lower().replace("-", "_")
            if normalized_key in FORBIDDEN_CONTINUOUS_CAPTURE_KEYS:
                raise ComputerPrivacyError("COMPUTER_CONTINUOUS_CAPTURE_RETENTION_FORBIDDEN")
            if normalized_key in SENSITIVE_KEYS:
                sanitized[key] = REDACTED
            elif secure_here and normalized_key in SECURE_VALUE_KEYS:
                sanitized[key] = REDACTED
            elif normalized_key == "url" and isinstance(raw_value, str):
                sanitized[key] = _safe_url(raw_value)
            else:
                sanitized[key] = sanitize_computer_content(
                    raw_value,
                    depth=depth + 1,
                    secure_parent=secure_here,
                )
        return sanitized
    if isinstance(value, (list, tuple)):
        return [
            sanitize_computer_content(
                item,
                depth=depth + 1,
                secure_parent=secure_parent,
            )
            for item in value
        ]
    return value


def retain_computer_result(
    result: Mapping[str, Any] | None,
    *,
    sensitivity: str,
) -> Mapping[str, Any] | None:
    """Apply TaskContract-compatible computer-use result retention.

    Credentials are always removed. Restricted/secret tasks retain only a digest
    and explicit metadata-only marker because their raw tool-output policy is deny.
    """

    if sensitivity not in SENSITIVITIES:
        raise ComputerPrivacyError("UNKNOWN_COMPUTER_PRIVACY_SENSITIVITY")
    if result is None:
        return None
    if not isinstance(result, Mapping):
        raise ComputerPrivacyError("COMPUTER_RESULT_MUST_BE_OBJECT")
    sanitized = sanitize_computer_content(result)
    _canonical_json(sanitized)
    if sensitivity in {"restricted", "secret"}:
        return {
            "retention": "metadata_only",
            "sanitized_result_sha256": _digest(sanitized),
        }
    return sanitized
