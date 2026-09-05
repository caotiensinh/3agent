from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import Callable

from .privacy import (
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_SANITIZE_WARN_ALLOW,
    OutboundDLPError,
    SENSITIVITY_INTERNAL,
    SENSITIVITY_PUBLIC,
    apply_internet_egress_policy,
)

CONSENT_POLICY_VERSION = "workspace.internet-egress-consent/v1"
CONSENT_TTL_SECONDS = 300

_LABELED_IDENTIFIER_RE = re.compile(
    r"(?ix)\b(?:"
    r"user[_ -]?id|account[_ -]?id|employee[_ -]?id|customer[_ -]?id|"
    r"device[_ -]?id|client[_ -]?id|session[_ -]?id|login[_ -]?id|id"
    r")\s*[:=]\s*(?:\"[^\"\n]{1,256}\"|'[^'\n]{1,256}'|[^\s,;]{1,256})"
)


@dataclass(frozen=True)
class EgressPreflight:
    state: str
    sensitivity: str
    action: str
    sanitized_query: str
    reasons: tuple[str, ...]
    removed_sensitive_fields: int
    raw_sha256: str
    warning_required: bool
    policy_version: str = CONSENT_POLICY_VERSION

    @property
    def consent_required(self) -> bool:
        return self.state == "consent_required"

    @property
    def allowed_without_consent(self) -> bool:
        return self.state == "allow"


class InternetEgressConsentRequired(PermissionError):
    def __init__(self, preflight: EgressPreflight, consent_token: str):
        super().__init__("Explicit user consent is required before sanitized Internet egress")
        self.preflight = preflight
        self.consent_token = consent_token

    def public_dict(self) -> dict:
        return {
            "code": "INTERNET_EGRESS_CONSENT_REQUIRED",
            "error": (
                "Sensitive or internal information was detected. Nothing has been sent to the Internet. "
                "Review the sanitized public query and explicitly approve before continuing."
            ),
            "sensitivity": self.preflight.sensitivity,
            "action": self.preflight.action,
            "reasons": list(self.preflight.reasons),
            "removed_sensitive_fields": self.preflight.removed_sensitive_fields,
            "sanitized_preview": self.preflight.sanitized_query,
            "consent_token": self.consent_token,
            "raw_content_sent": False,
            "uploads_sent": False,
            "policy_version": self.preflight.policy_version,
        }


class InternetEgressBlocked(PermissionError):
    def __init__(self, preflight: EgressPreflight):
        super().__init__("Internet egress blocked because no safe public query could be derived")
        self.preflight = preflight

    def public_dict(self) -> dict:
        return {
            "code": "INTERNET_EGRESS_BLOCKED",
            "error": (
                "The request contains sensitive or internal information and WorkSpace could not derive "
                "a safe public query. Nothing has been sent to the Internet."
            ),
            "sensitivity": self.preflight.sensitivity,
            "action": self.preflight.action,
            "reasons": list(self.preflight.reasons),
            "removed_sensitive_fields": self.preflight.removed_sensitive_fields,
            "sanitized_preview": "",
            "raw_content_sent": False,
            "uploads_sent": False,
            "policy_version": self.preflight.policy_version,
        }


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _remove_labeled_identifiers(value: str) -> tuple[str, int]:
    text, count = _LABELED_IDENTIFIER_RE.subn(" ", str(value or ""))
    text = " ".join(text.split()).strip(" ,;:-")
    return text, count


def preflight_public_egress(value: str, *, max_chars: int = 240) -> EgressPreflight:
    """Derive a minimum public query without granting egress authority.

    The raw prompt remains local. INTERNAL/CONFIDENTIAL/RESTRICTED content can be
    transformed into a public preview, but the preview is not authorized until
    the user supplies a valid consent token bound to the exact request.
    """

    raw = str(value or "")
    raw_digest = _sha256(raw)
    policy = apply_internet_egress_policy(raw, max_chars=max_chars)
    without_ids, id_count = _remove_labeled_identifiers(raw)

    if id_count:
        derived = apply_internet_egress_policy(without_ids, max_chars=max_chars)
        reasons = tuple(sorted(set((*policy.reasons, "labeled_identifier"))))
        if not derived.allowed or not derived.query:
            return EgressPreflight(
                state="blocked",
                sensitivity=(policy.sensitivity if policy.sensitivity != SENSITIVITY_PUBLIC else SENSITIVITY_INTERNAL),
                action=ACTION_BLOCK,
                sanitized_query="",
                reasons=reasons,
                removed_sensitive_fields=policy.removed_sensitive_fields + id_count,
                raw_sha256=raw_digest,
                warning_required=True,
            )
        return EgressPreflight(
            state="consent_required",
            sensitivity=(policy.sensitivity if policy.sensitivity != SENSITIVITY_PUBLIC else SENSITIVITY_INTERNAL),
            action=(policy.action if policy.action != ACTION_ALLOW else ACTION_SANITIZE_WARN_ALLOW),
            sanitized_query=derived.query,
            reasons=reasons,
            removed_sensitive_fields=policy.removed_sensitive_fields + id_count,
            raw_sha256=raw_digest,
            warning_required=True,
        )

    if not policy.allowed or not policy.query:
        return EgressPreflight(
            state="blocked",
            sensitivity=policy.sensitivity,
            action=ACTION_BLOCK,
            sanitized_query="",
            reasons=policy.reasons,
            removed_sensitive_fields=policy.removed_sensitive_fields,
            raw_sha256=raw_digest,
            warning_required=policy.warning_required,
        )

    state = "consent_required" if policy.warning_required else "allow"
    return EgressPreflight(
        state=state,
        sensitivity=policy.sensitivity,
        action=policy.action,
        sanitized_query=policy.query,
        reasons=policy.reasons,
        removed_sensitive_fields=policy.removed_sensitive_fields,
        raw_sha256=raw_digest,
        warning_required=policy.warning_required,
    )


def strict_public_search_query(value: str, *, max_chars: int = 240) -> str:
    """Final outbound authority: accept PUBLIC text only, never auto-declassify."""

    preflight = preflight_public_egress(value, max_chars=max_chars)
    if not preflight.allowed_without_consent:
        reason = ",".join(preflight.reasons) or preflight.state
        raise OutboundDLPError(
            "Outbound search text is not independently public; explicit consent-bound declassification "
            f"is required before egress: {reason}"
        )
    return preflight.sanitized_query


class InternetEgressConsentGuard:
    """Short-lived, process-local consent tokens bound to one exact sanitized request."""

    def __init__(
        self,
        *,
        ttl_seconds: int = CONSENT_TTL_SECONDS,
        secret: bytes | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.ttl_seconds = max(30, min(900, int(ttl_seconds)))
        self._secret = secret or secrets.token_bytes(32)
        self._now = now

    def preflight(self, value: str) -> EgressPreflight:
        return preflight_public_egress(value)

    def _claims(
        self,
        preflight: EgressPreflight,
        *,
        sender: str,
        mode: str,
        output_format: str,
        expires_at: int,
    ) -> dict:
        return {
            "v": CONSENT_POLICY_VERSION,
            "exp": expires_at,
            "raw": preflight.raw_sha256,
            "query": _sha256(preflight.sanitized_query),
            "sender": _sha256(str(sender)),
            "mode": str(mode),
            "format": str(output_format),
        }

    def issue(
        self,
        preflight: EgressPreflight,
        *,
        sender: str,
        mode: str,
        output_format: str,
    ) -> str:
        if not preflight.consent_required or not preflight.sanitized_query:
            raise ValueError("Consent tokens are issued only for sanitizable warning-required requests")
        claims = self._claims(
            preflight,
            sender=sender,
            mode=mode,
            output_format=output_format,
            expires_at=int(self._now()) + self.ttl_seconds,
        )
        payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = hmac.new(self._secret, payload, hashlib.sha256).digest()
        return _b64encode(payload) + "." + _b64encode(signature)

    def verify(
        self,
        token: str,
        preflight: EgressPreflight,
        *,
        sender: str,
        mode: str,
        output_format: str,
    ) -> bool:
        try:
            payload_part, signature_part = str(token or "").split(".", 1)
            payload = _b64decode(payload_part)
            supplied = _b64decode(signature_part)
            expected = hmac.new(self._secret, payload, hashlib.sha256).digest()
            if not hmac.compare_digest(supplied, expected):
                return False
            claims = json.loads(payload.decode("utf-8"))
            if not isinstance(claims, dict) or claims.get("v") != CONSENT_POLICY_VERSION:
                return False
            if int(claims.get("exp") or 0) < int(self._now()):
                return False
            expected_claims = self._claims(
                preflight,
                sender=sender,
                mode=mode,
                output_format=output_format,
                expires_at=int(claims["exp"]),
            )
            return all(claims.get(key) == expected_claims[key] for key in expected_claims)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeDecodeError):
            return False

    def authorize(
        self,
        value: str,
        *,
        sender: str,
        mode: str,
        output_format: str,
        consent_token: str = "",
    ) -> str:
        preflight = self.preflight(value)
        if preflight.state == "blocked":
            raise InternetEgressBlocked(preflight)
        if preflight.allowed_without_consent:
            return strict_public_search_query(preflight.sanitized_query)
        if not self.verify(
            consent_token,
            preflight,
            sender=sender,
            mode=mode,
            output_format=output_format,
        ):
            raise InternetEgressConsentRequired(
                preflight,
                self.issue(
                    preflight,
                    sender=sender,
                    mode=mode,
                    output_format=output_format,
                ),
            )
        # Consent authorizes only the already-derived public query. It never
        # authorizes raw prompt bytes, uploads, conversation history, or secrets.
        return strict_public_search_query(preflight.sanitized_query)
