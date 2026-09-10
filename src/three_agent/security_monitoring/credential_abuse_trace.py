from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint

AUTH_FORENSIC_EVENT_SCHEMA = "workspace-security-forensics/auth-event-v1"
CREDENTIAL_ABUSE_SCHEMA = "workspace-security-forensics/credential-abuse-v1"
AUTH_OUTCOMES = frozenset({"success", "failure"})
AUTH_METHODS = frozenset({"password", "kerberos", "ntlm", "ssh", "vpn", "sso", "certificate", "unknown"})
MAX_AUTH_EVENTS = 20_000
MAX_CREDENTIAL_CANDIDATES = 1024
MAX_AUTH_WINDOW_MINUTES = 1440

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$")


def _identifier(value: str, field_name: str, *, max_len: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or not _ID_RE.fullmatch(text):
        raise MonitoringContractError(f"{field_name} must be a compact identifier")
    if "://" in text or "/" in text or "\\" in text:
        raise MonitoringContractError(f"{field_name} must not expose a URL, path, or raw credential")
    return text


def _parse_timestamp(value: str, field_name: str) -> datetime:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MonitoringContractError(f"{field_name} must include timezone")
    return parsed


def _timestamp(value: str, field_name: str) -> str:
    _parse_timestamp(value, field_name)
    return str(value).strip()


def _strict_bool(value: bool, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise MonitoringContractError(f"{field_name} must be boolean")
    return value


@dataclass(frozen=True)
class AuthForensicEvent:
    event_id: str
    asset_ref: str
    user_ref: str
    source_ref: str
    observed_at: str
    evidence_ref: str
    outcome: str
    auth_method: str
    privileged_context: bool = False
    schema_version: str = AUTH_FORENSIC_EVENT_SCHEMA

    def validate(self) -> "AuthForensicEvent":
        object.__setattr__(self, "event_id", _identifier(self.event_id, "event_id", max_len=128))
        object.__setattr__(self, "asset_ref", _identifier(self.asset_ref, "asset_ref", max_len=128))
        object.__setattr__(self, "user_ref", _identifier(self.user_ref, "user_ref", max_len=128))
        object.__setattr__(self, "source_ref", _identifier(self.source_ref, "source_ref", max_len=128))
        object.__setattr__(self, "observed_at", _timestamp(self.observed_at, "observed_at"))
        object.__setattr__(self, "evidence_ref", _identifier(self.evidence_ref, "evidence_ref", max_len=128))
        if self.outcome not in AUTH_OUTCOMES:
            raise MonitoringContractError("unsupported authentication outcome")
        if self.auth_method not in AUTH_METHODS:
            raise MonitoringContractError("unsupported authentication method")
        _strict_bool(self.privileged_context, "privileged_context")
        if self.schema_version != AUTH_FORENSIC_EVENT_SCHEMA:
            raise MonitoringContractError("unsupported authentication forensic event schema")
        return self


@dataclass(frozen=True)
class CredentialAbuseCandidate:
    candidate_id: str
    user_ref: str
    source_ref: str
    success_event_id: str
    asset_refs: tuple[str, ...]
    reasons: tuple[str, ...]
    failure_count: int
    confidence: float
    evidence_refs: tuple[str, ...]
    window_start: str
    success_at: str


@dataclass(frozen=True)
class CredentialAbuseAssessment:
    candidates: tuple[CredentialAbuseCandidate, ...]
    events_analyzed: int
    authorized_asset_refs: tuple[str, ...]
    credential_material_accessed: bool = False
    authority: str = "advisory"
    schema_version: str = CREDENTIAL_ABUSE_SCHEMA

    def validate(self) -> "CredentialAbuseAssessment":
        if isinstance(self.events_analyzed, bool) or not isinstance(self.events_analyzed, int):
            raise MonitoringContractError("events_analyzed must be an integer")
        if not 0 <= self.events_analyzed <= MAX_AUTH_EVENTS:
            raise MonitoringContractError("events_analyzed is out of bounds")
        _strict_bool(self.credential_material_accessed, "credential_material_accessed")
        if self.credential_material_accessed:
            raise MonitoringContractError("credential abuse analyzer must not access credential material")
        authorized = tuple(sorted({_identifier(v, "authorized_asset_ref", max_len=128) for v in self.authorized_asset_refs}))
        if not authorized:
            raise MonitoringContractError("authorized asset scope is required")
        object.__setattr__(self, "authorized_asset_refs", authorized)
        allowed = set(authorized)
        if len(self.candidates) > MAX_CREDENTIAL_CANDIDATES:
            raise MonitoringContractError("credential abuse candidate bound exceeded")
        for candidate in self.candidates:
            _identifier(candidate.candidate_id, "candidate_id", max_len=128)
            _identifier(candidate.user_ref, "user_ref", max_len=128)
            _identifier(candidate.source_ref, "source_ref", max_len=128)
            _identifier(candidate.success_event_id, "success_event_id", max_len=128)
            if not candidate.asset_refs or any(asset not in allowed for asset in candidate.asset_refs):
                raise MonitoringContractError("credential candidate exceeds authorized asset scope")
            if "success_after_failure_burst" not in candidate.reasons:
                raise MonitoringContractError("credential candidate requires success-after-failure evidence")
            if isinstance(candidate.failure_count, bool) or not isinstance(candidate.failure_count, int) or candidate.failure_count < 1:
                raise MonitoringContractError("credential candidate failure_count is invalid")
            if not 0.0 <= candidate.confidence <= 1.0:
                raise MonitoringContractError("credential candidate confidence must be within [0,1]")
            if not candidate.evidence_refs:
                raise MonitoringContractError("credential candidate requires evidence refs")
            _timestamp(candidate.window_start, "window_start")
            _timestamp(candidate.success_at, "success_at")
        if self.authority != "advisory":
            raise MonitoringContractError("credential abuse assessment must remain advisory")
        if self.schema_version != CREDENTIAL_ABUSE_SCHEMA:
            raise MonitoringContractError("unsupported credential abuse schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "candidates": [asdict(candidate) for candidate in self.candidates],
            "events_analyzed": self.events_analyzed,
            "authorized_asset_refs": list(self.authorized_asset_refs),
            "credential_material_accessed": self.credential_material_accessed,
            "authority": self.authority,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


def trace_credential_abuse(
    events: Iterable[AuthForensicEvent],
    *,
    authorized_asset_refs: Iterable[str],
    failure_threshold: int = 5,
    window_minutes: int = 15,
) -> CredentialAbuseAssessment:
    """Detect success-after-failure authentication sequences from metadata only.

    No credential value, token, hash, ticket, private key, or password is read or
    tested. The analyzer cannot perform authentication attempts or expand target
    scope beyond the caller-supplied asset inventory.
    """

    if isinstance(failure_threshold, bool) or not isinstance(failure_threshold, int) or not 2 <= failure_threshold <= 1000:
        raise MonitoringContractError("failure_threshold must be within 2..1000")
    if isinstance(window_minutes, bool) or not isinstance(window_minutes, int) or not 1 <= window_minutes <= MAX_AUTH_WINDOW_MINUTES:
        raise MonitoringContractError(f"window_minutes must be within 1..{MAX_AUTH_WINDOW_MINUTES}")
    authorized = tuple(sorted({_identifier(v, "authorized_asset_ref", max_len=128) for v in authorized_asset_refs}))
    if not authorized:
        raise MonitoringContractError("authorized asset scope is required")
    allowed = set(authorized)
    rows = tuple(event.validate() for event in events)
    if len(rows) > MAX_AUTH_EVENTS:
        raise MonitoringContractError("authentication event bound exceeded")
    if any(event.asset_ref not in allowed for event in rows):
        raise MonitoringContractError("authentication event exceeds authorized asset scope")

    grouped: dict[tuple[str, str], list[AuthForensicEvent]] = {}
    for event in rows:
        grouped.setdefault((event.user_ref, event.source_ref), []).append(event)

    candidates: list[CredentialAbuseCandidate] = []
    delta = timedelta(minutes=window_minutes)
    for key in sorted(grouped):
        group = sorted(grouped[key], key=lambda event: (_parse_timestamp(event.observed_at, "observed_at"), event.event_id))
        for success_index, success in enumerate(group):
            if success.outcome != "success":
                continue
            success_time = _parse_timestamp(success.observed_at, "success_at")
            failures = [
                event
                for event in group[:success_index]
                if event.outcome == "failure"
                and success_time - delta <= _parse_timestamp(event.observed_at, "failure_at") <= success_time
            ]
            if len(failures) < failure_threshold:
                continue
            evidence_events = failures + [success]
            evidence_refs = tuple(sorted({event.evidence_ref for event in evidence_events}))
            asset_refs = tuple(sorted({event.asset_ref for event in evidence_events}))
            reasons = {"success_after_failure_burst"}
            if success.privileged_context:
                reasons.add("privileged_success")
            if len(asset_refs) >= 2:
                reasons.add("multi_asset_identity_use")
            if len({event.auth_method for event in evidence_events}) >= 2:
                reasons.add("auth_method_variation")
            ordered_reasons = tuple(sorted(reasons))
            confidence = 0.58 + min(0.18, 0.02 * (len(failures) - failure_threshold))
            if "privileged_success" in reasons:
                confidence += 0.1
            if "multi_asset_identity_use" in reasons:
                confidence += 0.08
            if "auth_method_variation" in reasons:
                confidence += 0.05
            confidence = round(min(0.95, confidence), 2)
            identity = {
                "user_ref": key[0],
                "source_ref": key[1],
                "success_event_id": success.event_id,
                "evidence_refs": evidence_refs,
                "schema": CREDENTIAL_ABUSE_SCHEMA,
            }
            candidates.append(
                CredentialAbuseCandidate(
                    candidate_id="credential-abuse:" + sha256_fingerprint(identity).split(":", 1)[1][:24],
                    user_ref=key[0],
                    source_ref=key[1],
                    success_event_id=success.event_id,
                    asset_refs=asset_refs,
                    reasons=ordered_reasons,
                    failure_count=len(failures),
                    confidence=confidence,
                    evidence_refs=evidence_refs,
                    window_start=failures[0].observed_at,
                    success_at=success.observed_at,
                )
            )
            if len(candidates) > MAX_CREDENTIAL_CANDIDATES:
                raise MonitoringContractError("credential abuse candidate bound exceeded")

    candidates.sort(key=lambda item: (-item.confidence, item.success_at, item.user_ref, item.source_ref))
    return CredentialAbuseAssessment(
        candidates=tuple(candidates),
        events_analyzed=len(rows),
        authorized_asset_refs=authorized,
    ).validate()
