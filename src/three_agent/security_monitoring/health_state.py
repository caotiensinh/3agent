from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .contracts import MonitoringContractError, _compact, canonical_json, sha256_fingerprint

HEALTH_STATES = {
    "unknown",
    "healthy",
    "degraded",
    "unreachable",
    "maintenance",
    "data_gap",
}
HEALTH_STATE_SCHEMA = "workspace-security-monitoring/health-state-v1"
HEALTH_TRANSITION_SCHEMA = "workspace-security-monitoring/health-transition-v1"


def _bounded_int(value: int, field_name: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MonitoringContractError(f"{field_name} must be an integer")
    if value < minimum or value > maximum:
        raise MonitoringContractError(f"{field_name} must be within {minimum}..{maximum}")
    return value


def _utc_timestamp(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise MonitoringContractError(f"{field_name} must be UTC")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _evidence_refs(values: tuple[str, ...]) -> tuple[str, ...]:
    refs = tuple(dict.fromkeys(_compact(v, "evidence_ref", max_len=256) for v in values))
    return refs


@dataclass(frozen=True)
class HealthPolicyConfig:
    """Deterministic health thresholds supplied by policy/config, never model output."""

    failure_samples_to_degraded: int = 2
    failure_samples_to_unreachable: int = 3
    recovery_samples_to_healthy: int = 2
    data_gap_after_seconds: int = 300

    def validate(self) -> "HealthPolicyConfig":
        degraded = _bounded_int(self.failure_samples_to_degraded, "failure_samples_to_degraded", minimum=1, maximum=64)
        unreachable = _bounded_int(self.failure_samples_to_unreachable, "failure_samples_to_unreachable", minimum=2, maximum=128)
        recovery = _bounded_int(self.recovery_samples_to_healthy, "recovery_samples_to_healthy", minimum=1, maximum=64)
        gap = _bounded_int(self.data_gap_after_seconds, "data_gap_after_seconds", minimum=1, maximum=86400)
        if unreachable <= degraded:
            raise MonitoringContractError("failure_samples_to_unreachable must exceed failure_samples_to_degraded")
        object.__setattr__(self, "failure_samples_to_degraded", degraded)
        object.__setattr__(self, "failure_samples_to_unreachable", unreachable)
        object.__setattr__(self, "recovery_samples_to_healthy", recovery)
        object.__setattr__(self, "data_gap_after_seconds", gap)
        return self

    def to_dict(self) -> dict[str, int]:
        self.validate()
        return {
            "data_gap_after_seconds": self.data_gap_after_seconds,
            "failure_samples_to_degraded": self.failure_samples_to_degraded,
            "failure_samples_to_unreachable": self.failure_samples_to_unreachable,
            "recovery_samples_to_healthy": self.recovery_samples_to_healthy,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


@dataclass(frozen=True)
class HealthStateRecord:
    """Interpreted health state; deliberately separate from raw ObservationRecord."""

    asset_id: str
    state: str
    evaluated_at: str
    evidence_refs: tuple[str, ...] = ()
    reason_code: str | None = None
    schema_version: str = HEALTH_STATE_SCHEMA

    def validate(self) -> "HealthStateRecord":
        object.__setattr__(self, "asset_id", _compact(self.asset_id, "asset_id", max_len=128))
        if self.state not in HEALTH_STATES:
            raise MonitoringContractError(f"unsupported health state: {self.state}")
        object.__setattr__(self, "evaluated_at", _utc_timestamp(self.evaluated_at, "evaluated_at"))
        object.__setattr__(self, "evidence_refs", _evidence_refs(self.evidence_refs))
        if self.reason_code is not None:
            object.__setattr__(self, "reason_code", _compact(self.reason_code, "reason_code", max_len=128))
        if self.schema_version != HEALTH_STATE_SCHEMA:
            raise MonitoringContractError(f"unsupported health state schema: {self.schema_version}")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "asset_id": self.asset_id,
            "evaluated_at": self.evaluated_at,
            "evidence_refs": list(self.evidence_refs),
            "reason_code": self.reason_code,
            "schema_version": self.schema_version,
            "state": self.state,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


@dataclass(frozen=True)
class HealthTransitionRecord:
    """Durable interpretation change with explicit evidence lineage."""

    asset_id: str
    previous_state: str
    current_state: str
    transitioned_at: str
    evidence_refs: tuple[str, ...]
    reason_code: str
    policy_fingerprint: str
    schema_version: str = HEALTH_TRANSITION_SCHEMA

    def validate(self) -> "HealthTransitionRecord":
        object.__setattr__(self, "asset_id", _compact(self.asset_id, "asset_id", max_len=128))
        if self.previous_state not in HEALTH_STATES or self.current_state not in HEALTH_STATES:
            raise MonitoringContractError("transition contains unsupported health state")
        if self.previous_state == self.current_state:
            raise MonitoringContractError("health transition must change state")
        object.__setattr__(self, "transitioned_at", _utc_timestamp(self.transitioned_at, "transitioned_at"))
        refs = _evidence_refs(self.evidence_refs)
        if not refs:
            raise MonitoringContractError("health transition requires evidence_refs")
        object.__setattr__(self, "evidence_refs", refs)
        object.__setattr__(self, "reason_code", _compact(self.reason_code, "reason_code", max_len=128))
        fingerprint = str(self.policy_fingerprint or "").strip()
        if not fingerprint.startswith("sha256:") or len(fingerprint) != 71:
            raise MonitoringContractError("policy_fingerprint must be a sha256 digest")
        object.__setattr__(self, "policy_fingerprint", fingerprint.lower())
        if self.schema_version != HEALTH_TRANSITION_SCHEMA:
            raise MonitoringContractError(f"unsupported health transition schema: {self.schema_version}")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "asset_id": self.asset_id,
            "current_state": self.current_state,
            "evidence_refs": list(self.evidence_refs),
            "policy_fingerprint": self.policy_fingerprint,
            "previous_state": self.previous_state,
            "reason_code": self.reason_code,
            "schema_version": self.schema_version,
            "transitioned_at": self.transitioned_at,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())
