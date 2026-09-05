from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint

PERSISTENCE_OBSERVATION_SCHEMA = "workspace-security-forensics/persistence-observation-v1"
PERSISTENCE_HUNT_SCHEMA = "workspace-security-forensics/persistence-hunt-v1"
PERSISTENCE_MECHANISMS = frozenset(
    {
        "service",
        "scheduled_task",
        "run_key",
        "startup_item",
        "wmi_subscription",
        "autorun_extension",
        "logon_script",
    }
)
MAX_PERSISTENCE_OBSERVATIONS = 4096
MAX_PERSISTENCE_CANDIDATES = 512

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$")


def _identifier(value: str, field_name: str, *, max_len: int = 256) -> str:
    text = str(value or "").strip()
    if "://" in text or "\\" in text or "/" in text:
        raise MonitoringContractError(f"{field_name} must not expose a URL or filesystem path")
    if not text or len(text) > max_len or not _ID_RE.fullmatch(text):
        raise MonitoringContractError(f"{field_name} must be a compact identifier")
    return text


def _timestamp(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MonitoringContractError(f"{field_name} must include timezone")
    return text


def _strict_bool(value: bool, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise MonitoringContractError(f"{field_name} must be boolean")
    return value


@dataclass(frozen=True)
class PersistenceObservation:
    observation_id: str
    asset_ref: str
    mechanism: str
    target_ref: str
    observed_at: str
    evidence_ref: str
    new_or_changed: bool
    unsigned_target: bool
    user_writable_target: bool
    high_privilege_context: bool
    enabled: bool = True
    user_ref: str | None = None
    schema_version: str = PERSISTENCE_OBSERVATION_SCHEMA

    def validate(self) -> "PersistenceObservation":
        object.__setattr__(self, "observation_id", _identifier(self.observation_id, "observation_id", max_len=128))
        object.__setattr__(self, "asset_ref", _identifier(self.asset_ref, "asset_ref", max_len=128))
        if self.mechanism not in PERSISTENCE_MECHANISMS:
            raise MonitoringContractError("unsupported persistence mechanism")
        object.__setattr__(self, "target_ref", _identifier(self.target_ref, "target_ref", max_len=160))
        object.__setattr__(self, "observed_at", _timestamp(self.observed_at, "observed_at"))
        object.__setattr__(self, "evidence_ref", _identifier(self.evidence_ref, "evidence_ref", max_len=128))
        for name in (
            "new_or_changed",
            "unsigned_target",
            "user_writable_target",
            "high_privilege_context",
            "enabled",
        ):
            _strict_bool(getattr(self, name), name)
        if self.user_ref is not None:
            object.__setattr__(self, "user_ref", _identifier(self.user_ref, "user_ref", max_len=128))
        if self.schema_version != PERSISTENCE_OBSERVATION_SCHEMA:
            raise MonitoringContractError("unsupported persistence observation schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class PersistenceCandidate:
    candidate_id: str
    asset_ref: str
    mechanism: str
    target_ref: str
    user_ref: str | None
    reasons: tuple[str, ...]
    confidence: float
    evidence_refs: tuple[str, ...]
    first_seen: str
    last_seen: str


@dataclass(frozen=True)
class PersistenceHuntAssessment:
    candidates: tuple[PersistenceCandidate, ...]
    observations_analyzed: int
    authority: str = "advisory"
    schema_version: str = PERSISTENCE_HUNT_SCHEMA

    def validate(self) -> "PersistenceHuntAssessment":
        if isinstance(self.observations_analyzed, bool) or not isinstance(self.observations_analyzed, int):
            raise MonitoringContractError("observations_analyzed must be an integer")
        if not 0 <= self.observations_analyzed <= MAX_PERSISTENCE_OBSERVATIONS:
            raise MonitoringContractError("observations_analyzed is out of bounds")
        if len(self.candidates) > MAX_PERSISTENCE_CANDIDATES:
            raise MonitoringContractError("persistence candidate bound exceeded")
        candidate_ids: set[str] = set()
        for candidate in self.candidates:
            _identifier(candidate.candidate_id, "candidate_id", max_len=128)
            if candidate.candidate_id in candidate_ids:
                raise MonitoringContractError("persistence candidate ids must be unique")
            candidate_ids.add(candidate.candidate_id)
            _identifier(candidate.asset_ref, "asset_ref", max_len=128)
            if candidate.mechanism not in PERSISTENCE_MECHANISMS:
                raise MonitoringContractError("unsupported persistence candidate mechanism")
            _identifier(candidate.target_ref, "target_ref", max_len=160)
            if candidate.user_ref is not None:
                _identifier(candidate.user_ref, "user_ref", max_len=128)
            if not candidate.reasons:
                raise MonitoringContractError("persistence candidates require evidence-backed reasons")
            for reason in candidate.reasons:
                _identifier(reason, "reason", max_len=96)
            if not 0.0 <= candidate.confidence <= 1.0:
                raise MonitoringContractError("candidate confidence must be within [0,1]")
            if not candidate.evidence_refs:
                raise MonitoringContractError("persistence candidates require evidence refs")
            for ref in candidate.evidence_refs:
                _identifier(ref, "evidence_ref", max_len=128)
            _timestamp(candidate.first_seen, "first_seen")
            _timestamp(candidate.last_seen, "last_seen")
        if self.authority != "advisory":
            raise MonitoringContractError("persistence hunt must remain advisory")
        if self.schema_version != PERSISTENCE_HUNT_SCHEMA:
            raise MonitoringContractError("unsupported persistence hunt schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "candidates": [asdict(candidate) for candidate in self.candidates],
            "observations_analyzed": self.observations_analyzed,
            "authority": self.authority,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


def _reasons(row: PersistenceObservation) -> tuple[str, ...]:
    reasons: list[str] = []
    if row.new_or_changed:
        reasons.append("new_or_changed")
    if row.unsigned_target:
        reasons.append("unsigned_target")
    if row.user_writable_target:
        reasons.append("user_writable_target")
    if row.high_privilege_context:
        reasons.append("high_privilege_context")
    if row.enabled:
        reasons.append("enabled_persistence")
    return tuple(reasons)


def _confidence(reasons: tuple[str, ...]) -> float:
    weights = {
        "new_or_changed": 0.24,
        "unsigned_target": 0.18,
        "user_writable_target": 0.24,
        "high_privilege_context": 0.18,
        "enabled_persistence": 0.08,
    }
    return round(min(0.95, sum(weights[reason] for reason in reasons)), 2)


def hunt_persistence(
    observations: Iterable[PersistenceObservation],
    *,
    minimum_reasons: int = 2,
) -> PersistenceHuntAssessment:
    """Identify evidence-backed persistence candidates without active host actions.

    A single indicator is intentionally insufficient by default. The function
    consumes already-collected metadata and never reads the registry, filesystem,
    services, scheduler, WMI, or a remote endpoint itself.
    """

    if isinstance(minimum_reasons, bool) or not isinstance(minimum_reasons, int) or not 1 <= minimum_reasons <= 5:
        raise MonitoringContractError("minimum_reasons must be within 1..5")
    rows = tuple(row.validate() for row in observations)
    if len(rows) > MAX_PERSISTENCE_OBSERVATIONS:
        raise MonitoringContractError("persistence observation bound exceeded")

    grouped: dict[tuple[str, str, str, str | None], list[PersistenceObservation]] = {}
    for row in rows:
        key = (row.asset_ref, row.mechanism, row.target_ref, row.user_ref)
        grouped.setdefault(key, []).append(row)

    candidates: list[PersistenceCandidate] = []
    for key in sorted(grouped, key=lambda item: tuple("" if value is None else value for value in item)):
        group = sorted(grouped[key], key=lambda row: (row.observed_at, row.observation_id))
        combined_reasons = tuple(sorted({reason for row in group for reason in _reasons(row)}))
        if len(combined_reasons) < minimum_reasons:
            continue
        evidence_refs = tuple(sorted({row.evidence_ref for row in group}))
        identity = {
            "asset_ref": key[0],
            "mechanism": key[1],
            "target_ref": key[2],
            "user_ref": key[3],
            "evidence_refs": evidence_refs,
            "schema": PERSISTENCE_HUNT_SCHEMA,
        }
        candidate_id = "persistence:" + sha256_fingerprint(identity).split(":", 1)[1][:24]
        candidates.append(
            PersistenceCandidate(
                candidate_id=candidate_id,
                asset_ref=key[0],
                mechanism=key[1],
                target_ref=key[2],
                user_ref=key[3],
                reasons=combined_reasons,
                confidence=_confidence(combined_reasons),
                evidence_refs=evidence_refs,
                first_seen=group[0].observed_at,
                last_seen=group[-1].observed_at,
            )
        )
        if len(candidates) > MAX_PERSISTENCE_CANDIDATES:
            raise MonitoringContractError("persistence candidate bound exceeded")

    candidates.sort(key=lambda item: (-item.confidence, item.asset_ref, item.mechanism, item.target_ref))
    return PersistenceHuntAssessment(
        candidates=tuple(candidates),
        observations_analyzed=len(rows),
    ).validate()
