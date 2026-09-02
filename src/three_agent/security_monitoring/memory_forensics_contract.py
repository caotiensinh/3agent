from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint

MEMORY_OBSERVATION_SCHEMA = "workspace-security-forensics/memory-observation-v1"
MEMORY_ASSESSMENT_SCHEMA = "workspace-security-forensics/memory-assessment-v1"
MEMORY_OBSERVATION_TYPES = frozenset(
    {
        "process",
        "hidden_process",
        "socket",
        "module",
        "code_injection",
        "command_history",
        "suspicious_handle",
        "kernel_anomaly",
        "yara_match",
    }
)
HIGH_SIGNAL_MEMORY_TYPES = frozenset({"hidden_process", "code_injection", "kernel_anomaly", "yara_match"})
MAX_MEMORY_OBSERVATIONS = 8192
MAX_MEMORY_CANDIDATES = 1024

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$")


def _identifier(value: str, field_name: str, *, max_len: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or not _ID_RE.fullmatch(text):
        raise MonitoringContractError(f"{field_name} must be a compact identifier")
    if "://" in text or "/" in text or "\\" in text:
        raise MonitoringContractError(f"{field_name} must not expose raw content, URLs, or filesystem paths")
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
class MemoryForensicObservation:
    observation_id: str
    asset_ref: str
    observation_type: str
    subject_ref: str
    observed_at: str
    evidence_ref: str
    indicator_present: bool
    externally_corroborated: bool = False
    raw_payload_embedded: bool = False
    schema_version: str = MEMORY_OBSERVATION_SCHEMA

    def validate(self) -> "MemoryForensicObservation":
        object.__setattr__(self, "observation_id", _identifier(self.observation_id, "observation_id", max_len=128))
        object.__setattr__(self, "asset_ref", _identifier(self.asset_ref, "asset_ref", max_len=128))
        if self.observation_type not in MEMORY_OBSERVATION_TYPES:
            raise MonitoringContractError("unsupported memory observation type")
        object.__setattr__(self, "subject_ref", _identifier(self.subject_ref, "subject_ref", max_len=160))
        object.__setattr__(self, "observed_at", _timestamp(self.observed_at, "observed_at"))
        object.__setattr__(self, "evidence_ref", _identifier(self.evidence_ref, "evidence_ref", max_len=128))
        _strict_bool(self.indicator_present, "indicator_present")
        _strict_bool(self.externally_corroborated, "externally_corroborated")
        _strict_bool(self.raw_payload_embedded, "raw_payload_embedded")
        if self.raw_payload_embedded:
            raise MonitoringContractError("raw memory payload must not be embedded in the analysis contract")
        if self.schema_version != MEMORY_OBSERVATION_SCHEMA:
            raise MonitoringContractError("unsupported memory observation schema")
        return self


@dataclass(frozen=True)
class MemoryForensicCandidate:
    candidate_id: str
    asset_ref: str
    subject_ref: str
    observation_types: tuple[str, ...]
    reasons: tuple[str, ...]
    confidence: float
    evidence_refs: tuple[str, ...]
    first_seen: str
    last_seen: str


@dataclass(frozen=True)
class MemoryForensicAssessment:
    candidates: tuple[MemoryForensicCandidate, ...]
    observations_analyzed: int
    acquisition_performed: bool = False
    authority: str = "advisory"
    schema_version: str = MEMORY_ASSESSMENT_SCHEMA

    def validate(self) -> "MemoryForensicAssessment":
        if isinstance(self.observations_analyzed, bool) or not isinstance(self.observations_analyzed, int):
            raise MonitoringContractError("observations_analyzed must be an integer")
        if not 0 <= self.observations_analyzed <= MAX_MEMORY_OBSERVATIONS:
            raise MonitoringContractError("observations_analyzed is out of bounds")
        _strict_bool(self.acquisition_performed, "acquisition_performed")
        if self.acquisition_performed:
            raise MonitoringContractError("memory analyzer must not perform acquisition")
        if len(self.candidates) > MAX_MEMORY_CANDIDATES:
            raise MonitoringContractError("memory candidate bound exceeded")
        for candidate in self.candidates:
            _identifier(candidate.candidate_id, "candidate_id", max_len=128)
            _identifier(candidate.asset_ref, "asset_ref", max_len=128)
            _identifier(candidate.subject_ref, "subject_ref", max_len=160)
            if not candidate.observation_types or any(kind not in MEMORY_OBSERVATION_TYPES for kind in candidate.observation_types):
                raise MonitoringContractError("memory candidate observation types are invalid")
            if not candidate.reasons:
                raise MonitoringContractError("memory candidate requires supporting reasons")
            if not 0.0 <= candidate.confidence <= 1.0:
                raise MonitoringContractError("memory candidate confidence must be within [0,1]")
            if not candidate.evidence_refs:
                raise MonitoringContractError("memory candidate requires evidence refs")
            _timestamp(candidate.first_seen, "first_seen")
            _timestamp(candidate.last_seen, "last_seen")
        if self.authority != "advisory":
            raise MonitoringContractError("memory assessment must remain advisory")
        if self.schema_version != MEMORY_ASSESSMENT_SCHEMA:
            raise MonitoringContractError("unsupported memory assessment schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "candidates": [asdict(candidate) for candidate in self.candidates],
            "observations_analyzed": self.observations_analyzed,
            "acquisition_performed": self.acquisition_performed,
            "authority": self.authority,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


def assess_memory_observations(
    observations: Iterable[MemoryForensicObservation],
) -> MemoryForensicAssessment:
    """Assess normalized outputs from an external memory-forensics adapter.

    WorkSpace receives only typed metadata and evidence references. This module
    cannot dump RAM, attach to a process, execute a plugin, preserve raw command
    history, or embed memory bytes.
    """

    rows = tuple(row.validate() for row in observations)
    if len(rows) > MAX_MEMORY_OBSERVATIONS:
        raise MonitoringContractError("memory observation bound exceeded")
    grouped: dict[tuple[str, str], list[MemoryForensicObservation]] = {}
    for row in rows:
        if row.indicator_present:
            grouped.setdefault((row.asset_ref, row.subject_ref), []).append(row)

    candidates: list[MemoryForensicCandidate] = []
    for key in sorted(grouped):
        group = sorted(grouped[key], key=lambda row: (row.observed_at, row.observation_id))
        observation_types = tuple(sorted({row.observation_type for row in group}))
        evidence_refs = tuple(sorted({row.evidence_ref for row in group}))
        reasons: set[str] = {f"memory_{kind}" for kind in observation_types}
        if len(evidence_refs) >= 2:
            reasons.add("multi_evidence_corroboration")
        if any(row.externally_corroborated for row in group):
            reasons.add("external_corroboration")
        high_signal = bool(set(observation_types) & HIGH_SIGNAL_MEMORY_TYPES)
        corroborated = len(evidence_refs) >= 2 or any(row.externally_corroborated for row in group)
        if not (high_signal and corroborated):
            continue
        ordered_reasons = tuple(sorted(reasons))
        confidence = 0.4
        confidence += min(0.24, 0.08 * len(observation_types))
        if "multi_evidence_corroboration" in reasons:
            confidence += 0.16
        if "external_corroboration" in reasons:
            confidence += 0.12
        confidence = round(min(0.95, confidence), 2)
        identity = {
            "asset_ref": key[0],
            "subject_ref": key[1],
            "evidence_refs": evidence_refs,
            "schema": MEMORY_ASSESSMENT_SCHEMA,
        }
        candidates.append(
            MemoryForensicCandidate(
                candidate_id="memory:" + sha256_fingerprint(identity).split(":", 1)[1][:24],
                asset_ref=key[0],
                subject_ref=key[1],
                observation_types=observation_types,
                reasons=ordered_reasons,
                confidence=confidence,
                evidence_refs=evidence_refs,
                first_seen=group[0].observed_at,
                last_seen=group[-1].observed_at,
            )
        )
        if len(candidates) > MAX_MEMORY_CANDIDATES:
            raise MonitoringContractError("memory candidate bound exceeded")

    candidates.sort(key=lambda item: (-item.confidence, item.asset_ref, item.subject_ref))
    return MemoryForensicAssessment(tuple(candidates), len(rows)).validate()
