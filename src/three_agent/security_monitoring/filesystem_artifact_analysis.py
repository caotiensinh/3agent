from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint

FILESYSTEM_ARTIFACT_SCHEMA = "workspace-security-forensics/filesystem-artifact-observation-v1"
FILESYSTEM_ANALYSIS_SCHEMA = "workspace-security-forensics/filesystem-artifact-analysis-v1"
FILESYSTEM_ARTIFACT_TYPES = frozenset({"mft", "amcache", "shimcache", "prefetch", "srum", "registry"})
MAX_FILESYSTEM_ARTIFACTS = 8192
MAX_FILESYSTEM_CANDIDATES = 1024

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$")


def _identifier(value: str, field_name: str, *, max_len: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or not _ID_RE.fullmatch(text):
        raise MonitoringContractError(f"{field_name} must be a compact identifier")
    if "://" in text or "/" in text or "\\" in text:
        raise MonitoringContractError(f"{field_name} must not expose a URL or filesystem path")
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
class FilesystemArtifactObservation:
    observation_id: str
    asset_ref: str
    artifact_type: str
    file_ref: str
    observed_at: str
    evidence_ref: str
    execution_observed: bool = False
    recently_created: bool = False
    deleted_or_missing: bool = False
    timestamp_anomaly: bool = False
    schema_version: str = FILESYSTEM_ARTIFACT_SCHEMA

    def validate(self) -> "FilesystemArtifactObservation":
        object.__setattr__(self, "observation_id", _identifier(self.observation_id, "observation_id", max_len=128))
        object.__setattr__(self, "asset_ref", _identifier(self.asset_ref, "asset_ref", max_len=128))
        if self.artifact_type not in FILESYSTEM_ARTIFACT_TYPES:
            raise MonitoringContractError("unsupported filesystem artifact type")
        object.__setattr__(self, "file_ref", _identifier(self.file_ref, "file_ref", max_len=160))
        object.__setattr__(self, "observed_at", _timestamp(self.observed_at, "observed_at"))
        object.__setattr__(self, "evidence_ref", _identifier(self.evidence_ref, "evidence_ref", max_len=128))
        for name in ("execution_observed", "recently_created", "deleted_or_missing", "timestamp_anomaly"):
            _strict_bool(getattr(self, name), name)
        if self.schema_version != FILESYSTEM_ARTIFACT_SCHEMA:
            raise MonitoringContractError("unsupported filesystem artifact observation schema")
        return self


@dataclass(frozen=True)
class FilesystemArtifactCandidate:
    candidate_id: str
    asset_ref: str
    file_ref: str
    artifact_types: tuple[str, ...]
    reasons: tuple[str, ...]
    confidence: float
    evidence_refs: tuple[str, ...]
    first_seen: str
    last_seen: str


@dataclass(frozen=True)
class FilesystemArtifactAssessment:
    candidates: tuple[FilesystemArtifactCandidate, ...]
    observations_analyzed: int
    authority: str = "advisory"
    schema_version: str = FILESYSTEM_ANALYSIS_SCHEMA

    def validate(self) -> "FilesystemArtifactAssessment":
        if isinstance(self.observations_analyzed, bool) or not isinstance(self.observations_analyzed, int):
            raise MonitoringContractError("observations_analyzed must be an integer")
        if not 0 <= self.observations_analyzed <= MAX_FILESYSTEM_ARTIFACTS:
            raise MonitoringContractError("observations_analyzed is out of bounds")
        if len(self.candidates) > MAX_FILESYSTEM_CANDIDATES:
            raise MonitoringContractError("filesystem candidate bound exceeded")
        seen: set[str] = set()
        for candidate in self.candidates:
            _identifier(candidate.candidate_id, "candidate_id", max_len=128)
            if candidate.candidate_id in seen:
                raise MonitoringContractError("filesystem candidate ids must be unique")
            seen.add(candidate.candidate_id)
            _identifier(candidate.asset_ref, "asset_ref", max_len=128)
            _identifier(candidate.file_ref, "file_ref", max_len=160)
            if not candidate.artifact_types or any(kind not in FILESYSTEM_ARTIFACT_TYPES for kind in candidate.artifact_types):
                raise MonitoringContractError("filesystem candidate artifact types are invalid")
            if len(candidate.reasons) < 2:
                raise MonitoringContractError("filesystem candidate requires multiple supporting reasons")
            if not 0.0 <= candidate.confidence <= 1.0:
                raise MonitoringContractError("filesystem candidate confidence must be within [0,1]")
            if not candidate.evidence_refs:
                raise MonitoringContractError("filesystem candidate requires evidence refs")
            _timestamp(candidate.first_seen, "first_seen")
            _timestamp(candidate.last_seen, "last_seen")
        if self.authority != "advisory":
            raise MonitoringContractError("filesystem analysis must remain advisory")
        if self.schema_version != FILESYSTEM_ANALYSIS_SCHEMA:
            raise MonitoringContractError("unsupported filesystem analysis schema")
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


def analyze_filesystem_artifacts(
    observations: Iterable[FilesystemArtifactObservation],
) -> FilesystemArtifactAssessment:
    """Correlate already-collected filesystem metadata without acquiring files.

    Raw paths and file contents are intentionally excluded. Callers provide typed
    file references and immutable evidence references produced by authorized
    collectors or imported forensic datasets.
    """

    rows = tuple(row.validate() for row in observations)
    if len(rows) > MAX_FILESYSTEM_ARTIFACTS:
        raise MonitoringContractError("filesystem artifact input bound exceeded")
    grouped: dict[tuple[str, str], list[FilesystemArtifactObservation]] = {}
    for row in rows:
        grouped.setdefault((row.asset_ref, row.file_ref), []).append(row)

    candidates: list[FilesystemArtifactCandidate] = []
    for key in sorted(grouped):
        group = sorted(grouped[key], key=lambda row: (row.observed_at, row.observation_id))
        artifact_types = tuple(sorted({row.artifact_type for row in group}))
        reasons: set[str] = set()
        if len(artifact_types) >= 2:
            reasons.add("multi_artifact_corroboration")
        if any(row.execution_observed for row in group):
            reasons.add("execution_observed")
        if any(row.recently_created for row in group):
            reasons.add("recently_created")
        if any(row.deleted_or_missing for row in group):
            reasons.add("deleted_or_missing")
        if any(row.timestamp_anomaly for row in group):
            reasons.add("timestamp_anomaly")
        ordered_reasons = tuple(sorted(reasons))
        if len(ordered_reasons) < 2:
            continue
        evidence_refs = tuple(sorted({row.evidence_ref for row in group}))
        weights = {
            "multi_artifact_corroboration": 0.28,
            "execution_observed": 0.28,
            "recently_created": 0.14,
            "deleted_or_missing": 0.14,
            "timestamp_anomaly": 0.16,
        }
        confidence = round(min(0.95, sum(weights[reason] for reason in ordered_reasons)), 2)
        identity = {
            "asset_ref": key[0],
            "file_ref": key[1],
            "evidence_refs": evidence_refs,
            "schema": FILESYSTEM_ANALYSIS_SCHEMA,
        }
        candidates.append(
            FilesystemArtifactCandidate(
                candidate_id="fsartifact:" + sha256_fingerprint(identity).split(":", 1)[1][:24],
                asset_ref=key[0],
                file_ref=key[1],
                artifact_types=artifact_types,
                reasons=ordered_reasons,
                confidence=confidence,
                evidence_refs=evidence_refs,
                first_seen=group[0].observed_at,
                last_seen=group[-1].observed_at,
            )
        )
        if len(candidates) > MAX_FILESYSTEM_CANDIDATES:
            raise MonitoringContractError("filesystem candidate bound exceeded")

    candidates.sort(key=lambda item: (-item.confidence, item.asset_ref, item.file_ref))
    return FilesystemArtifactAssessment(tuple(candidates), len(rows)).validate()
