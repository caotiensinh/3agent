from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint

ANTI_FORENSICS_OBSERVATION_SCHEMA = "workspace-security-forensics/anti-forensics-observation-v1"
ANTI_FORENSICS_ASSESSMENT_SCHEMA = "workspace-security-forensics/anti-forensics-assessment-v1"
ANTI_FORENSICS_TYPES = frozenset(
    {
        "log_clear",
        "audit_disabled",
        "edr_disabled",
        "telemetry_gap",
        "timestamp_anomaly",
        "history_deleted",
        "log_service_stopped",
    }
)
DESTRUCTIVE_TYPES = frozenset(
    {"log_clear", "audit_disabled", "edr_disabled", "history_deleted", "log_service_stopped"}
)
MAX_ANTI_FORENSICS_OBSERVATIONS = 4096
MAX_ANTI_FORENSICS_FINDINGS = 512

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
class AntiForensicsObservation:
    observation_id: str
    asset_ref: str
    observation_type: str
    observed_at: str
    evidence_ref: str
    indicator_present: bool
    externally_corroborated: bool = False
    schema_version: str = ANTI_FORENSICS_OBSERVATION_SCHEMA

    def validate(self) -> "AntiForensicsObservation":
        object.__setattr__(self, "observation_id", _identifier(self.observation_id, "observation_id", max_len=128))
        object.__setattr__(self, "asset_ref", _identifier(self.asset_ref, "asset_ref", max_len=128))
        if self.observation_type not in ANTI_FORENSICS_TYPES:
            raise MonitoringContractError("unsupported anti-forensics observation type")
        object.__setattr__(self, "observed_at", _timestamp(self.observed_at, "observed_at"))
        object.__setattr__(self, "evidence_ref", _identifier(self.evidence_ref, "evidence_ref", max_len=128))
        _strict_bool(self.indicator_present, "indicator_present")
        _strict_bool(self.externally_corroborated, "externally_corroborated")
        if self.schema_version != ANTI_FORENSICS_OBSERVATION_SCHEMA:
            raise MonitoringContractError("unsupported anti-forensics observation schema")
        return self


@dataclass(frozen=True)
class AntiForensicsFinding:
    finding_id: str
    asset_ref: str
    indicators: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    confidence: float
    first_seen: str
    last_seen: str
    evidence_integrity_degraded: bool


@dataclass(frozen=True)
class AntiForensicsAssessment:
    findings: tuple[AntiForensicsFinding, ...]
    observations_analyzed: int
    evidence_absence_interpretation: str = "unknown_not_clean"
    authority: str = "advisory"
    schema_version: str = ANTI_FORENSICS_ASSESSMENT_SCHEMA

    def validate(self) -> "AntiForensicsAssessment":
        if isinstance(self.observations_analyzed, bool) or not isinstance(self.observations_analyzed, int):
            raise MonitoringContractError("observations_analyzed must be an integer")
        if not 0 <= self.observations_analyzed <= MAX_ANTI_FORENSICS_OBSERVATIONS:
            raise MonitoringContractError("observations_analyzed is out of bounds")
        if len(self.findings) > MAX_ANTI_FORENSICS_FINDINGS:
            raise MonitoringContractError("anti-forensics finding bound exceeded")
        for finding in self.findings:
            _identifier(finding.finding_id, "finding_id", max_len=128)
            _identifier(finding.asset_ref, "asset_ref", max_len=128)
            if not finding.indicators or any(kind not in ANTI_FORENSICS_TYPES for kind in finding.indicators):
                raise MonitoringContractError("anti-forensics finding indicators are invalid")
            if not finding.evidence_refs:
                raise MonitoringContractError("anti-forensics finding requires evidence refs")
            if not 0.0 <= finding.confidence <= 1.0:
                raise MonitoringContractError("anti-forensics confidence must be within [0,1]")
            _timestamp(finding.first_seen, "first_seen")
            _timestamp(finding.last_seen, "last_seen")
            _strict_bool(finding.evidence_integrity_degraded, "evidence_integrity_degraded")
        if self.evidence_absence_interpretation != "unknown_not_clean":
            raise MonitoringContractError("evidence absence must not be interpreted as a clean host")
        if self.authority != "advisory":
            raise MonitoringContractError("anti-forensics assessment must remain advisory")
        if self.schema_version != ANTI_FORENSICS_ASSESSMENT_SCHEMA:
            raise MonitoringContractError("unsupported anti-forensics assessment schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "findings": [asdict(finding) for finding in self.findings],
            "observations_analyzed": self.observations_analyzed,
            "evidence_absence_interpretation": self.evidence_absence_interpretation,
            "authority": self.authority,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


def detect_anti_forensics(
    observations: Iterable[AntiForensicsObservation],
) -> AntiForensicsAssessment:
    """Detect evidence-integrity degradation from already-collected telemetry.

    Missing telemetry is never treated as proof that no attack occurred. The
    result remains an advisory evidence-quality finding and does not modify audit
    policy, EDR configuration, logs, or endpoints.
    """

    rows = tuple(row.validate() for row in observations)
    if len(rows) > MAX_ANTI_FORENSICS_OBSERVATIONS:
        raise MonitoringContractError("anti-forensics observation bound exceeded")
    grouped: dict[str, list[AntiForensicsObservation]] = {}
    for row in rows:
        if row.indicator_present:
            grouped.setdefault(row.asset_ref, []).append(row)

    findings: list[AntiForensicsFinding] = []
    for asset_ref in sorted(grouped):
        group = sorted(grouped[asset_ref], key=lambda row: (row.observed_at, row.observation_id))
        indicators = tuple(sorted({row.observation_type for row in group}))
        evidence_refs = tuple(sorted({row.evidence_ref for row in group}))
        destructive = bool(set(indicators) & DESTRUCTIVE_TYPES)
        corroborated = len(evidence_refs) >= 2 or any(row.externally_corroborated for row in group)
        if not (destructive and corroborated):
            continue
        confidence = 0.42
        confidence += min(0.28, 0.07 * len(indicators))
        if len(evidence_refs) >= 2:
            confidence += 0.12
        if any(row.externally_corroborated for row in group):
            confidence += 0.1
        confidence = round(min(0.95, confidence), 2)
        identity = {
            "asset_ref": asset_ref,
            "indicators": indicators,
            "evidence_refs": evidence_refs,
            "schema": ANTI_FORENSICS_ASSESSMENT_SCHEMA,
        }
        findings.append(
            AntiForensicsFinding(
                finding_id="antiforensics:" + sha256_fingerprint(identity).split(":", 1)[1][:24],
                asset_ref=asset_ref,
                indicators=indicators,
                evidence_refs=evidence_refs,
                confidence=confidence,
                first_seen=group[0].observed_at,
                last_seen=group[-1].observed_at,
                evidence_integrity_degraded=True,
            )
        )
        if len(findings) > MAX_ANTI_FORENSICS_FINDINGS:
            raise MonitoringContractError("anti-forensics finding bound exceeded")

    findings.sort(key=lambda item: (-item.confidence, item.asset_ref))
    return AntiForensicsAssessment(tuple(findings), len(rows)).validate()
