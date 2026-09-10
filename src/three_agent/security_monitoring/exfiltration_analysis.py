from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint

EXFIL_FLOW_SCHEMA = "workspace-security-forensics/exfil-flow-observation-v1"
EXFIL_ASSESSMENT_SCHEMA = "workspace-security-forensics/exfiltration-assessment-v1"
EXFIL_PROTOCOLS = frozenset({"tls", "http", "dns", "ssh", "other"})
MAX_EXFIL_FLOWS = 50_000
MAX_EXFIL_CANDIDATES = 1024
MAX_FLOW_BYTES = 10 * 1024 * 1024 * 1024 * 1024

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$")


def _identifier(value: str, field_name: str, *, max_len: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or not _ID_RE.fullmatch(text):
        raise MonitoringContractError(f"{field_name} must be a compact identifier")
    if "://" in text or "/" in text or "\\" in text:
        raise MonitoringContractError(f"{field_name} must not expose a URL, payload, or filesystem path")
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


def _bytes(value: int, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_FLOW_BYTES:
        raise MonitoringContractError(f"{field_name} is outside the allowed byte bound")
    return value


@dataclass(frozen=True)
class ExfiltrationFlowObservation:
    flow_id: str
    asset_ref: str
    destination_ref: str
    protocol: str
    observed_at: str
    evidence_ref: str
    bytes_out: int
    baseline_p95_bytes: int
    destination_previously_seen: bool
    process_ref: str | None = None
    user_ref: str | None = None
    payload_inspected: bool = False
    schema_version: str = EXFIL_FLOW_SCHEMA

    def validate(self) -> "ExfiltrationFlowObservation":
        object.__setattr__(self, "flow_id", _identifier(self.flow_id, "flow_id", max_len=128))
        object.__setattr__(self, "asset_ref", _identifier(self.asset_ref, "asset_ref", max_len=128))
        object.__setattr__(self, "destination_ref", _identifier(self.destination_ref, "destination_ref", max_len=160))
        if self.protocol not in EXFIL_PROTOCOLS:
            raise MonitoringContractError("unsupported exfiltration protocol")
        object.__setattr__(self, "observed_at", _timestamp(self.observed_at, "observed_at"))
        object.__setattr__(self, "evidence_ref", _identifier(self.evidence_ref, "evidence_ref", max_len=128))
        _bytes(self.bytes_out, "bytes_out")
        _bytes(self.baseline_p95_bytes, "baseline_p95_bytes")
        _strict_bool(self.destination_previously_seen, "destination_previously_seen")
        _strict_bool(self.payload_inspected, "payload_inspected")
        if self.payload_inspected:
            raise MonitoringContractError("exfiltration analyzer must remain metadata-only")
        if self.process_ref is not None:
            object.__setattr__(self, "process_ref", _identifier(self.process_ref, "process_ref", max_len=128))
        if self.user_ref is not None:
            object.__setattr__(self, "user_ref", _identifier(self.user_ref, "user_ref", max_len=128))
        if self.schema_version != EXFIL_FLOW_SCHEMA:
            raise MonitoringContractError("unsupported exfiltration flow schema")
        return self


@dataclass(frozen=True)
class ExfiltrationCandidate:
    candidate_id: str
    asset_ref: str
    destination_ref: str
    protocol: str
    process_refs: tuple[str, ...]
    user_refs: tuple[str, ...]
    reasons: tuple[str, ...]
    total_bytes_out: int
    baseline_p95_bytes: int
    confidence: float
    evidence_refs: tuple[str, ...]
    first_seen: str
    last_seen: str


@dataclass(frozen=True)
class ExfiltrationAssessment:
    candidates: tuple[ExfiltrationCandidate, ...]
    flows_analyzed: int
    payload_inspected: bool = False
    authority: str = "advisory"
    schema_version: str = EXFIL_ASSESSMENT_SCHEMA

    def validate(self) -> "ExfiltrationAssessment":
        if isinstance(self.flows_analyzed, bool) or not isinstance(self.flows_analyzed, int):
            raise MonitoringContractError("flows_analyzed must be an integer")
        if not 0 <= self.flows_analyzed <= MAX_EXFIL_FLOWS:
            raise MonitoringContractError("flows_analyzed is out of bounds")
        _strict_bool(self.payload_inspected, "payload_inspected")
        if self.payload_inspected:
            raise MonitoringContractError("exfiltration assessment must remain metadata-only")
        if len(self.candidates) > MAX_EXFIL_CANDIDATES:
            raise MonitoringContractError("exfiltration candidate bound exceeded")
        for candidate in self.candidates:
            _identifier(candidate.candidate_id, "candidate_id", max_len=128)
            _identifier(candidate.asset_ref, "asset_ref", max_len=128)
            _identifier(candidate.destination_ref, "destination_ref", max_len=160)
            if candidate.protocol not in EXFIL_PROTOCOLS:
                raise MonitoringContractError("unsupported exfiltration candidate protocol")
            if len(candidate.reasons) < 2 or "anomalous_outbound_volume" not in candidate.reasons:
                raise MonitoringContractError("exfiltration candidate requires corroborated volume anomaly")
            _bytes(candidate.total_bytes_out, "total_bytes_out")
            _bytes(candidate.baseline_p95_bytes, "baseline_p95_bytes")
            if not 0.0 <= candidate.confidence <= 1.0:
                raise MonitoringContractError("exfiltration confidence must be within [0,1]")
            if not candidate.evidence_refs:
                raise MonitoringContractError("exfiltration candidate requires evidence refs")
            _timestamp(candidate.first_seen, "first_seen")
            _timestamp(candidate.last_seen, "last_seen")
        if self.authority != "advisory":
            raise MonitoringContractError("exfiltration assessment must remain advisory")
        if self.schema_version != EXFIL_ASSESSMENT_SCHEMA:
            raise MonitoringContractError("unsupported exfiltration assessment schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "candidates": [asdict(candidate) for candidate in self.candidates],
            "flows_analyzed": self.flows_analyzed,
            "payload_inspected": self.payload_inspected,
            "authority": self.authority,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


def analyze_exfiltration_metadata(
    flows: Iterable[ExfiltrationFlowObservation],
    *,
    minimum_total_bytes: int = 10_000_000,
    baseline_multiplier: float = 3.0,
) -> ExfiltrationAssessment:
    """Identify outbound-volume anomalies without inspecting packet payloads."""

    _bytes(minimum_total_bytes, "minimum_total_bytes")
    if isinstance(baseline_multiplier, bool) or not isinstance(baseline_multiplier, (int, float)):
        raise MonitoringContractError("baseline_multiplier must be numeric")
    baseline_multiplier = float(baseline_multiplier)
    if not 1.0 <= baseline_multiplier <= 100.0:
        raise MonitoringContractError("baseline_multiplier must be within [1,100]")

    rows = tuple(flow.validate() for flow in flows)
    if len(rows) > MAX_EXFIL_FLOWS:
        raise MonitoringContractError("exfiltration flow bound exceeded")
    grouped: dict[tuple[str, str, str], list[ExfiltrationFlowObservation]] = {}
    for flow in rows:
        grouped.setdefault((flow.asset_ref, flow.destination_ref, flow.protocol), []).append(flow)

    candidates: list[ExfiltrationCandidate] = []
    for key in sorted(grouped):
        group = sorted(grouped[key], key=lambda flow: (flow.observed_at, flow.flow_id))
        total_bytes = sum(flow.bytes_out for flow in group)
        if total_bytes > MAX_FLOW_BYTES:
            raise MonitoringContractError("aggregated outbound bytes exceed bound")
        baseline = max((flow.baseline_p95_bytes for flow in group), default=0)
        anomaly_threshold = max(minimum_total_bytes, int(baseline * baseline_multiplier))
        if total_bytes < anomaly_threshold:
            continue
        reasons = {"anomalous_outbound_volume"}
        if any(not flow.destination_previously_seen for flow in group):
            reasons.add("new_destination")
        evidence_refs = tuple(sorted({flow.evidence_ref for flow in group}))
        if len(evidence_refs) >= 2:
            reasons.add("multi_session_evidence")
        if key[2] == "dns" and total_bytes >= minimum_total_bytes:
            reasons.add("high_volume_dns_channel")
        ordered_reasons = tuple(sorted(reasons))
        if len(ordered_reasons) < 2:
            continue
        confidence = 0.5
        if "new_destination" in reasons:
            confidence += 0.16
        if "multi_session_evidence" in reasons:
            confidence += 0.14
        if "high_volume_dns_channel" in reasons:
            confidence += 0.14
        if baseline > 0 and total_bytes >= baseline * baseline_multiplier * 2:
            confidence += 0.08
        confidence = round(min(0.95, confidence), 2)
        process_refs = tuple(sorted({flow.process_ref for flow in group if flow.process_ref is not None}))
        user_refs = tuple(sorted({flow.user_ref for flow in group if flow.user_ref is not None}))
        identity = {
            "asset_ref": key[0],
            "destination_ref": key[1],
            "protocol": key[2],
            "evidence_refs": evidence_refs,
            "schema": EXFIL_ASSESSMENT_SCHEMA,
        }
        candidates.append(
            ExfiltrationCandidate(
                candidate_id="exfil:" + sha256_fingerprint(identity).split(":", 1)[1][:24],
                asset_ref=key[0],
                destination_ref=key[1],
                protocol=key[2],
                process_refs=process_refs,
                user_refs=user_refs,
                reasons=ordered_reasons,
                total_bytes_out=total_bytes,
                baseline_p95_bytes=baseline,
                confidence=confidence,
                evidence_refs=evidence_refs,
                first_seen=group[0].observed_at,
                last_seen=group[-1].observed_at,
            )
        )
        if len(candidates) > MAX_EXFIL_CANDIDATES:
            raise MonitoringContractError("exfiltration candidate bound exceeded")

    candidates.sort(key=lambda item: (-item.confidence, -item.total_bytes_out, item.asset_ref, item.destination_ref))
    return ExfiltrationAssessment(tuple(candidates), len(rows)).validate()
