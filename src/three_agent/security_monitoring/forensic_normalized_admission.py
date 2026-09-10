from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re

from .contracts import APPROVED_DATA_CLASSES, MonitoringContractError
from .forensic_evidence import (
    CaseAuthorization,
    EvidenceObject,
    EvidenceProvenance as ForensicEvidenceProvenance,
    ForensicEventTime,
)
from .normalized_evidence import NormalizedEvidence, NormalizedEvidenceError

NORMALIZED_FORENSIC_ADMISSION_SCHEMA = "workspace-security-forensics/normalized-admission-v1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

NORMALIZED_TO_FORENSIC_TYPE = {
    "snmp_observation": "other_metadata",
    "log_event": "host_log",
    "pcap_summary": "pcap",
    "dns_event": "dns",
    "network_flow": "flow",
    "authentication_event": "authentication",
    "process_event": "process",
    "correlation_result": "other_metadata",
}


def _sha(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not _SHA256_RE.fullmatch(text):
        raise MonitoringContractError(f"{field_name} must be a SHA-256 fingerprint")
    return text


def _utc(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MonitoringContractError(f"{field_name} must include timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class NormalizedEvidenceAdmissionScope:
    task_ref_sha256: str
    authorization_ref_sha256: str
    case_authorization_fingerprint: str
    allowed_sensitivities: tuple[str, ...]
    source_clock_ref: str
    clock_uncertainty_ms: int = 0
    schema_version: str = NORMALIZED_FORENSIC_ADMISSION_SCHEMA

    def validate(self) -> "NormalizedEvidenceAdmissionScope":
        object.__setattr__(self, "task_ref_sha256", _sha(self.task_ref_sha256, "task_ref_sha256"))
        object.__setattr__(
            self,
            "authorization_ref_sha256",
            _sha(self.authorization_ref_sha256, "authorization_ref_sha256"),
        )
        object.__setattr__(
            self,
            "case_authorization_fingerprint",
            _sha(self.case_authorization_fingerprint, "case_authorization_fingerprint"),
        )
        sensitivities = tuple(sorted(str(value or "").strip() for value in self.allowed_sensitivities))
        if not sensitivities or len(sensitivities) != len(set(sensitivities)):
            raise MonitoringContractError("allowed_sensitivities must be non-empty and unique")
        if set(sensitivities) - APPROVED_DATA_CLASSES:
            raise MonitoringContractError("allowed_sensitivities contains unsupported data class")
        object.__setattr__(self, "allowed_sensitivities", sensitivities)
        clock_ref = str(self.source_clock_ref or "").strip()
        if not clock_ref or len(clock_ref) > 128 or "://" in clock_ref or "\\" in clock_ref:
            raise MonitoringContractError("source_clock_ref must be a compact local reference")
        object.__setattr__(self, "source_clock_ref", clock_ref)
        if isinstance(self.clock_uncertainty_ms, bool) or not isinstance(self.clock_uncertainty_ms, int):
            raise MonitoringContractError("clock_uncertainty_ms must be an integer")
        if not 0 <= self.clock_uncertainty_ms <= 86_400_000:
            raise MonitoringContractError("clock_uncertainty_ms must be within 0..86400000")
        if self.schema_version != NORMALIZED_FORENSIC_ADMISSION_SCHEMA:
            raise MonitoringContractError("unsupported normalized forensic admission schema")
        return self


def normalized_to_forensic_evidence(
    normalized: NormalizedEvidence,
    *,
    case_authorization: CaseAuthorization,
    admission_scope: NormalizedEvidenceAdmissionScope,
) -> EvidenceObject:
    """Admit already-normalized evidence into the canonical forensic metadata contract.

    This adapter performs no collection, file reads, network access, model calls or
    remediation. It only verifies existing task/authorization/asset/sensitivity
    lineage and projects metadata into the canonical EvidenceObject.
    """

    if not isinstance(normalized, NormalizedEvidence):
        raise MonitoringContractError("normalized forensic admission requires NormalizedEvidence")
    try:
        normalized.validate()
    except NormalizedEvidenceError as exc:
        raise MonitoringContractError(f"normalized evidence rejected: {exc}") from exc
    if not isinstance(case_authorization, CaseAuthorization):
        raise MonitoringContractError("normalized forensic admission requires CaseAuthorization")
    case_authorization.validate()
    if not isinstance(admission_scope, NormalizedEvidenceAdmissionScope):
        raise MonitoringContractError("normalized forensic admission scope type is invalid")
    admission_scope.validate()

    if admission_scope.case_authorization_fingerprint != case_authorization.fingerprint:
        raise MonitoringContractError("case authorization fingerprint mismatch")
    if normalized.task_ref_sha256 != admission_scope.task_ref_sha256:
        raise MonitoringContractError("normalized evidence task lineage mismatch")
    if normalized.authorization_ref_sha256 != admission_scope.authorization_ref_sha256:
        raise MonitoringContractError("normalized evidence authorization lineage mismatch")
    if normalized.asset_ref not in case_authorization.approved_asset_refs:
        raise MonitoringContractError("normalized evidence asset is outside forensic case scope")
    if normalized.sensitivity not in admission_scope.allowed_sensitivities:
        raise MonitoringContractError("normalized evidence sensitivity is outside admission scope")

    forensic_type = NORMALIZED_TO_FORENSIC_TYPE.get(normalized.evidence_type)
    if forensic_type is None:
        raise MonitoringContractError("normalized evidence type has no forensic mapping")
    if forensic_type not in case_authorization.allowed_evidence_types:
        raise MonitoringContractError("mapped forensic evidence type is outside case authorization")

    event_time = ForensicEventTime(
        original_timestamp=normalized.observation_window.end_at,
        normalized_utc=_utc(normalized.observation_window.end_at, "observation_window.end_at"),
        source_clock_ref=admission_scope.source_clock_ref,
        uncertainty_ms=admission_scope.clock_uncertainty_ms,
    ).validate()
    provenance = ForensicEvidenceProvenance(
        source_id=normalized.asset_ref,
        source_type=normalized.source_type,
        collected_at=normalized.collected_at,
        producer_id=normalized.provenance.producer,
        producer_version=normalized.provenance.parser_version,
        source_content_sha256=normalized.integrity.source_record_sha256,
    ).validate()

    return EvidenceObject(
        evidence_id=normalized.evidence_id,
        evidence_type=forensic_type,
        content_sha256=normalized.integrity.content_sha256,
        byte_size=0,
        data_class=normalized.sensitivity,
        provenance=provenance,
        event_time=event_time,
        derived=False,
        immutable=True,
        payload_embedded=False,
    ).validate()
