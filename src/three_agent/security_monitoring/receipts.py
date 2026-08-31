from __future__ import annotations

import re
from dataclasses import dataclass, field

from .contracts import MonitoringContractError, _compact, _iso_timestamp

REPORT_STATUSES = {"completed", "partial", "failed", "pending_nas"}
ARCHIVE_STATUSES = {"archived", "pending_nas", "failed"}
PERIOD_KINDS = {"daily", "weekly", "monthly"}


def _sha256(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", text):
        raise MonitoringContractError(f"{field_name} must be a SHA-256 fingerprint")
    return text


@dataclass(frozen=True)
class ReportReceipt:
    report_id: str
    period_kind: str
    period_key: str
    cutoff_at: str
    status: str
    coverage_pct: float
    bundle_ref: str
    manifest_sha256: str
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)
    ai_status: str = "not_requested"
    archive_status: str = "pending_nas"
    schema_version: str = "workspace-security-monitoring/report-receipt-v1"

    def validate(self) -> "ReportReceipt":
        object.__setattr__(self, "report_id", _compact(self.report_id, "report_id", max_len=128))
        if self.period_kind not in PERIOD_KINDS:
            raise MonitoringContractError("unsupported report period_kind")
        object.__setattr__(self, "period_key", _compact(self.period_key, "period_key", max_len=128))
        object.__setattr__(self, "cutoff_at", _iso_timestamp(self.cutoff_at, "cutoff_at"))
        if self.status not in REPORT_STATUSES:
            raise MonitoringContractError("unsupported report status")
        if not 0.0 <= self.coverage_pct <= 100.0:
            raise MonitoringContractError("coverage_pct must be within [0,100]")
        object.__setattr__(self, "bundle_ref", _compact(self.bundle_ref, "bundle_ref"))
        object.__setattr__(self, "manifest_sha256", _sha256(self.manifest_sha256, "manifest_sha256"))
        refs = tuple(_compact(v, "evidence_ref") for v in self.evidence_refs)
        object.__setattr__(self, "evidence_refs", refs)
        if self.ai_status not in {"not_requested", "valid", "unavailable", "invalid", "fallback"}:
            raise MonitoringContractError("unsupported ai_status")
        if self.archive_status not in ARCHIVE_STATUSES:
            raise MonitoringContractError("unsupported archive_status")
        return self


@dataclass(frozen=True)
class ArchiveReceipt:
    archive_id: str
    period_kind: str
    period_key: str
    status: str
    bundle_ref: str
    manifest_sha256: str
    attempt: int
    updated_at: str
    failure_code: str | None = None
    schema_version: str = "workspace-security-monitoring/archive-receipt-v1"

    def validate(self) -> "ArchiveReceipt":
        object.__setattr__(self, "archive_id", _compact(self.archive_id, "archive_id", max_len=128))
        if self.period_kind not in PERIOD_KINDS:
            raise MonitoringContractError("unsupported archive period_kind")
        object.__setattr__(self, "period_key", _compact(self.period_key, "period_key", max_len=128))
        if self.status not in ARCHIVE_STATUSES:
            raise MonitoringContractError("unsupported archive status")
        object.__setattr__(self, "bundle_ref", _compact(self.bundle_ref, "bundle_ref"))
        object.__setattr__(self, "manifest_sha256", _sha256(self.manifest_sha256, "manifest_sha256"))
        if self.attempt < 1:
            raise MonitoringContractError("archive attempt must be >= 1")
        object.__setattr__(self, "updated_at", _iso_timestamp(self.updated_at, "updated_at"))
        if self.failure_code is not None:
            object.__setattr__(self, "failure_code", _compact(self.failure_code, "failure_code", max_len=96))
        if self.status == "failed" and not self.failure_code:
            raise MonitoringContractError("failed archive requires failure_code")
        return self
