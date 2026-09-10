from __future__ import annotations

import re
from dataclasses import dataclass

from .contracts import APPROVED_DATA_CLASSES, MonitoringContractError, sha256_fingerprint

PRIVACY_RECEIPT_SCHEMA = "workspace-security-monitoring/evidence-privacy-receipt-v1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _sha(value: str, field: str) -> str:
    text = str(value or "").strip()
    if not _SHA256_RE.fullmatch(text):
        raise MonitoringContractError(f"{field} must be SHA-256")
    return text


def _compact(value: str, field: str, max_len: int = 128) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or "://" in text or any(ch.isspace() for ch in text):
        raise MonitoringContractError(f"{field} must be a bounded compact identifier")
    return text


@dataclass(frozen=True)
class EvidencePrivacyReceipt:
    evidence_ref: str
    sensitivity: str
    redaction_policy_sha256: str
    source_record_sha256: str
    retained_payload_sha256: str
    raw_payload_retained: bool = False
    credentials_retained: bool = False
    secrets_retained: bool = False
    schema_version: str = PRIVACY_RECEIPT_SCHEMA

    def validate(self) -> "EvidencePrivacyReceipt":
        if self.schema_version != PRIVACY_RECEIPT_SCHEMA:
            raise MonitoringContractError("unsupported privacy receipt schema")
        object.__setattr__(self, "evidence_ref", _compact(self.evidence_ref, "evidence_ref"))
        if self.sensitivity not in APPROVED_DATA_CLASSES:
            raise MonitoringContractError("unsupported sensitivity classification")
        object.__setattr__(self, "redaction_policy_sha256", _sha(self.redaction_policy_sha256, "redaction_policy_sha256"))
        object.__setattr__(self, "source_record_sha256", _sha(self.source_record_sha256, "source_record_sha256"))
        object.__setattr__(self, "retained_payload_sha256", _sha(self.retained_payload_sha256, "retained_payload_sha256"))
        if self.raw_payload_retained or self.credentials_retained or self.secrets_retained:
            raise MonitoringContractError("privacy receipt forbids raw payload, credential, or secret retention")
        return self

    @property
    def receipt_id(self) -> str:
        self.validate()
        identity = {
            "schema_version": self.schema_version,
            "evidence_ref": self.evidence_ref,
            "sensitivity": self.sensitivity,
            "redaction_policy_sha256": self.redaction_policy_sha256,
            "source_record_sha256": self.source_record_sha256,
            "retained_payload_sha256": self.retained_payload_sha256,
            "raw_payload_retained": self.raw_payload_retained,
            "credentials_retained": self.credentials_retained,
            "secrets_retained": self.secrets_retained,
        }
        return "privacy-receipt:" + sha256_fingerprint(identity).split(":", 1)[1][:24]
