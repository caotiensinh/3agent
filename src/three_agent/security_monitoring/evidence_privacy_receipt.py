from __future__ import annotations

import re
from dataclasses import dataclass

from .contracts import APPROVED_DATA_CLASSES, MonitoringContractError, sha256_fingerprint

PRIVACY_RECEIPT_SCHEMA = "workspace-security-monitoring/evidence-privacy-receipt-v1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_ID_RE = re.compile(r"^evidence:[0-9a-f]{24}$")


def _sha(value: str, field: str) -> str:
    text = str(value or "").strip()
    if not _SHA256_RE.fullmatch(text):
        raise MonitoringContractError(f"{field} must be SHA-256")
    return text


def _exact_false(value: bool, field: str) -> bool:
    if not isinstance(value, bool) or value is not False:
        raise MonitoringContractError(
            f"privacy receipt forbids {field}; value must be exact boolean False"
        )
    return value


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
        evidence_ref = str(self.evidence_ref or "").strip()
        if not _EVIDENCE_ID_RE.fullmatch(evidence_ref):
            raise MonitoringContractError("evidence_ref must reference canonical evidence")
        object.__setattr__(self, "evidence_ref", evidence_ref)
        if self.sensitivity not in APPROVED_DATA_CLASSES:
            raise MonitoringContractError("unsupported sensitivity classification")
        object.__setattr__(
            self,
            "redaction_policy_sha256",
            _sha(self.redaction_policy_sha256, "redaction_policy_sha256"),
        )
        object.__setattr__(
            self,
            "source_record_sha256",
            _sha(self.source_record_sha256, "source_record_sha256"),
        )
        object.__setattr__(
            self,
            "retained_payload_sha256",
            _sha(self.retained_payload_sha256, "retained_payload_sha256"),
        )
        _exact_false(self.raw_payload_retained, "raw payload retention")
        _exact_false(self.credentials_retained, "credential retention")
        _exact_false(self.secrets_retained, "secret retention")
        return self

    def identity_dict(self) -> dict[str, object]:
        self.validate()
        return {
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

    @property
    def receipt_id(self) -> str:
        return "privacy-receipt:" + sha256_fingerprint(self.identity_dict()).split(":", 1)[1][:24]

    def public_dict(self) -> dict[str, object]:
        return {"receipt_id": self.receipt_id, **self.identity_dict()}
