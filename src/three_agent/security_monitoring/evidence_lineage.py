from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from .contracts import APPROVED_DATA_CLASSES, sha256_fingerprint
from .normalized_evidence import MAX_BATCH_EVIDENCE, NormalizedEvidenceBatch, NormalizedEvidenceError

EVIDENCE_LINEAGE_POLICY_SCHEMA = "workspace-security-evidence-lineage-policy/v1"
EVIDENCE_LINEAGE_RECEIPT_SCHEMA = "workspace-security-evidence-lineage-receipt/v1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_ID_RE = re.compile(r"^evidence:[0-9a-f]{24}$")
_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,255}$")


class EvidenceLineageError(ValueError):
    """Evidence lineage does not satisfy the reviewed task/inventory/integrity boundary."""


def _sha(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not _SHA256_RE.fullmatch(text):
        raise EvidenceLineageError(f"{field_name} must be SHA-256")
    return text


def _compact(value: str, field_name: str, *, max_len: int = 128) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or not _COMPACT_RE.fullmatch(text):
        raise EvidenceLineageError(f"{field_name} must be a bounded compact identifier")
    if "://" in text or ".." in text.split("/"):
        raise EvidenceLineageError(f"{field_name} contains an unsafe reference")
    return text


@dataclass(frozen=True)
class EvidenceLineagePolicy:
    task_ref_sha256: str
    approved_authorization_refs: tuple[str, ...]
    approved_asset_refs: tuple[str, ...]
    allowed_sensitivities: tuple[str, ...] = ("public", "internal", "confidential", "restricted")
    max_evidence: int = MAX_BATCH_EVIDENCE
    schema_version: str = EVIDENCE_LINEAGE_POLICY_SCHEMA

    def validate(self) -> "EvidenceLineagePolicy":
        if self.schema_version != EVIDENCE_LINEAGE_POLICY_SCHEMA:
            raise EvidenceLineageError("unsupported evidence lineage policy schema")
        object.__setattr__(self, "task_ref_sha256", _sha(self.task_ref_sha256, "task_ref_sha256"))
        auth = tuple(_sha(value, "approved_authorization_ref") for value in self.approved_authorization_refs)
        if not auth or len(auth) > 32 or len(set(auth)) != len(auth):
            raise EvidenceLineageError("approved authorization references must be non-empty, unique, and bounded")
        assets = tuple(_compact(value, "approved_asset_ref") for value in self.approved_asset_refs)
        if not assets or len(assets) > 512 or len(set(assets)) != len(assets):
            raise EvidenceLineageError("approved asset references must be non-empty, unique, and bounded")
        sensitivities = tuple(str(value or "").strip() for value in self.allowed_sensitivities)
        if not sensitivities or len(set(sensitivities)) != len(sensitivities):
            raise EvidenceLineageError("allowed sensitivities must be non-empty and unique")
        if set(sensitivities) - APPROVED_DATA_CLASSES:
            raise EvidenceLineageError("allowed sensitivities contain unsupported classifications")
        if isinstance(self.max_evidence, bool) or not isinstance(self.max_evidence, int) or not 1 <= self.max_evidence <= MAX_BATCH_EVIDENCE:
            raise EvidenceLineageError("max_evidence is outside the enterprise bound")
        object.__setattr__(self, "approved_authorization_refs", auth)
        object.__setattr__(self, "approved_asset_refs", assets)
        object.__setattr__(self, "allowed_sensitivities", sensitivities)
        return self

    @property
    def fingerprint(self) -> str:
        self.validate()
        return sha256_fingerprint(asdict(self))


@dataclass(frozen=True)
class EvidenceLineageReceipt:
    task_ref_sha256: str
    policy_fingerprint: str
    evidence_batch_fingerprint: str
    evidence_ids: tuple[str, ...]
    evidence_count: int
    status: str = "validated"
    reason_code: str = "EVIDENCE_LINEAGE_VALIDATED"
    authority: str = "advisory"
    automatic_action_allowed: bool = False
    schema_version: str = EVIDENCE_LINEAGE_RECEIPT_SCHEMA

    def validate(self) -> "EvidenceLineageReceipt":
        if self.schema_version != EVIDENCE_LINEAGE_RECEIPT_SCHEMA:
            raise EvidenceLineageError("unsupported evidence lineage receipt schema")
        for name, value in (("task_ref_sha256", self.task_ref_sha256), ("policy_fingerprint", self.policy_fingerprint), ("evidence_batch_fingerprint", self.evidence_batch_fingerprint)):
            _sha(value, name)
        if self.status != "validated" or self.reason_code != "EVIDENCE_LINEAGE_VALIDATED":
            raise EvidenceLineageError("lineage receipt must represent a validated gate result")
        if not isinstance(self.automatic_action_allowed, bool):
            raise EvidenceLineageError("lineage receipt automatic_action_allowed must be boolean")
        if self.authority != "advisory" or self.automatic_action_allowed:
            raise EvidenceLineageError("lineage receipt cannot grant automatic action authority")
        if isinstance(self.evidence_count, bool) or not isinstance(self.evidence_count, int):
            raise EvidenceLineageError("lineage receipt evidence_count must be an integer")
        if self.evidence_count != len(self.evidence_ids) or not 1 <= self.evidence_count <= MAX_BATCH_EVIDENCE:
            raise EvidenceLineageError("lineage receipt evidence count mismatch or bound exceeded")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise EvidenceLineageError("lineage receipt evidence IDs must be unique")
        if any(not _EVIDENCE_ID_RE.fullmatch(str(value or "")) for value in self.evidence_ids):
            raise EvidenceLineageError("lineage receipt contains invalid evidence ID")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {"schema_version": self.schema_version, "task_ref_sha256": self.task_ref_sha256, "policy_fingerprint": self.policy_fingerprint, "evidence_batch_fingerprint": self.evidence_batch_fingerprint, "evidence_ids": list(self.evidence_ids), "evidence_count": self.evidence_count, "status": self.status, "reason_code": self.reason_code, "authority": self.authority, "automatic_action_allowed": self.automatic_action_allowed}


class EvidenceLineageGate:
    """Fail-closed gate between normalized evidence and correlation/analysis."""

    def __init__(self, policy: EvidenceLineagePolicy) -> None:
        self.policy = policy.validate()

    def validate_batch(self, batch: NormalizedEvidenceBatch) -> EvidenceLineageReceipt:
        try:
            batch.validate()
        except NormalizedEvidenceError as exc:
            raise EvidenceLineageError(f"normalized evidence rejected: {exc}") from exc
        if len(batch.evidence) > self.policy.max_evidence:
            raise EvidenceLineageError("EVIDENCE_LINEAGE_BATCH_BOUND_EXCEEDED")
        approved_auth = set(self.policy.approved_authorization_refs)
        approved_assets = set(self.policy.approved_asset_refs)
        allowed_sensitivities = set(self.policy.allowed_sensitivities)
        for row in batch.evidence:
            if row.task_ref_sha256 != self.policy.task_ref_sha256:
                raise EvidenceLineageError("EVIDENCE_LINEAGE_TASK_MISMATCH")
            if row.authorization_ref_sha256 not in approved_auth:
                raise EvidenceLineageError("EVIDENCE_LINEAGE_AUTHORIZATION_MISMATCH")
            if row.asset_ref not in approved_assets:
                raise EvidenceLineageError("EVIDENCE_LINEAGE_ASSET_NOT_APPROVED")
            if row.sensitivity not in allowed_sensitivities:
                raise EvidenceLineageError("EVIDENCE_LINEAGE_SENSITIVITY_DENIED")
            if row.integrity.source_record_sha256 not in set(row.provenance.lineage_refs):
                raise EvidenceLineageError("EVIDENCE_LINEAGE_SOURCE_HASH_NOT_IN_PROVENANCE")
            if row.integrity.content_sha256 == row.task_ref_sha256 or row.integrity.content_sha256 == row.authorization_ref_sha256:
                raise EvidenceLineageError("EVIDENCE_LINEAGE_DOMAIN_HASH_COLLISION")
        return EvidenceLineageReceipt(task_ref_sha256=self.policy.task_ref_sha256, policy_fingerprint=self.policy.fingerprint, evidence_batch_fingerprint=batch.fingerprint, evidence_ids=tuple(row.evidence_id for row in batch.evidence), evidence_count=len(batch.evidence)).validate()
