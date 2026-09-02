from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .analyst_finding import AnalystFinding
from .contracts import canonical_json, sha256_fingerprint
from .evidence_lineage import EvidenceLineageReceipt
from .normalized_evidence import NormalizedEvidenceBatch

EVIDENCE_ANALYSIS_AUDIT_SCHEMA = "workspace-security-evidence-analysis-audit-record/v1"
EVIDENCE_ANALYSIS_AUDIT_VERIFY_SCHEMA = "workspace-security-evidence-analysis-audit-verification/v1"
EVIDENCE_ANALYSIS_EVENT = "ANALYST_FINDING_RECORDED"
MAX_ANALYSIS_AUDIT_RECORD_BYTES = 16 * 1024

_SHA256_PREFIX = "sha256:"
_SHA256_HEX_LENGTH = 64


class EvidenceAnalysisAuditError(ValueError):
    """Finding audit evidence is malformed or its hash chain is invalid."""


class EvidenceAnalysisAuditBusy(BlockingIOError):
    """The single-writer finding audit lock is currently held."""


def _sha(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not text.startswith(_SHA256_PREFIX):
        raise EvidenceAnalysisAuditError(f"{field_name} must be SHA-256")
    digest = text[len(_SHA256_PREFIX) :]
    if len(digest) != _SHA256_HEX_LENGTH or any(ch not in "0123456789abcdef" for ch in digest):
        raise EvidenceAnalysisAuditError(f"{field_name} must be SHA-256")
    return text


def _utc(value: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceAnalysisAuditError("occurred_at must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceAnalysisAuditError("occurred_at must include timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class EvidenceAnalysisAuditRecord:
    record_index: int
    occurred_at: str
    task_ref_sha256: str
    workflow_audit_anchor_sha256: str
    evidence_batch_sha256: str
    lineage_receipt_sha256: str
    finding_sha256: str
    previous_record_sha256: str
    record_sha256: str = ""
    event_type: str = EVIDENCE_ANALYSIS_EVENT
    authority: str = "advisory"
    automatic_action_allowed: bool = False
    schema_version: str = EVIDENCE_ANALYSIS_AUDIT_SCHEMA

    def _identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "record_index": self.record_index,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at,
            "task_ref_sha256": self.task_ref_sha256,
            "workflow_audit_anchor_sha256": self.workflow_audit_anchor_sha256,
            "evidence_batch_sha256": self.evidence_batch_sha256,
            "lineage_receipt_sha256": self.lineage_receipt_sha256,
            "finding_sha256": self.finding_sha256,
            "previous_record_sha256": self.previous_record_sha256,
            "authority": self.authority,
            "automatic_action_allowed": self.automatic_action_allowed,
        }

    def validate(self) -> "EvidenceAnalysisAuditRecord":
        if self.schema_version != EVIDENCE_ANALYSIS_AUDIT_SCHEMA:
            raise EvidenceAnalysisAuditError("unsupported evidence analysis audit schema")
        if isinstance(self.record_index, bool) or not isinstance(self.record_index, int) or self.record_index < 1:
            raise EvidenceAnalysisAuditError("record_index must be a positive integer")
        if self.event_type != EVIDENCE_ANALYSIS_EVENT:
            raise EvidenceAnalysisAuditError("unsupported evidence analysis event")
        object.__setattr__(self, "occurred_at", _utc(self.occurred_at))
        for field_name, value in (
            ("task_ref_sha256", self.task_ref_sha256),
            ("workflow_audit_anchor_sha256", self.workflow_audit_anchor_sha256),
            ("evidence_batch_sha256", self.evidence_batch_sha256),
            ("lineage_receipt_sha256", self.lineage_receipt_sha256),
            ("finding_sha256", self.finding_sha256),
            ("previous_record_sha256", self.previous_record_sha256),
        ):
            _sha(value, field_name)
        if not isinstance(self.automatic_action_allowed, bool):
            raise EvidenceAnalysisAuditError("finding audit automatic_action_allowed must be boolean")
        if self.authority != "advisory" or self.automatic_action_allowed:
            raise EvidenceAnalysisAuditError("finding audit cannot grant automatic action authority")
        expected = sha256_fingerprint(self._identity_payload())
        if self.record_sha256 != expected:
            raise EvidenceAnalysisAuditError("record_sha256 does not match finding audit content")
        return self

    @classmethod
    def build(
        cls,
        *,
        record_index: int,
        occurred_at: str,
        task_ref_sha256: str,
        workflow_audit_anchor_sha256: str,
        evidence_batch_sha256: str,
        lineage_receipt_sha256: str,
        finding_sha256: str,
        previous_record_sha256: str,
    ) -> "EvidenceAnalysisAuditRecord":
        base = cls(
            record_index=record_index,
            occurred_at=_utc(occurred_at),
            task_ref_sha256=task_ref_sha256,
            workflow_audit_anchor_sha256=workflow_audit_anchor_sha256,
            evidence_batch_sha256=evidence_batch_sha256,
            lineage_receipt_sha256=lineage_receipt_sha256,
            finding_sha256=finding_sha256,
            previous_record_sha256=previous_record_sha256,
        )
        result = cls(**{**asdict(base), "record_sha256": sha256_fingerprint(base._identity_payload())})
        return result.validate()

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {**self._identity_payload(), "record_sha256": self.record_sha256}

    def to_json(self) -> str:
        return canonical_json(self.public_dict())

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "EvidenceAnalysisAuditRecord":
        expected = {
            "schema_version",
            "record_index",
            "event_type",
            "occurred_at",
            "task_ref_sha256",
            "workflow_audit_anchor_sha256",
            "evidence_batch_sha256",
            "lineage_receipt_sha256",
            "finding_sha256",
            "previous_record_sha256",
            "authority",
            "automatic_action_allowed",
            "record_sha256",
        }
        if set(payload) != expected:
            raise EvidenceAnalysisAuditError("finding audit record fields do not match schema")
        return cls(
            schema_version=str(payload["schema_version"]),
            record_index=payload["record_index"],
            event_type=str(payload["event_type"]),
            occurred_at=str(payload["occurred_at"]),
            task_ref_sha256=str(payload["task_ref_sha256"]),
            workflow_audit_anchor_sha256=str(payload["workflow_audit_anchor_sha256"]),
            evidence_batch_sha256=str(payload["evidence_batch_sha256"]),
            lineage_receipt_sha256=str(payload["lineage_receipt_sha256"]),
            finding_sha256=str(payload["finding_sha256"]),
            previous_record_sha256=str(payload["previous_record_sha256"]),
            authority=str(payload["authority"]),
            automatic_action_allowed=payload["automatic_action_allowed"],
            record_sha256=str(payload["record_sha256"]),
        ).validate()


@dataclass(frozen=True)
class EvidenceAnalysisAuditVerification:
    record_count: int
    anchor_record_sha256: str
    last_record_sha256: str
    valid: bool = True
    schema_version: str = EVIDENCE_ANALYSIS_AUDIT_VERIFY_SCHEMA

    def validate(self) -> "EvidenceAnalysisAuditVerification":
        if self.schema_version != EVIDENCE_ANALYSIS_AUDIT_VERIFY_SCHEMA:
            raise EvidenceAnalysisAuditError("unsupported finding audit verification schema")
        if isinstance(self.record_count, bool) or not isinstance(self.record_count, int) or self.record_count < 1:
            raise EvidenceAnalysisAuditError("finding audit verification requires at least one record")
        _sha(self.anchor_record_sha256, "anchor_record_sha256")
        _sha(self.last_record_sha256, "last_record_sha256")
        if not self.valid:
            raise EvidenceAnalysisAuditError("invalid finding audit chain must fail closed")
        return self


class EvidenceAnalysisAuditJournal:
    """Append-only finding journal anchored to an already-verified workflow audit record."""

    def __init__(
        self,
        path: str | Path,
        *,
        anchor_record_sha256: str,
        lock_timeout_seconds: float = 2.0,
    ) -> None:
        raw = Path(path)
        if not raw.is_absolute():
            raise EvidenceAnalysisAuditError("finding audit journal path must be absolute")
        if not 0.1 <= float(lock_timeout_seconds) <= 30.0:
            raise EvidenceAnalysisAuditError("finding audit lock timeout must be within 0.1..30 seconds")
        self.path = raw
        self.lock_path = raw.with_name(raw.name + ".lock")
        self.anchor_record_sha256 = _sha(anchor_record_sha256, "anchor_record_sha256")
        self.lock_timeout_seconds = float(lock_timeout_seconds)

    def _validate_paths(self) -> None:
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if parent.is_symlink():
            raise EvidenceAnalysisAuditError("finding audit parent symlink denied")
        if self.path.exists() and self.path.is_symlink():
            raise EvidenceAnalysisAuditError("finding audit journal symlink denied")
        if self.lock_path.exists() and self.lock_path.is_symlink():
            raise EvidenceAnalysisAuditError("finding audit lock symlink denied")

    @staticmethod
    def _open_flags(base: int) -> int:
        flags = base
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        return flags

    def _acquire_lock(self) -> int:
        self._validate_paths()
        deadline = time.monotonic() + self.lock_timeout_seconds
        while True:
            try:
                return os.open(
                    self.lock_path,
                    self._open_flags(os.O_CREAT | os.O_EXCL | os.O_WRONLY),
                    0o600,
                )
            except FileExistsError:
                if time.monotonic() >= deadline:
                    raise EvidenceAnalysisAuditBusy("EVIDENCE_ANALYSIS_AUDIT_BUSY")
                time.sleep(0.01)

    def _release_lock(self, fd: int) -> None:
        try:
            os.close(fd)
        finally:
            try:
                self.lock_path.unlink()
            except FileNotFoundError:
                pass

    def _records_unlocked(self) -> tuple[EvidenceAnalysisAuditRecord, ...]:
        if not self.path.exists():
            return ()
        records: list[EvidenceAnalysisAuditRecord] = []
        previous = self.anchor_record_sha256
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, raw in enumerate(handle, 1):
                text = raw.rstrip("\n")
                if not text:
                    raise EvidenceAnalysisAuditError(f"empty finding audit record at line {line_number}")
                if len(text.encode("utf-8")) > MAX_ANALYSIS_AUDIT_RECORD_BYTES:
                    raise EvidenceAnalysisAuditError("finding audit record exceeds size bound")
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise EvidenceAnalysisAuditError(f"invalid finding audit JSON at line {line_number}") from exc
                if not isinstance(payload, dict):
                    raise EvidenceAnalysisAuditError("finding audit record must be a JSON object")
                record = EvidenceAnalysisAuditRecord.from_dict(payload)
                if record.record_index != line_number:
                    raise EvidenceAnalysisAuditError("finding audit record_index is not contiguous")
                if record.workflow_audit_anchor_sha256 != self.anchor_record_sha256:
                    raise EvidenceAnalysisAuditError("finding audit workflow anchor changed")
                if record.previous_record_sha256 != previous:
                    raise EvidenceAnalysisAuditError("finding audit hash chain is broken")
                records.append(record)
                previous = record.record_sha256
        return tuple(records)

    def append(
        self,
        *,
        finding: AnalystFinding,
        batch: NormalizedEvidenceBatch,
        lineage_receipt: EvidenceLineageReceipt,
        occurred_at: str,
    ) -> EvidenceAnalysisAuditRecord:
        finding.validate()
        batch.validate()
        lineage_receipt.validate()
        if finding.task_ref_sha256 != lineage_receipt.task_ref_sha256:
            raise EvidenceAnalysisAuditError("finding task does not match lineage receipt")
        if finding.audit_record_sha256 != self.anchor_record_sha256:
            raise EvidenceAnalysisAuditError("finding is not linked to the configured workflow audit anchor")
        if finding.lineage_receipt.public_dict() != lineage_receipt.public_dict():
            raise EvidenceAnalysisAuditError("finding lineage receipt does not match validated lineage")
        if batch.fingerprint != lineage_receipt.evidence_batch_fingerprint:
            raise EvidenceAnalysisAuditError("evidence batch does not match validated lineage receipt")

        fd = self._acquire_lock()
        try:
            records = self._records_unlocked()
            previous = records[-1].record_sha256 if records else self.anchor_record_sha256
            record = EvidenceAnalysisAuditRecord.build(
                record_index=len(records) + 1,
                occurred_at=occurred_at,
                task_ref_sha256=finding.task_ref_sha256,
                workflow_audit_anchor_sha256=self.anchor_record_sha256,
                evidence_batch_sha256=batch.fingerprint,
                lineage_receipt_sha256=sha256_fingerprint(lineage_receipt.public_dict()),
                finding_sha256=finding.identity_sha256,
                previous_record_sha256=previous,
            )
            encoded = record.to_json() + "\n"
            if len(encoded.encode("utf-8")) > MAX_ANALYSIS_AUDIT_RECORD_BYTES:
                raise EvidenceAnalysisAuditError("finding audit record exceeds size bound")
            journal_fd = os.open(
                self.path,
                self._open_flags(os.O_APPEND | os.O_CREAT | os.O_WRONLY),
                0o600,
            )
            try:
                os.write(journal_fd, encoded.encode("utf-8"))
                os.fsync(journal_fd)
            finally:
                os.close(journal_fd)
            return record
        finally:
            self._release_lock(fd)

    def records(self) -> tuple[EvidenceAnalysisAuditRecord, ...]:
        fd = self._acquire_lock()
        try:
            return self._records_unlocked()
        finally:
            self._release_lock(fd)

    def verify(self) -> EvidenceAnalysisAuditVerification:
        records = self.records()
        if not records:
            raise EvidenceAnalysisAuditError("finding audit journal is empty")
        return EvidenceAnalysisAuditVerification(
            record_count=len(records),
            anchor_record_sha256=self.anchor_record_sha256,
            last_record_sha256=records[-1].record_sha256,
        ).validate()
