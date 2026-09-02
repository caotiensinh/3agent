from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .contracts import MonitoringContractError, canonical_json, sha256_fingerprint

SECURITY_WORKFLOW_AUDIT_SCHEMA = "workspace-security-workflow-audit-record/v1"
SECURITY_WORKFLOW_AUDIT_VERIFY_SCHEMA = "workspace-security-workflow-audit-verification/v1"
AUDIT_EVENT_TYPES = frozenset(
    {
        "SESSION_PREPARED",
        "STEP_REQUESTED",
        "STEP_COMPLETED",
        "STEP_FAILED",
    }
)
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SESSION_RE = re.compile(r"^security-session:[0-9a-f]{24}$")
_STEP_RE = re.compile(r"^step:[0-9a-f]{24}$")
_INVOCATION_RE = re.compile(r"^invoke-[0-9a-f]{24}$")
_REASON_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
MAX_AUDIT_RECORD_BYTES = 16 * 1024
MAX_AUDIT_REASON_CODES = 16


class SecurityWorkflowAuditError(ValueError):
    """Audit record or journal integrity is invalid."""


class SecurityWorkflowAuditBusy(BlockingIOError):
    """The single-writer audit lock is currently held."""


def _sha(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not _SHA256_RE.fullmatch(text):
        raise SecurityWorkflowAuditError(f"{field_name} must be SHA-256")
    return text


def _utc(value: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SecurityWorkflowAuditError("occurred_at must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SecurityWorkflowAuditError("occurred_at must include timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _reasons(values: Iterable[str]) -> tuple[str, ...]:
    output = tuple(str(value or "").strip() for value in values)
    if len(output) > MAX_AUDIT_REASON_CODES:
        raise SecurityWorkflowAuditError("audit reason code bound exceeded")
    if len(set(output)) != len(output):
        raise SecurityWorkflowAuditError("audit reason codes must be unique")
    if any(not _REASON_RE.fullmatch(value) for value in output):
        raise SecurityWorkflowAuditError("audit reason code is invalid")
    return output


@dataclass(frozen=True)
class SecurityWorkflowAuditRecord:
    record_index: int
    event_type: str
    session_id: str
    occurred_at: str
    request_sha256: str
    plan_fingerprint: str
    binding_fingerprint: str
    workflow_fingerprint: str
    previous_record_sha256: str | None
    reason_codes: tuple[str, ...] = ()
    step_id: str | None = None
    input_fingerprint: str | None = None
    invocation_id: str | None = None
    record_sha256: str = ""
    schema_version: str = SECURITY_WORKFLOW_AUDIT_SCHEMA

    def validate(self) -> "SecurityWorkflowAuditRecord":
        if isinstance(self.record_index, bool) or not isinstance(self.record_index, int) or self.record_index < 1:
            raise SecurityWorkflowAuditError("record_index must be a positive integer")
        if self.event_type not in AUDIT_EVENT_TYPES:
            raise SecurityWorkflowAuditError("unsupported audit event_type")
        if not _SESSION_RE.fullmatch(str(self.session_id or "")):
            raise SecurityWorkflowAuditError("session_id is invalid")
        object.__setattr__(self, "occurred_at", _utc(self.occurred_at))
        for field_name, value in (
            ("request_sha256", self.request_sha256),
            ("plan_fingerprint", self.plan_fingerprint),
            ("binding_fingerprint", self.binding_fingerprint),
            ("workflow_fingerprint", self.workflow_fingerprint),
        ):
            _sha(value, field_name)
        if self.previous_record_sha256 is not None:
            _sha(self.previous_record_sha256, "previous_record_sha256")
        object.__setattr__(self, "reason_codes", _reasons(self.reason_codes))
        if self.step_id is not None and not _STEP_RE.fullmatch(str(self.step_id)):
            raise SecurityWorkflowAuditError("step_id is invalid")
        if self.input_fingerprint is not None:
            _sha(self.input_fingerprint, "input_fingerprint")
        if self.invocation_id is not None and not _INVOCATION_RE.fullmatch(str(self.invocation_id)):
            raise SecurityWorkflowAuditError("invocation_id is invalid")
        if self.schema_version != SECURITY_WORKFLOW_AUDIT_SCHEMA:
            raise SecurityWorkflowAuditError("unsupported workflow audit schema")

        if self.event_type == "SESSION_PREPARED":
            if self.step_id is not None or self.input_fingerprint is not None or self.invocation_id is not None:
                raise SecurityWorkflowAuditError("SESSION_PREPARED cannot contain step invocation fields")
        elif self.event_type == "STEP_REQUESTED":
            if self.step_id is None or self.input_fingerprint is None or self.invocation_id is not None:
                raise SecurityWorkflowAuditError("STEP_REQUESTED requires step_id and input_fingerprint only")
        elif self.event_type == "STEP_COMPLETED":
            if self.step_id is None or self.input_fingerprint is None or self.invocation_id is None:
                raise SecurityWorkflowAuditError("STEP_COMPLETED requires invocation lineage")
        elif self.event_type == "STEP_FAILED":
            if self.step_id is None or self.input_fingerprint is None or self.invocation_id is not None:
                raise SecurityWorkflowAuditError("STEP_FAILED requires failed step/input lineage")
            if not self.reason_codes:
                raise SecurityWorkflowAuditError("STEP_FAILED requires reason_codes")

        expected = sha256_fingerprint(self._identity_payload())
        if self.record_sha256 != expected:
            raise SecurityWorkflowAuditError("record_sha256 does not match audit record content")
        return self

    def _identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "record_index": self.record_index,
            "event_type": self.event_type,
            "session_id": self.session_id,
            "occurred_at": self.occurred_at,
            "request_sha256": self.request_sha256,
            "plan_fingerprint": self.plan_fingerprint,
            "binding_fingerprint": self.binding_fingerprint,
            "workflow_fingerprint": self.workflow_fingerprint,
            "previous_record_sha256": self.previous_record_sha256,
            "reason_codes": list(self.reason_codes),
            "step_id": self.step_id,
            "input_fingerprint": self.input_fingerprint,
            "invocation_id": self.invocation_id,
        }

    @classmethod
    def build(
        cls,
        *,
        record_index: int,
        event_type: str,
        session_id: str,
        request_sha256: str,
        plan_fingerprint: str,
        binding_fingerprint: str,
        workflow_fingerprint: str,
        previous_record_sha256: str | None,
        reason_codes: tuple[str, ...] = (),
        step_id: str | None = None,
        input_fingerprint: str | None = None,
        invocation_id: str | None = None,
        occurred_at: str | None = None,
    ) -> "SecurityWorkflowAuditRecord":
        base = cls(
            record_index=record_index,
            event_type=event_type,
            session_id=session_id,
            occurred_at=occurred_at or _now_utc(),
            request_sha256=request_sha256,
            plan_fingerprint=plan_fingerprint,
            binding_fingerprint=binding_fingerprint,
            workflow_fingerprint=workflow_fingerprint,
            previous_record_sha256=previous_record_sha256,
            reason_codes=reason_codes,
            step_id=step_id,
            input_fingerprint=input_fingerprint,
            invocation_id=invocation_id,
        )
        object.__setattr__(base, "occurred_at", _utc(base.occurred_at))
        object.__setattr__(base, "reason_codes", _reasons(base.reason_codes))
        record_sha256 = sha256_fingerprint(base._identity_payload())
        result = cls(**{**asdict(base), "record_sha256": record_sha256})
        return result.validate()

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {**self._identity_payload(), "record_sha256": self.record_sha256}

    def to_json(self) -> str:
        return canonical_json(self.public_dict())

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "SecurityWorkflowAuditRecord":
        expected = {
            "schema_version",
            "record_index",
            "event_type",
            "session_id",
            "occurred_at",
            "request_sha256",
            "plan_fingerprint",
            "binding_fingerprint",
            "workflow_fingerprint",
            "previous_record_sha256",
            "reason_codes",
            "step_id",
            "input_fingerprint",
            "invocation_id",
            "record_sha256",
        }
        if set(payload) != expected:
            raise SecurityWorkflowAuditError("audit record fields do not match schema")
        reasons = payload["reason_codes"]
        if not isinstance(reasons, list):
            raise SecurityWorkflowAuditError("audit reason_codes must be an array")
        return cls(
            schema_version=str(payload["schema_version"]),
            record_index=payload["record_index"],
            event_type=str(payload["event_type"]),
            session_id=str(payload["session_id"]),
            occurred_at=str(payload["occurred_at"]),
            request_sha256=str(payload["request_sha256"]),
            plan_fingerprint=str(payload["plan_fingerprint"]),
            binding_fingerprint=str(payload["binding_fingerprint"]),
            workflow_fingerprint=str(payload["workflow_fingerprint"]),
            previous_record_sha256=(
                None if payload["previous_record_sha256"] is None else str(payload["previous_record_sha256"])
            ),
            reason_codes=tuple(str(value) for value in reasons),
            step_id=None if payload["step_id"] is None else str(payload["step_id"]),
            input_fingerprint=(
                None if payload["input_fingerprint"] is None else str(payload["input_fingerprint"])
            ),
            invocation_id=None if payload["invocation_id"] is None else str(payload["invocation_id"]),
            record_sha256=str(payload["record_sha256"]),
        ).validate()


@dataclass(frozen=True)
class SecurityWorkflowAuditVerification:
    record_count: int
    first_record_sha256: str | None
    last_record_sha256: str | None
    valid: bool = True
    schema_version: str = SECURITY_WORKFLOW_AUDIT_VERIFY_SCHEMA

    def validate(self) -> "SecurityWorkflowAuditVerification":
        if isinstance(self.record_count, bool) or not isinstance(self.record_count, int) or self.record_count < 0:
            raise SecurityWorkflowAuditError("verification record_count is invalid")
        if self.record_count == 0:
            if self.first_record_sha256 is not None or self.last_record_sha256 is not None:
                raise SecurityWorkflowAuditError("empty audit verification cannot expose hashes")
        else:
            _sha(str(self.first_record_sha256 or ""), "first_record_sha256")
            _sha(str(self.last_record_sha256 or ""), "last_record_sha256")
        if not self.valid:
            raise SecurityWorkflowAuditError("invalid audit chains must raise before verification result")
        return self


class SecurityWorkflowAuditJournal:
    """Local append-only JSONL audit journal with a single-writer hash chain.

    The journal stores identifiers/fingerprints only. Natural-language requests,
    evidence payloads, targets, credentials, file paths, model prompts and handler
    outputs are deliberately absent. A lock-file serializes writers across processes.
    """

    def __init__(self, path: str | Path, *, lock_timeout_seconds: float = 2.0) -> None:
        raw = Path(path)
        if not raw.is_absolute():
            raise SecurityWorkflowAuditError("audit journal path must be absolute")
        if not 0.1 <= float(lock_timeout_seconds) <= 30.0:
            raise SecurityWorkflowAuditError("audit lock timeout must be within 0.1..30 seconds")
        self.path = raw
        self.lock_path = raw.with_name(raw.name + ".lock")
        self.lock_timeout_seconds = float(lock_timeout_seconds)

    def _validate_paths(self) -> None:
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if parent.is_symlink():
            raise SecurityWorkflowAuditError("audit journal parent symlink denied")
        if self.path.exists() and self.path.is_symlink():
            raise SecurityWorkflowAuditError("audit journal symlink denied")
        if self.lock_path.exists() and self.lock_path.is_symlink():
            raise SecurityWorkflowAuditError("audit lock symlink denied")

    def _acquire_lock(self) -> int:
        self._validate_paths()
        deadline = time.monotonic() + self.lock_timeout_seconds
        while True:
            try:
                return os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                if time.monotonic() >= deadline:
                    raise SecurityWorkflowAuditBusy("AUDIT_JOURNAL_BUSY")
                time.sleep(0.01)

    def _release_lock(self, fd: int) -> None:
        try:
            os.close(fd)
        finally:
            try:
                self.lock_path.unlink()
            except FileNotFoundError:
                pass

    def _records_unlocked(self) -> tuple[SecurityWorkflowAuditRecord, ...]:
        if not self.path.exists():
            return ()
        records: list[SecurityWorkflowAuditRecord] = []
        previous: str | None = None
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, raw in enumerate(handle, 1):
                text = raw.rstrip("\n")
                if not text:
                    raise SecurityWorkflowAuditError(f"empty audit record at line {line_number}")
                if len(text.encode("utf-8")) > MAX_AUDIT_RECORD_BYTES:
                    raise SecurityWorkflowAuditError("audit record exceeds size bound")
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise SecurityWorkflowAuditError(f"invalid audit JSON at line {line_number}") from exc
                if not isinstance(payload, dict):
                    raise SecurityWorkflowAuditError("audit record must be a JSON object")
                record = SecurityWorkflowAuditRecord.from_dict(payload)
                if record.record_index != line_number:
                    raise SecurityWorkflowAuditError("audit record_index is not contiguous")
                if record.previous_record_sha256 != previous:
                    raise SecurityWorkflowAuditError("audit hash chain is broken")
                records.append(record)
                previous = record.record_sha256
        return tuple(records)

    def append(
        self,
        *,
        event_type: str,
        session_id: str,
        request_sha256: str,
        plan_fingerprint: str,
        binding_fingerprint: str,
        workflow_fingerprint: str,
        reason_codes: tuple[str, ...] = (),
        step_id: str | None = None,
        input_fingerprint: str | None = None,
        invocation_id: str | None = None,
        occurred_at: str | None = None,
    ) -> SecurityWorkflowAuditRecord:
        fd = self._acquire_lock()
        try:
            records = self._records_unlocked()
            record = SecurityWorkflowAuditRecord.build(
                record_index=len(records) + 1,
                event_type=event_type,
                session_id=session_id,
                request_sha256=request_sha256,
                plan_fingerprint=plan_fingerprint,
                binding_fingerprint=binding_fingerprint,
                workflow_fingerprint=workflow_fingerprint,
                previous_record_sha256=(records[-1].record_sha256 if records else None),
                reason_codes=reason_codes,
                step_id=step_id,
                input_fingerprint=input_fingerprint,
                invocation_id=invocation_id,
                occurred_at=occurred_at,
            )
            encoded = record.to_json() + "\n"
            if len(encoded.encode("utf-8")) > MAX_AUDIT_RECORD_BYTES:
                raise SecurityWorkflowAuditError("audit record exceeds size bound")
            flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
            journal_fd = os.open(self.path, flags, 0o600)
            try:
                os.write(journal_fd, encoded.encode("utf-8"))
                os.fsync(journal_fd)
            finally:
                os.close(journal_fd)
            return record
        finally:
            self._release_lock(fd)

    def records(self) -> tuple[SecurityWorkflowAuditRecord, ...]:
        fd = self._acquire_lock()
        try:
            return self._records_unlocked()
        finally:
            self._release_lock(fd)

    def verify(self) -> SecurityWorkflowAuditVerification:
        records = self.records()
        return SecurityWorkflowAuditVerification(
            record_count=len(records),
            first_record_sha256=records[0].record_sha256 if records else None,
            last_record_sha256=records[-1].record_sha256 if records else None,
        ).validate()
