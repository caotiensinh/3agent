from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from .checkpoint import SourceCheckpoint, SourceDescriptor, _nonnegative_int
from .checkpoint_compatibility import CheckpointCompatibilityReceipt, SourceContinuationEvaluator
from .contracts import MonitoringContractError, canonical_json, sha256_fingerprint

REPLAY_RECEIPT_SCHEMA = "workspace-security-monitoring/replay-receipt-v1"
_REPLAY_STOP_REASONS = {"source_end", "partial_record", "record_limit", "byte_limit"}


def _payload_sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class ReplayRecord:
    """One in-memory replay record ordered by its original byte position."""

    start_offset_bytes: int
    end_offset_bytes: int
    payload_sha256: str
    text: str

    @property
    def consumed_bytes(self) -> int:
        return self.end_offset_bytes - self.start_offset_bytes

    def evidence_dict(self) -> dict[str, Any]:
        """Hash-only representation safe for deterministic receipts."""
        return {
            "end_offset_bytes": self.end_offset_bytes,
            "payload_sha256": self.payload_sha256,
            "start_offset_bytes": self.start_offset_bytes,
        }


@dataclass(frozen=True)
class ReplayReceipt:
    source_id: str
    compatibility_fingerprint: str
    compatibility_action: str
    source_size_bytes: int
    start_offset_bytes: int
    next_offset_bytes: int
    record_count: int
    replayed_bytes: int
    records_fingerprint: str
    stop_reason: str
    schema_version: str = REPLAY_RECEIPT_SCHEMA

    def validate(self) -> "ReplayReceipt":
        source_size = _nonnegative_int(self.source_size_bytes, "source_size_bytes")
        start = _nonnegative_int(self.start_offset_bytes, "start_offset_bytes")
        next_offset = _nonnegative_int(self.next_offset_bytes, "next_offset_bytes")
        count = _nonnegative_int(self.record_count, "record_count")
        replayed = _nonnegative_int(self.replayed_bytes, "replayed_bytes")
        if not start <= next_offset <= source_size:
            raise MonitoringContractError("replay offsets must satisfy start <= next <= source size")
        if replayed != next_offset - start:
            raise MonitoringContractError("replayed_bytes must equal next_offset_bytes - start_offset_bytes")
        if self.stop_reason not in _REPLAY_STOP_REASONS:
            raise MonitoringContractError(f"unsupported replay stop reason: {self.stop_reason}")
        if self.schema_version != REPLAY_RECEIPT_SCHEMA:
            raise MonitoringContractError(f"unsupported replay receipt schema: {self.schema_version}")
        object.__setattr__(self, "source_size_bytes", source_size)
        object.__setattr__(self, "start_offset_bytes", start)
        object.__setattr__(self, "next_offset_bytes", next_offset)
        object.__setattr__(self, "record_count", count)
        object.__setattr__(self, "replayed_bytes", replayed)
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "compatibility_action": self.compatibility_action,
            "compatibility_fingerprint": self.compatibility_fingerprint,
            "next_offset_bytes": self.next_offset_bytes,
            "record_count": self.record_count,
            "records_fingerprint": self.records_fingerprint,
            "replayed_bytes": self.replayed_bytes,
            "schema_version": self.schema_version,
            "source_id": self.source_id,
            "source_size_bytes": self.source_size_bytes,
            "start_offset_bytes": self.start_offset_bytes,
            "stop_reason": self.stop_reason,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


@dataclass(frozen=True)
class ReplayBatch:
    records: tuple[ReplayRecord, ...]
    receipt: ReplayReceipt
    compatibility: CheckpointCompatibilityReceipt


class DeterministicByteReplay:
    """Replay newline-delimited local evidence without performing any I/O.

    Input bytes and source metadata are supplied by an already-authorized caller.
    The harness never opens a path, socket or device. Only complete newline-terminated
    records are consumed, so a checkpoint never advances across a partial record.
    """

    def __init__(
        self,
        *,
        max_source_bytes: int = 16 * 1024 * 1024,
        max_replay_bytes: int = 4 * 1024 * 1024,
        max_records: int = 10000,
        max_record_bytes: int = 256 * 1024,
    ) -> None:
        if not 4096 <= max_source_bytes <= 128 * 1024 * 1024:
            raise ValueError("max_source_bytes out of range")
        if not 1 <= max_replay_bytes <= max_source_bytes:
            raise ValueError("max_replay_bytes out of range")
        if not 1 <= max_records <= 100000:
            raise ValueError("max_records out of range")
        if not 1 <= max_record_bytes <= min(max_replay_bytes, 1024 * 1024):
            raise ValueError("max_record_bytes out of range")
        self.max_source_bytes = max_source_bytes
        self.max_replay_bytes = max_replay_bytes
        self.max_records = max_records
        self.max_record_bytes = max_record_bytes
        self._continuation = SourceContinuationEvaluator()

    def replay(
        self,
        *,
        source: SourceDescriptor,
        source_bytes: bytes,
        checkpoint: SourceCheckpoint | None = None,
    ) -> ReplayBatch:
        if not isinstance(source_bytes, bytes):
            raise MonitoringContractError("source_bytes must be bytes")
        source.validate()
        source_size = len(source_bytes)
        if source_size > self.max_source_bytes:
            raise MonitoringContractError("replay source exceeds max_source_bytes")

        compatibility = self._continuation.evaluate(
            current_source=source,
            current_size_bytes=source_size,
            checkpoint=checkpoint,
        )
        if compatibility.action == "invalid" or compatibility.resume_offset_bytes is None:
            raise MonitoringContractError(
                f"checkpoint is not replayable: {compatibility.reason_code}"
            )
        start = compatibility.resume_offset_bytes
        if start > 0 and source_bytes[start - 1 : start] != b"\n":
            raise MonitoringContractError("checkpoint cursor is not at a record boundary")

        records: list[ReplayRecord] = []
        cursor = start
        stop_reason = "source_end"
        while cursor < source_size:
            if len(records) >= self.max_records:
                stop_reason = "record_limit"
                break
            newline = source_bytes.find(b"\n", cursor)
            if newline < 0:
                stop_reason = "partial_record"
                break
            end = newline + 1
            consumed = end - cursor
            if consumed > self.max_record_bytes:
                raise MonitoringContractError("single replay record exceeds max_record_bytes")
            if (end - start) > self.max_replay_bytes:
                stop_reason = "byte_limit"
                break
            payload = source_bytes[cursor:newline]
            records.append(
                ReplayRecord(
                    start_offset_bytes=cursor,
                    end_offset_bytes=end,
                    payload_sha256=_payload_sha256(payload),
                    text=payload.decode("utf-8", errors="replace"),
                )
            )
            cursor = end

        evidence = [record.evidence_dict() for record in records]
        receipt = ReplayReceipt(
            source_id=source.source_id,
            compatibility_fingerprint=compatibility.fingerprint,
            compatibility_action=compatibility.action,
            source_size_bytes=source_size,
            start_offset_bytes=start,
            next_offset_bytes=cursor,
            record_count=len(records),
            replayed_bytes=cursor - start,
            records_fingerprint=sha256_fingerprint(evidence),
            stop_reason=stop_reason,
        ).validate()
        return ReplayBatch(records=tuple(records), receipt=receipt, compatibility=compatibility)
