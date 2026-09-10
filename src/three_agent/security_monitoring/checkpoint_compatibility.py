from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .checkpoint import SourceCheckpoint, SourceDescriptor, _nonnegative_int
from .contracts import MonitoringContractError, canonical_json, sha256_fingerprint

CHECKPOINT_COMPATIBILITY_SCHEMA = "workspace-security-monitoring/checkpoint-compatibility-v1"
CHECKPOINT_ACTIONS = {"start", "resume", "reset", "invalid"}
CHECKPOINT_REASONS = {
    "no_checkpoint",
    "compatible",
    "source_rotated",
    "source_truncated",
    "source_format_changed",
    "source_id_mismatch",
    "source_kind_changed",
    "cursor_beyond_current_extent",
}


@dataclass(frozen=True)
class CheckpointCompatibilityReceipt:
    source_id: str
    action: str
    reason_code: str
    current_source_fingerprint: str
    previous_checkpoint_fingerprint: str | None
    current_size_bytes: int
    resume_offset_bytes: int | None
    schema_version: str = CHECKPOINT_COMPATIBILITY_SCHEMA

    def validate(self) -> "CheckpointCompatibilityReceipt":
        if self.action not in CHECKPOINT_ACTIONS:
            raise MonitoringContractError(f"unsupported checkpoint action: {self.action}")
        if self.reason_code not in CHECKPOINT_REASONS:
            raise MonitoringContractError(f"unsupported checkpoint reason: {self.reason_code}")
        current_size = _nonnegative_int(self.current_size_bytes, "current_size_bytes")
        object.__setattr__(self, "current_size_bytes", current_size)
        if self.resume_offset_bytes is not None:
            offset = _nonnegative_int(self.resume_offset_bytes, "resume_offset_bytes")
            if offset > current_size:
                raise MonitoringContractError("resume_offset_bytes must not exceed current_size_bytes")
            object.__setattr__(self, "resume_offset_bytes", offset)
        if self.action == "invalid" and self.resume_offset_bytes is not None:
            raise MonitoringContractError("invalid checkpoint decisions must not expose a resume offset")
        if self.action in {"start", "reset"} and self.resume_offset_bytes != 0:
            raise MonitoringContractError("start/reset decisions must resume from byte zero")
        if self.action == "resume" and self.resume_offset_bytes is None:
            raise MonitoringContractError("resume decisions require an explicit resume offset")
        if self.schema_version != CHECKPOINT_COMPATIBILITY_SCHEMA:
            raise MonitoringContractError(f"unsupported checkpoint compatibility schema: {self.schema_version}")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "action": self.action,
            "current_size_bytes": self.current_size_bytes,
            "current_source_fingerprint": self.current_source_fingerprint,
            "previous_checkpoint_fingerprint": self.previous_checkpoint_fingerprint,
            "reason_code": self.reason_code,
            "resume_offset_bytes": self.resume_offset_bytes,
            "schema_version": self.schema_version,
            "source_id": self.source_id,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


class SourceContinuationEvaluator:
    """Deterministically decide whether a source checkpoint can be reused.

    This evaluator never performs I/O and never broadens collection authority. A
    caller must supply the already-observed source descriptor and current extent.
    Ambiguous state returns RESET or INVALID rather than silently resuming.
    """

    def evaluate(
        self,
        *,
        current_source: SourceDescriptor,
        current_size_bytes: int,
        checkpoint: SourceCheckpoint | None,
    ) -> CheckpointCompatibilityReceipt:
        current_source.validate()
        current_size = _nonnegative_int(current_size_bytes, "current_size_bytes")
        current_fingerprint = current_source.fingerprint

        if checkpoint is None:
            return self._receipt(
                current_source=current_source,
                action="start",
                reason_code="no_checkpoint",
                current_fingerprint=current_fingerprint,
                previous_checkpoint_fingerprint=None,
                current_size=current_size,
                resume_offset=0,
            )

        checkpoint.validate()
        previous_fingerprint = checkpoint.fingerprint
        previous_source = checkpoint.source

        if previous_source.source_id != current_source.source_id:
            return self._receipt(
                current_source=current_source,
                action="invalid",
                reason_code="source_id_mismatch",
                current_fingerprint=current_fingerprint,
                previous_checkpoint_fingerprint=previous_fingerprint,
                current_size=current_size,
                resume_offset=None,
            )
        if previous_source.source_kind != current_source.source_kind:
            return self._receipt(
                current_source=current_source,
                action="invalid",
                reason_code="source_kind_changed",
                current_fingerprint=current_fingerprint,
                previous_checkpoint_fingerprint=previous_fingerprint,
                current_size=current_size,
                resume_offset=None,
            )
        if previous_source.format_id != current_source.format_id:
            return self._receipt(
                current_source=current_source,
                action="reset",
                reason_code="source_format_changed",
                current_fingerprint=current_fingerprint,
                previous_checkpoint_fingerprint=previous_fingerprint,
                current_size=current_size,
                resume_offset=0,
            )
        if previous_source.identity_fingerprint != current_source.identity_fingerprint:
            return self._receipt(
                current_source=current_source,
                action="reset",
                reason_code="source_rotated",
                current_fingerprint=current_fingerprint,
                previous_checkpoint_fingerprint=previous_fingerprint,
                current_size=current_size,
                resume_offset=0,
            )
        if current_size < checkpoint.observed_size_bytes:
            return self._receipt(
                current_source=current_source,
                action="reset",
                reason_code="source_truncated",
                current_fingerprint=current_fingerprint,
                previous_checkpoint_fingerprint=previous_fingerprint,
                current_size=current_size,
                resume_offset=0,
            )
        if checkpoint.cursor_offset_bytes > current_size:
            return self._receipt(
                current_source=current_source,
                action="invalid",
                reason_code="cursor_beyond_current_extent",
                current_fingerprint=current_fingerprint,
                previous_checkpoint_fingerprint=previous_fingerprint,
                current_size=current_size,
                resume_offset=None,
            )
        return self._receipt(
            current_source=current_source,
            action="resume",
            reason_code="compatible",
            current_fingerprint=current_fingerprint,
            previous_checkpoint_fingerprint=previous_fingerprint,
            current_size=current_size,
            resume_offset=checkpoint.cursor_offset_bytes,
        )

    @staticmethod
    def _receipt(
        *,
        current_source: SourceDescriptor,
        action: str,
        reason_code: str,
        current_fingerprint: str,
        previous_checkpoint_fingerprint: str | None,
        current_size: int,
        resume_offset: int | None,
    ) -> CheckpointCompatibilityReceipt:
        return CheckpointCompatibilityReceipt(
            source_id=current_source.source_id,
            action=action,
            reason_code=reason_code,
            current_source_fingerprint=current_fingerprint,
            previous_checkpoint_fingerprint=previous_checkpoint_fingerprint,
            current_size_bytes=current_size,
            resume_offset_bytes=resume_offset,
        ).validate()
