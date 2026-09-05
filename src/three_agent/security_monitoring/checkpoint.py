from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from .contracts import MonitoringContractError, _compact, canonical_json, sha256_fingerprint

SOURCE_DESCRIPTOR_SCHEMA = "workspace-security-monitoring/source-descriptor-v1"
SOURCE_CHECKPOINT_SCHEMA = "workspace-security-monitoring/source-checkpoint-v1"
_SOURCE_KIND_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$", re.ASCII)
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)


def _strict_mapping(payload: Any, *, field_name: str) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        raise MonitoringContractError(f"{field_name} must be an object")
    return payload


def _require_exact_fields(payload: Mapping[str, Any], expected: set[str], *, field_name: str) -> None:
    actual = set(payload)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing={missing}")
        if unknown:
            details.append(f"unknown={unknown}")
        raise MonitoringContractError(f"{field_name} fields do not match schema: {', '.join(details)}")


def _nonnegative_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MonitoringContractError(f"{field_name} must be an integer")
    if value < 0:
        raise MonitoringContractError(f"{field_name} must be non-negative")
    return value


def _utc_timestamp(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MonitoringContractError(f"{field_name} must include timezone")
    if parsed.utcoffset().total_seconds() != 0:
        raise MonitoringContractError(f"{field_name} must be UTC")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class SourceDescriptor:
    """Opaque identity for a bounded monitoring source.

    The descriptor deliberately stores no filesystem path, URL or credential. The
    identity fingerprint is supplied by the source adapter from non-secret source
    identity material (for example an inode/device tuple or immutable object ID).
    """

    source_id: str
    source_kind: str
    identity_fingerprint: str
    format_id: str
    schema_version: str = SOURCE_DESCRIPTOR_SCHEMA

    def validate(self) -> "SourceDescriptor":
        object.__setattr__(self, "source_id", _compact(self.source_id, "source_id", max_len=128))
        kind = str(self.source_kind or "").strip().lower()
        if not _SOURCE_KIND_RE.fullmatch(kind):
            raise MonitoringContractError("source_kind must be a lowercase compact kind")
        object.__setattr__(self, "source_kind", kind)
        fingerprint = str(self.identity_fingerprint or "").strip()
        if not _SHA256_RE.fullmatch(fingerprint):
            raise MonitoringContractError("identity_fingerprint must be a SHA-256 fingerprint")
        object.__setattr__(self, "identity_fingerprint", fingerprint)
        object.__setattr__(self, "format_id", _compact(self.format_id, "format_id", max_len=96))
        if self.schema_version != SOURCE_DESCRIPTOR_SCHEMA:
            raise MonitoringContractError(f"unsupported source descriptor schema: {self.schema_version}")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "format_id": self.format_id,
            "identity_fingerprint": self.identity_fingerprint,
            "schema_version": self.schema_version,
            "source_id": self.source_id,
            "source_kind": self.source_kind,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "SourceDescriptor":
        data = _strict_mapping(payload, field_name="source_descriptor")
        _require_exact_fields(
            data,
            {"source_id", "source_kind", "identity_fingerprint", "format_id", "schema_version"},
            field_name="source_descriptor",
        )
        return cls(
            source_id=data["source_id"],
            source_kind=data["source_kind"],
            identity_fingerprint=data["identity_fingerprint"],
            format_id=data["format_id"],
            schema_version=data["schema_version"],
        ).validate()

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


@dataclass(frozen=True)
class SourceCheckpoint:
    """Fail-closed byte cursor for resumable local evidence ingestion."""

    source: SourceDescriptor
    cursor_offset_bytes: int
    observed_size_bytes: int
    checkpointed_at: str
    last_event_at: str | None = None
    schema_version: str = SOURCE_CHECKPOINT_SCHEMA

    def validate(self) -> "SourceCheckpoint":
        if not isinstance(self.source, SourceDescriptor):
            raise MonitoringContractError("source must be a SourceDescriptor")
        self.source.validate()
        cursor = _nonnegative_int(self.cursor_offset_bytes, "cursor_offset_bytes")
        extent = _nonnegative_int(self.observed_size_bytes, "observed_size_bytes")
        if cursor > extent:
            raise MonitoringContractError("cursor_offset_bytes must not exceed observed_size_bytes")
        object.__setattr__(self, "cursor_offset_bytes", cursor)
        object.__setattr__(self, "observed_size_bytes", extent)
        object.__setattr__(self, "checkpointed_at", _utc_timestamp(self.checkpointed_at, "checkpointed_at"))
        if self.last_event_at is not None:
            object.__setattr__(self, "last_event_at", _utc_timestamp(self.last_event_at, "last_event_at"))
        if self.schema_version != SOURCE_CHECKPOINT_SCHEMA:
            raise MonitoringContractError(f"unsupported source checkpoint schema: {self.schema_version}")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "checkpointed_at": self.checkpointed_at,
            "cursor_offset_bytes": self.cursor_offset_bytes,
            "last_event_at": self.last_event_at,
            "observed_size_bytes": self.observed_size_bytes,
            "schema_version": self.schema_version,
            "source": self.source.to_dict(),
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "SourceCheckpoint":
        data = _strict_mapping(payload, field_name="source_checkpoint")
        _require_exact_fields(
            data,
            {
                "source",
                "cursor_offset_bytes",
                "observed_size_bytes",
                "checkpointed_at",
                "last_event_at",
                "schema_version",
            },
            field_name="source_checkpoint",
        )
        return cls(
            source=SourceDescriptor.from_dict(data["source"]),
            cursor_offset_bytes=data["cursor_offset_bytes"],
            observed_size_bytes=data["observed_size_bytes"],
            checkpointed_at=data["checkpointed_at"],
            last_event_at=data["last_event_at"],
            schema_version=data["schema_version"],
        ).validate()

    @classmethod
    def from_json(cls, payload: str) -> "SourceCheckpoint":
        try:
            decoded = json.loads(payload)
        except (TypeError, json.JSONDecodeError) as exc:
            raise MonitoringContractError("source_checkpoint must be valid JSON") from exc
        return cls.from_dict(decoded)

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())
