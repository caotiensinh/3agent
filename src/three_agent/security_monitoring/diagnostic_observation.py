from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .contracts import sha256_fingerprint

DIAGNOSTIC_OBSERVATION_SCHEMA = "workspace-diagnostic-observation/v1"
DIAGNOSTIC_OBSERVATION_STATUSES = frozenset(
    {"succeeded", "failed", "partial", "timeout", "unsupported", "cancelled"}
)
DIAGNOSTIC_CONTENT_TYPES = frozenset({"application/json", "text/plain"})
MAX_DIAGNOSTIC_PAYLOAD_BYTES = 64 * 1024
MAX_DIAGNOSTIC_SUMMARY_CHARS = 1024
MAX_DIAGNOSTIC_REDACTIONS = 10_000

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,255}$")


class DiagnosticObservationError(ValueError):
    """A diagnostic observation is malformed, unbounded, or unsafe to promote."""


def _sha256(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise DiagnosticObservationError(f"INVALID_{field_name.upper()}")
    return value


def _single_line(value: Any, field_name: str, *, max_len: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise DiagnosticObservationError(f"INVALID_{field_name.upper()}")
    if len(value) > max_len or "\n" in value or "\r" in value or "\x00" in value:
        raise DiagnosticObservationError(f"INVALID_{field_name.upper()}")
    return value


def _reference(value: Any, field_name: str) -> str:
    text = _single_line(value, field_name, max_len=256)
    if not _REF_RE.fullmatch(text) or "://" in text:
        raise DiagnosticObservationError(f"INVALID_{field_name.upper()}")
    if any(segment == ".." for segment in text.split("/")):
        raise DiagnosticObservationError(f"INVALID_{field_name.upper()}")
    return text


def _timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DiagnosticObservationError("INVALID_OBSERVED_AT")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise DiagnosticObservationError("INVALID_OBSERVED_AT") from exc
    if parsed.tzinfo is None:
        raise DiagnosticObservationError("INVALID_OBSERVED_AT")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json_payload(value: str) -> str:
    try:
        decoded = json.loads(value)
        return json.dumps(
            decoded,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise DiagnosticObservationError("INVALID_JSON_PAYLOAD") from exc


@dataclass(frozen=True)
class DiagnosticObservation:
    source_tool: str
    source_capability: str
    task_ref_sha256: str
    request_ref_sha256: str
    observed_at: str
    status: str
    summary: str
    payload: str
    content_type: str
    original_payload_bytes: int
    truncated: bool = False
    redaction_count: int = 0
    secret_material_detected: bool = False
    error_code: str | None = None
    authority: str = "advisory"
    automatic_action_allowed: bool = False
    schema_version: str = DIAGNOSTIC_OBSERVATION_SCHEMA

    def validate(self) -> "DiagnosticObservation":
        if self.schema_version != DIAGNOSTIC_OBSERVATION_SCHEMA:
            raise DiagnosticObservationError("OBSERVATION_SCHEMA_VERSION_MISMATCH")

        object.__setattr__(self, "source_tool", _reference(self.source_tool, "source_tool"))
        object.__setattr__(
            self,
            "source_capability",
            _reference(self.source_capability, "source_capability"),
        )
        _sha256(self.task_ref_sha256, "task_ref_sha256")
        _sha256(self.request_ref_sha256, "request_ref_sha256")
        object.__setattr__(self, "observed_at", _timestamp(self.observed_at))

        if self.status not in DIAGNOSTIC_OBSERVATION_STATUSES:
            raise DiagnosticObservationError("INVALID_OBSERVATION_STATUS")
        object.__setattr__(
            self,
            "summary",
            _single_line(
                self.summary,
                "summary",
                max_len=MAX_DIAGNOSTIC_SUMMARY_CHARS,
            ),
        )
        if self.content_type not in DIAGNOSTIC_CONTENT_TYPES:
            raise DiagnosticObservationError("UNSUPPORTED_CONTENT_TYPE")
        if not isinstance(self.payload, str) or "\x00" in self.payload:
            raise DiagnosticObservationError("INVALID_PAYLOAD")

        payload = self.payload
        incoming_size = len(payload.encode("utf-8"))
        if incoming_size > MAX_DIAGNOSTIC_PAYLOAD_BYTES:
            raise DiagnosticObservationError("DIAGNOSTIC_PAYLOAD_BOUND_EXCEEDED")
        if self.content_type == "application/json":
            payload = _canonical_json_payload(payload)
            if len(payload.encode("utf-8")) > MAX_DIAGNOSTIC_PAYLOAD_BYTES:
                raise DiagnosticObservationError("DIAGNOSTIC_PAYLOAD_BOUND_EXCEEDED")
            object.__setattr__(self, "payload", payload)

        payload_size = len(self.payload.encode("utf-8"))
        if (
            isinstance(self.original_payload_bytes, bool)
            or not isinstance(self.original_payload_bytes, int)
            or self.original_payload_bytes < payload_size
        ):
            raise DiagnosticObservationError("INVALID_ORIGINAL_PAYLOAD_BYTES")
        if self.truncated:
            if self.original_payload_bytes <= payload_size:
                raise DiagnosticObservationError("TRUNCATION_METADATA_MISMATCH")
        elif self.original_payload_bytes != payload_size:
            raise DiagnosticObservationError("TRUNCATION_METADATA_MISMATCH")

        if (
            isinstance(self.redaction_count, bool)
            or not isinstance(self.redaction_count, int)
            or not 0 <= self.redaction_count <= MAX_DIAGNOSTIC_REDACTIONS
        ):
            raise DiagnosticObservationError("INVALID_REDACTION_COUNT")
        if not isinstance(self.secret_material_detected, bool):
            raise DiagnosticObservationError("INVALID_SECRET_MATERIAL_FLAG")
        if self.secret_material_detected:
            raise DiagnosticObservationError("SECRET_MATERIAL_MUST_NOT_BE_PROMOTED")

        if self.error_code is not None:
            object.__setattr__(self, "error_code", _reference(self.error_code, "error_code"))
        if self.status == "succeeded" and self.error_code is not None:
            raise DiagnosticObservationError("SUCCESS_CANNOT_HAVE_ERROR_CODE")
        if self.status != "succeeded" and self.error_code is None:
            raise DiagnosticObservationError("NON_SUCCESS_REQUIRES_ERROR_CODE")

        if not isinstance(self.automatic_action_allowed, bool):
            raise DiagnosticObservationError("INVALID_AUTOMATIC_ACTION_ALLOWED")
        if self.authority != "advisory" or self.automatic_action_allowed:
            raise DiagnosticObservationError("OBSERVATION_CANNOT_GRANT_AUTHORITY")
        return self

    @property
    def payload_size_bytes(self) -> int:
        self.validate()
        return len(self.payload.encode("utf-8"))

    @property
    def redacted(self) -> bool:
        self.validate()
        return self.redaction_count > 0

    def canonical_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "source_tool": self.source_tool,
            "source_capability": self.source_capability,
            "task_ref_sha256": self.task_ref_sha256,
            "request_ref_sha256": self.request_ref_sha256,
            "observed_at": self.observed_at,
            "status": self.status,
            "summary": self.summary,
            "payload": self.payload,
            "content_type": self.content_type,
            "payload_size_bytes": len(self.payload.encode("utf-8")),
            "original_payload_bytes": self.original_payload_bytes,
            "truncated": self.truncated,
            "redacted": self.redaction_count > 0,
            "redaction_count": self.redaction_count,
            "secret_material_detected": self.secret_material_detected,
            "error_code": self.error_code,
            "authority": self.authority,
            "automatic_action_allowed": self.automatic_action_allowed,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.canonical_dict())

    @property
    def observation_id(self) -> str:
        return "diagnostic:" + self.fingerprint.removeprefix("sha256:")[:32]
