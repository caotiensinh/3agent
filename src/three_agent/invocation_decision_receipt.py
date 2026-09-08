from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .capability_authority import CAPABILITY_DECISION_SCHEMA, CapabilityDecision

INVOCATION_DECISION_RECEIPT_SCHEMA = "workspace-invocation-decision-receipt/v1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,255}$")
_REASON_RE = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{0,95}$")


class InvocationDecisionReceiptError(ValueError):
    """Invocation decision evidence is malformed or would broaden authority."""


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise InvocationDecisionReceiptError("RECEIPT_NOT_CANONICAL_JSON") from exc


def _fingerprint(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _sha256(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise InvocationDecisionReceiptError(f"INVALID_{field_name.upper()}")
    return value


def _reference(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise InvocationDecisionReceiptError(f"INVALID_{field_name.upper()}")
    if len(value) > 256 or not _REF_RE.fullmatch(value) or "://" in value:
        raise InvocationDecisionReceiptError(f"INVALID_{field_name.upper()}")
    if any(segment == ".." for segment in value.split("/")):
        raise InvocationDecisionReceiptError(f"INVALID_{field_name.upper()}")
    return value


def _reason_code(value: Any) -> str:
    if not isinstance(value, str) or not _REASON_RE.fullmatch(value):
        raise InvocationDecisionReceiptError("INVALID_REASON_CODE")
    return value


@dataclass(frozen=True)
class InvocationDecisionReceipt:
    task_id: str
    task_ref_sha256: str
    request_ref_sha256: str
    capability_id: str
    tool_id: str
    effect: str
    resource_kind: str
    resource_sha256: str
    authority_fingerprint: str
    authority_decision_fingerprint: str
    allowed: bool
    reason_code: str
    descriptor_fingerprint: str | None = None
    snapshot_fingerprint: str | None = None
    authority: str = "advisory"
    automatic_action_allowed: bool = False
    schema_version: str = INVOCATION_DECISION_RECEIPT_SCHEMA

    def validate(self) -> "InvocationDecisionReceipt":
        if self.schema_version != INVOCATION_DECISION_RECEIPT_SCHEMA:
            raise InvocationDecisionReceiptError("RECEIPT_SCHEMA_VERSION_MISMATCH")
        object.__setattr__(self, "task_id", _reference(self.task_id, "task_id"))
        _sha256(self.task_ref_sha256, "task_ref_sha256")
        _sha256(self.request_ref_sha256, "request_ref_sha256")
        object.__setattr__(
            self,
            "capability_id",
            _reference(self.capability_id, "capability_id"),
        )
        object.__setattr__(self, "tool_id", _reference(self.tool_id, "tool_id"))
        object.__setattr__(self, "effect", _reference(self.effect, "effect"))
        object.__setattr__(
            self,
            "resource_kind",
            _reference(self.resource_kind, "resource_kind"),
        )
        _sha256(self.resource_sha256, "resource_sha256")
        _sha256(self.authority_fingerprint, "authority_fingerprint")
        _sha256(
            self.authority_decision_fingerprint,
            "authority_decision_fingerprint",
        )
        if self.descriptor_fingerprint is not None:
            _sha256(self.descriptor_fingerprint, "descriptor_fingerprint")
        if self.snapshot_fingerprint is not None:
            _sha256(self.snapshot_fingerprint, "snapshot_fingerprint")
        if not isinstance(self.allowed, bool):
            raise InvocationDecisionReceiptError("INVALID_ALLOWED_OUTCOME")
        object.__setattr__(self, "reason_code", _reason_code(self.reason_code))
        if not isinstance(self.automatic_action_allowed, bool):
            raise InvocationDecisionReceiptError("INVALID_AUTOMATIC_ACTION_ALLOWED")
        if self.authority != "advisory" or self.automatic_action_allowed:
            raise InvocationDecisionReceiptError("RECEIPT_CANNOT_GRANT_AUTHORITY")
        return self

    def canonical_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "task_ref_sha256": self.task_ref_sha256,
            "request_ref_sha256": self.request_ref_sha256,
            "capability_id": self.capability_id,
            "tool_id": self.tool_id,
            "effect": self.effect,
            "resource_kind": self.resource_kind,
            "resource_sha256": self.resource_sha256,
            "authority_fingerprint": self.authority_fingerprint,
            "authority_decision_fingerprint": self.authority_decision_fingerprint,
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "descriptor_fingerprint": self.descriptor_fingerprint,
            "snapshot_fingerprint": self.snapshot_fingerprint,
            "authority": self.authority,
            "automatic_action_allowed": self.automatic_action_allowed,
        }

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.canonical_dict())


def receipt_from_capability_decision(
    *,
    decision: CapabilityDecision,
    task_ref_sha256: str,
    request_ref_sha256: str,
    tool_id: str,
    descriptor_fingerprint: str | None = None,
    snapshot_fingerprint: str | None = None,
) -> InvocationDecisionReceipt:
    """Project one authority decision into immutable audit metadata only."""

    if not isinstance(decision, CapabilityDecision):
        raise InvocationDecisionReceiptError("INVALID_CAPABILITY_DECISION")
    if decision.schema_version != CAPABILITY_DECISION_SCHEMA:
        raise InvocationDecisionReceiptError("CAPABILITY_DECISION_SCHEMA_VERSION_MISMATCH")
    metadata = decision.metadata()
    return InvocationDecisionReceipt(
        task_id=decision.task_id,
        task_ref_sha256=_sha256(task_ref_sha256, "task_ref_sha256"),
        request_ref_sha256=_sha256(request_ref_sha256, "request_ref_sha256"),
        capability_id=decision.capability,
        tool_id=tool_id,
        effect=decision.effect,
        resource_kind=decision.resource_kind,
        resource_sha256=str(metadata["resource_sha256"]),
        authority_fingerprint=decision.authority_fingerprint,
        authority_decision_fingerprint=_fingerprint(metadata),
        allowed=decision.allowed,
        reason_code=decision.reason_code,
        descriptor_fingerprint=descriptor_fingerprint,
        snapshot_fingerprint=snapshot_fingerprint,
    ).validate()
