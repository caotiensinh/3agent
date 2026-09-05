"""Strict contracts for WorkSpace Phase 4B local reflection.

The model receives a bounded, capability-free packet and returns a narrow
proposal. Provenance, domain, sensitivity, ownership, identity and persistence
authority remain deterministic parent-process concerns.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any

from .adaptive_learning_admission import VerifiedLearningSourceEnvelope
from .adaptive_learning_contract import (
    ACTIONS,
    DOMAINS,
    EXECUTION_MODES,
    KINDS,
    RISK_LEVELS,
    SENSITIVITIES,
)

DOMAIN_BINDING_SCHEMA = "workspace-learning-reflection-domain-binding/v1"
REFLECTION_PACKET_SCHEMA = "workspace-learning-reflection-packet/v1"
REFLECTION_RESULT_SCHEMA = "workspace-learning-reflection-result/v1"

AUTHORITY_TYPES = {"operator", "workflow", "policy"}
RESULTS = {"CANDIDATE", "NO_LEARNING_VALUE"}
_MAX_PACKET_BYTES = 16 * 1024
_MAX_SUMMARY_BYTES = 8 * 1024
_MAX_SUMMARY_CHARS = 3500
_MAX_RESULT_BYTES = 32 * 1024
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")


class ReflectionContractError(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code)
        super().__init__(self.reason_code)


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _id(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not _ID.fullmatch(text):
        raise ReflectionContractError(f"REFLECTION_{field.upper()}_INVALID")
    return text


def _sha(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA.fullmatch(text):
        raise ReflectionContractError(f"REFLECTION_{field.upper()}_INVALID")
    return text


def _strict(payload: Any, fields: set[str], schema: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != fields:
        raise ReflectionContractError("REFLECTION_SCHEMA_FIELDS_INVALID")
    if payload.get("schema_version") != schema:
        raise ReflectionContractError("REFLECTION_SCHEMA_VERSION_INVALID")
    return dict(payload)


@dataclass(frozen=True)
class ReflectionDomainBinding:
    binding_id: str
    admission_id: str
    task_id: str
    domain: str
    authority_type: str
    authority_id: str
    schema_version: str = DOMAIN_BINDING_SCHEMA

    FIELDS = {
        "schema_version",
        "binding_id",
        "admission_id",
        "task_id",
        "domain",
        "authority_type",
        "authority_id",
    }

    @classmethod
    def create(
        cls,
        envelope: VerifiedLearningSourceEnvelope,
        *,
        domain: str,
        authority_type: str,
        authority_id: str,
    ) -> "ReflectionDomainBinding":
        domain = str(domain or "").strip().lower()
        authority_type = str(authority_type or "").strip().lower()
        authority_id = _id(authority_id, "authority_id")
        if domain not in DOMAINS:
            raise ReflectionContractError("REFLECTION_DOMAIN_INVALID")
        if authority_type not in AUTHORITY_TYPES:
            raise ReflectionContractError("REFLECTION_BINDING_AUTHORITY_INVALID")
        envelope.to_payload()
        basis = {
            "schema_version": DOMAIN_BINDING_SCHEMA,
            "admission_id": envelope.admission_id,
            "task_id": envelope.task_id,
            "domain": domain,
            "authority_type": authority_type,
            "authority_id": authority_id,
        }
        binding_id = "binding:" + _digest(basis).split(":", 1)[1]
        return cls(
            binding_id=binding_id,
            admission_id=envelope.admission_id,
            task_id=envelope.task_id,
            domain=domain,
            authority_type=authority_type,
            authority_id=authority_id,
        ).validate(envelope)

    def validate(
        self, envelope: VerifiedLearningSourceEnvelope | None = None
    ) -> "ReflectionDomainBinding":
        _id(self.binding_id, "binding_id")
        _id(self.admission_id, "admission_id")
        _id(self.task_id, "task_id")
        if self.domain not in DOMAINS:
            raise ReflectionContractError("REFLECTION_DOMAIN_INVALID")
        if self.authority_type not in AUTHORITY_TYPES:
            raise ReflectionContractError("REFLECTION_BINDING_AUTHORITY_INVALID")
        _id(self.authority_id, "authority_id")
        expected_basis = {
            "schema_version": DOMAIN_BINDING_SCHEMA,
            "admission_id": self.admission_id,
            "task_id": self.task_id,
            "domain": self.domain,
            "authority_type": self.authority_type,
            "authority_id": self.authority_id,
        }
        expected_id = "binding:" + _digest(expected_basis).split(":", 1)[1]
        if self.binding_id != expected_id:
            raise ReflectionContractError("REFLECTION_BINDING_ID_MISMATCH")
        if envelope is not None:
            envelope.to_payload()
            if self.admission_id != envelope.admission_id or self.task_id != envelope.task_id:
                raise ReflectionContractError("REFLECTION_BINDING_SOURCE_MISMATCH")
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)

    @property
    def sha256(self) -> str:
        return _digest(self.to_payload())

    @classmethod
    def from_payload(cls, payload: Any) -> "ReflectionDomainBinding":
        return cls(**_strict(payload, cls.FIELDS, DOMAIN_BINDING_SCHEMA)).validate()


@dataclass(frozen=True)
class BoundedReflectionPacket:
    admission_id: str
    admission_provenance_sha256: str
    binding_sha256: str
    task_id: str
    domain: str
    sensitivity: str
    risk_level: str
    outcome: str
    evidence_hashes: tuple[str, ...]
    summary: str
    output_schema_version: str
    allowed_action: str
    target_item_id: str | None
    base_item_sha256: str | None
    schema_version: str = REFLECTION_PACKET_SCHEMA

    FIELDS = {
        "schema_version",
        "admission_id",
        "admission_provenance_sha256",
        "binding_sha256",
        "task_id",
        "domain",
        "sensitivity",
        "risk_level",
        "outcome",
        "evidence_hashes",
        "summary",
        "output_schema_version",
        "allowed_action",
        "target_item_id",
        "base_item_sha256",
    }

    def validate(self) -> "BoundedReflectionPacket":
        _id(self.admission_id, "admission_id")
        _sha(self.admission_provenance_sha256, "admission_provenance_sha256")
        _sha(self.binding_sha256, "binding_sha256")
        _id(self.task_id, "task_id")
        if self.domain not in DOMAINS:
            raise ReflectionContractError("REFLECTION_DOMAIN_INVALID")
        if self.sensitivity not in SENSITIVITIES:
            raise ReflectionContractError("REFLECTION_SENSITIVITY_INVALID")
        if self.sensitivity == "secret":
            raise ReflectionContractError("REFLECTION_SECRET_NOT_SUPPORTED")
        if self.risk_level not in RISK_LEVELS:
            raise ReflectionContractError("REFLECTION_RISK_INVALID")
        if self.outcome != "verified_success":
            raise ReflectionContractError("REFLECTION_SOURCE_NOT_VERIFIED_SUCCESS")
        if not isinstance(self.evidence_hashes, tuple) or not 1 <= len(self.evidence_hashes) <= 32:
            raise ReflectionContractError("REFLECTION_EVIDENCE_HASHES_INVALID")
        if len(set(self.evidence_hashes)) != len(self.evidence_hashes):
            raise ReflectionContractError("REFLECTION_EVIDENCE_HASHES_INVALID")
        for value in self.evidence_hashes:
            _sha(value, "evidence_sha256")
        if (
            not isinstance(self.summary, str)
            or not self.summary.strip()
            or len(self.summary) > _MAX_SUMMARY_CHARS
            or len(self.summary.encode("utf-8")) > _MAX_SUMMARY_BYTES
        ):
            raise ReflectionContractError("REFLECTION_SUMMARY_SIZE_INVALID")
        if self.output_schema_version != REFLECTION_RESULT_SCHEMA:
            raise ReflectionContractError("REFLECTION_OUTPUT_SCHEMA_INVALID")
        if self.allowed_action not in ACTIONS:
            raise ReflectionContractError("REFLECTION_ACTION_INVALID")
        if self.allowed_action == "create":
            if self.target_item_id is not None or self.base_item_sha256 is not None:
                raise ReflectionContractError("REFLECTION_CREATE_BASE_FORBIDDEN")
        else:
            _id(self.target_item_id, "target_item_id")
            _sha(self.base_item_sha256, "base_item_sha256")
        encoded = _canonical(self.to_payload_unchecked()).encode("utf-8")
        if len(encoded) > _MAX_PACKET_BYTES:
            raise ReflectionContractError("REFLECTION_PACKET_SIZE_INVALID")
        return self

    def to_payload_unchecked(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["evidence_hashes"] = list(self.evidence_hashes)
        return payload

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return self.to_payload_unchecked()

    @property
    def sha256(self) -> str:
        return _digest(self.to_payload())

    @classmethod
    def from_payload(cls, payload: Any) -> "BoundedReflectionPacket":
        data = _strict(payload, cls.FIELDS, REFLECTION_PACKET_SCHEMA)
        if not isinstance(data["evidence_hashes"], list):
            raise ReflectionContractError("REFLECTION_EVIDENCE_HASHES_INVALID")
        data["evidence_hashes"] = tuple(data["evidence_hashes"])
        return cls(**data).validate()


@dataclass(frozen=True)
class ReflectionResult:
    result: str
    kind: str
    title: str
    content: str
    scope: str
    action: str
    execution_mode: str
    reusable_value_reason: str
    schema_version: str = REFLECTION_RESULT_SCHEMA

    FIELDS = {
        "schema_version",
        "result",
        "kind",
        "title",
        "content",
        "scope",
        "action",
        "execution_mode",
        "reusable_value_reason",
    }

    def validate(self) -> "ReflectionResult":
        if self.result not in RESULTS:
            raise ReflectionContractError("REFLECTION_RESULT_INVALID")
        if not isinstance(self.reusable_value_reason, str) or not 1 <= len(self.reusable_value_reason.strip()) <= 512:
            raise ReflectionContractError("REFLECTION_REUSABLE_VALUE_REASON_INVALID")
        if self.result == "NO_LEARNING_VALUE":
            if (
                self.kind != "none"
                or self.title != ""
                or self.content != ""
                or self.scope != ""
                or self.action != "none"
                or self.execution_mode != "none"
            ):
                raise ReflectionContractError("REFLECTION_NO_VALUE_PAYLOAD_INVALID")
            return self
        if self.kind not in KINDS:
            raise ReflectionContractError("REFLECTION_KIND_INVALID")
        if self.action not in ACTIONS:
            raise ReflectionContractError("REFLECTION_ACTION_INVALID")
        if self.execution_mode not in EXECUTION_MODES:
            raise ReflectionContractError("REFLECTION_EXECUTION_MODE_INVALID")
        if not isinstance(self.title, str) or not 1 <= len(self.title.strip()) <= 160:
            raise ReflectionContractError("REFLECTION_TITLE_INVALID")
        if not isinstance(self.content, str) or not 1 <= len(self.content.strip()) <= 12000:
            raise ReflectionContractError("REFLECTION_CONTENT_INVALID")
        if not isinstance(self.scope, str) or not 1 <= len(self.scope.strip()) <= 240:
            raise ReflectionContractError("REFLECTION_SCOPE_INVALID")
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)

    @classmethod
    def from_payload(cls, payload: Any) -> "ReflectionResult":
        return cls(**_strict(payload, cls.FIELDS, REFLECTION_RESULT_SCHEMA)).validate()


REFLECTION_RESULT_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "result",
        "kind",
        "title",
        "content",
        "scope",
        "action",
        "execution_mode",
        "reusable_value_reason",
    ],
    "properties": {
        "schema_version": {"type": "string", "enum": [REFLECTION_RESULT_SCHEMA]},
        "result": {"type": "string", "enum": ["CANDIDATE", "NO_LEARNING_VALUE"]},
        "kind": {"type": "string", "enum": ["none", *sorted(KINDS)]},
        "title": {"type": "string", "maxLength": 160},
        "content": {"type": "string", "maxLength": 12000},
        "scope": {"type": "string", "maxLength": 240},
        "action": {"type": "string", "enum": ["none", *sorted(ACTIONS)]},
        "execution_mode": {"type": "string", "enum": ["none", *sorted(EXECUTION_MODES)]},
        "reusable_value_reason": {"type": "string", "minLength": 1, "maxLength": 512},
    },
}


def parse_strict_reflection_result(raw: str) -> ReflectionResult:
    if not isinstance(raw, str):
        raise ReflectionContractError("REFLECTION_WORKER_OUTPUT_INVALID")
    if not raw or len(raw.encode("utf-8")) > _MAX_RESULT_BYTES or raw != raw.strip():
        raise ReflectionContractError("REFLECTION_WORKER_OUTPUT_INVALID")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReflectionContractError("REFLECTION_WORKER_OUTPUT_INVALID") from exc
    if not isinstance(payload, dict):
        raise ReflectionContractError("REFLECTION_WORKER_OUTPUT_INVALID")
    return ReflectionResult.from_payload(payload)
