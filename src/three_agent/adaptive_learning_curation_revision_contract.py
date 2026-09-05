"""Strict capability-free contracts for Phase 4J curation revision reflection."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Mapping

from .adaptive_learning_contract import DOMAINS, EXECUTION_MODES, KINDS, RISK_LEVELS, SENSITIVITIES

REVISION_PACKET_SCHEMA = "workspace-learning-curation-revision-packet/v1"
REVISION_RESULT_SCHEMA = "workspace-learning-curation-revision-result/v1"
REVISION_ACTIONS = {"REVISE_OR_ARCHIVE_REVIEW", "DOMAIN_REVISE_OR_ARCHIVE_REVIEW"}
REVISION_RESULTS = {"REVISION_CANDIDATE", "NO_REVISION_VALUE"}
ACTIVE_LEVELS = {"approved", "enterprise"}
TRUST_MARKER = "untrusted_reference_data_only"

_MAX_PACKET_BYTES = 64 * 1024
_MAX_RESULT_BYTES = 48 * 1024
_MAX_TITLE = 160
_MAX_CONTENT = 12000
_MAX_SCOPE = 240
_MAX_REASON = 512
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_METRIC_FIELDS = {
    "unique_task_observations",
    "isolated_task_observations",
    "confounded_task_observations",
    "isolated_verified_success",
    "isolated_failed",
    "isolated_waiting_human",
    "isolated_done_unverified",
}


class CurationRevisionContractError(ValueError):
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
        raise CurationRevisionContractError(f"CURATION_REVISION_{field.upper()}_INVALID")
    return text


def _sha(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA.fullmatch(text):
        raise CurationRevisionContractError(f"CURATION_REVISION_{field.upper()}_INVALID")
    return text


def _strict(payload: Any, fields: set[str], schema: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != fields:
        raise CurationRevisionContractError("CURATION_REVISION_SCHEMA_FIELDS_INVALID")
    if payload.get("schema_version") != schema:
        raise CurationRevisionContractError("CURATION_REVISION_SCHEMA_VERSION_INVALID")
    return dict(payload)


def _text(value: Any, *, field: str, maximum: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise CurationRevisionContractError(f"CURATION_REVISION_{field.upper()}_INVALID")
    text = value.strip()
    if (not allow_empty and not text) or len(text) > maximum:
        raise CurationRevisionContractError(f"CURATION_REVISION_{field.upper()}_INVALID")
    if any(ord(ch) < 32 and ch not in "\n\t\r" for ch in text):
        raise CurationRevisionContractError(f"CURATION_REVISION_{field.upper()}_INVALID")
    return text


def validate_revision_metrics(metrics: Mapping[str, Any]) -> dict[str, int]:
    if not isinstance(metrics, Mapping) or set(metrics) != _METRIC_FIELDS:
        raise CurationRevisionContractError("CURATION_REVISION_METRICS_INVALID")
    normalized: dict[str, int] = {}
    for key in sorted(_METRIC_FIELDS):
        value = metrics[key]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise CurationRevisionContractError("CURATION_REVISION_METRICS_INVALID")
        normalized[key] = value
    if (
        normalized["isolated_task_observations"]
        + normalized["confounded_task_observations"]
        != normalized["unique_task_observations"]
    ):
        raise CurationRevisionContractError("CURATION_REVISION_METRICS_PARTITION_INVALID")
    isolated_known = (
        normalized["isolated_verified_success"]
        + normalized["isolated_failed"]
        + normalized["isolated_waiting_human"]
        + normalized["isolated_done_unverified"]
    )
    if isolated_known > normalized["isolated_task_observations"]:
        raise CurationRevisionContractError("CURATION_REVISION_METRICS_PARTITION_INVALID")
    return normalized


@dataclass(frozen=True)
class CurationRevisionPacket:
    approval_id: str
    approval_sha256: str
    proposal_id: str
    proposal_sha256: str
    proposal_set_sha256: str
    item_id: str
    knowledge_sha256: str
    candidate_sha256: str
    checkpoint_sequence: int
    checkpoint_sha256: str
    state_sha256: str
    domain: str
    sensitivity: str
    risk_level: str
    active_level: str
    kind: str
    execution_mode: str
    curation_action: str
    revision_metrics: dict[str, int]
    current_title: str
    current_content: str
    current_scope: str
    trust: str = TRUST_MARKER
    capability_grants: tuple[str, ...] = ()
    output_schema_version: str = REVISION_RESULT_SCHEMA
    schema_version: str = REVISION_PACKET_SCHEMA

    FIELDS = {
        "schema_version", "approval_id", "approval_sha256", "proposal_id",
        "proposal_sha256", "proposal_set_sha256", "item_id", "knowledge_sha256",
        "candidate_sha256", "checkpoint_sequence", "checkpoint_sha256", "state_sha256",
        "domain", "sensitivity", "risk_level", "active_level", "kind", "execution_mode",
        "curation_action", "revision_metrics", "current_title", "current_content",
        "current_scope", "trust", "capability_grants", "output_schema_version",
    }

    def validate(self) -> "CurationRevisionPacket":
        for value, field in ((self.approval_id, "approval_id"), (self.proposal_id, "proposal_id"), (self.item_id, "item_id")):
            _id(value, field)
        for value, field in (
            (self.approval_sha256, "approval_sha256"),
            (self.proposal_sha256, "proposal_sha256"),
            (self.proposal_set_sha256, "proposal_set_sha256"),
            (self.knowledge_sha256, "knowledge_sha256"),
            (self.candidate_sha256, "candidate_sha256"),
            (self.checkpoint_sha256, "checkpoint_sha256"),
            (self.state_sha256, "state_sha256"),
        ):
            _sha(value, field)
        if not isinstance(self.checkpoint_sequence, int) or isinstance(self.checkpoint_sequence, bool) or self.checkpoint_sequence < 1:
            raise CurationRevisionContractError("CURATION_REVISION_CHECKPOINT_SEQUENCE_INVALID")
        if self.domain not in DOMAINS:
            raise CurationRevisionContractError("CURATION_REVISION_DOMAIN_INVALID")
        if self.sensitivity not in SENSITIVITIES or self.sensitivity == "secret":
            raise CurationRevisionContractError("CURATION_REVISION_SENSITIVITY_INVALID")
        if self.risk_level not in RISK_LEVELS:
            raise CurationRevisionContractError("CURATION_REVISION_RISK_INVALID")
        if self.active_level not in ACTIVE_LEVELS:
            raise CurationRevisionContractError("CURATION_REVISION_ACTIVE_LEVEL_INVALID")
        if self.kind not in KINDS:
            raise CurationRevisionContractError("CURATION_REVISION_KIND_INVALID")
        if self.execution_mode not in EXECUTION_MODES:
            raise CurationRevisionContractError("CURATION_REVISION_EXECUTION_MODE_INVALID")
        if self.curation_action not in REVISION_ACTIONS:
            raise CurationRevisionContractError("CURATION_REVISION_ACTION_FORBIDDEN")
        validate_revision_metrics(self.revision_metrics)
        _text(self.current_title, field="current_title", maximum=_MAX_TITLE)
        _text(self.current_content, field="current_content", maximum=_MAX_CONTENT)
        _text(self.current_scope, field="current_scope", maximum=_MAX_SCOPE)
        if self.trust != TRUST_MARKER:
            raise CurationRevisionContractError("CURATION_REVISION_TRUST_INVALID")
        if self.capability_grants != ():
            raise CurationRevisionContractError("CURATION_REVISION_CAPABILITY_GRANT_FORBIDDEN")
        if self.output_schema_version != REVISION_RESULT_SCHEMA:
            raise CurationRevisionContractError("CURATION_REVISION_OUTPUT_SCHEMA_INVALID")
        if len(_canonical(self.to_payload_unchecked()).encode("utf-8")) > _MAX_PACKET_BYTES:
            raise CurationRevisionContractError("CURATION_REVISION_PACKET_SIZE_INVALID")
        return self

    def to_payload_unchecked(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["capability_grants"] = list(self.capability_grants)
        payload["revision_metrics"] = validate_revision_metrics(self.revision_metrics)
        return payload

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return self.to_payload_unchecked()

    @property
    def sha256(self) -> str:
        return _digest(self.to_payload())

    @classmethod
    def from_payload(cls, payload: Any) -> "CurationRevisionPacket":
        data = _strict(payload, cls.FIELDS, REVISION_PACKET_SCHEMA)
        grants = data.get("capability_grants")
        if not isinstance(grants, list):
            raise CurationRevisionContractError("CURATION_REVISION_CAPABILITY_GRANT_FORBIDDEN")
        data["capability_grants"] = tuple(grants)
        data["revision_metrics"] = validate_revision_metrics(data["revision_metrics"])
        return cls(**data).validate()


@dataclass(frozen=True)
class CurationRevisionResult:
    result: str
    title: str
    content: str
    scope: str
    revision_reason: str
    schema_version: str = REVISION_RESULT_SCHEMA

    FIELDS = {"schema_version", "result", "title", "content", "scope", "revision_reason"}

    def validate(self) -> "CurationRevisionResult":
        if self.result not in REVISION_RESULTS:
            raise CurationRevisionContractError("CURATION_REVISION_RESULT_INVALID")
        _text(self.revision_reason, field="revision_reason", maximum=_MAX_REASON)
        if self.result == "NO_REVISION_VALUE":
            if self.title != "" or self.content != "" or self.scope != "":
                raise CurationRevisionContractError("CURATION_REVISION_NO_VALUE_PAYLOAD_INVALID")
            return self
        _text(self.title, field="title", maximum=_MAX_TITLE)
        _text(self.content, field="content", maximum=_MAX_CONTENT)
        _text(self.scope, field="scope", maximum=_MAX_SCOPE)
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)

    @classmethod
    def from_payload(cls, payload: Any) -> "CurationRevisionResult":
        return cls(**_strict(payload, cls.FIELDS, REVISION_RESULT_SCHEMA)).validate()


REVISION_RESULT_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "result", "title", "content", "scope", "revision_reason"],
    "properties": {
        "schema_version": {"type": "string", "enum": [REVISION_RESULT_SCHEMA]},
        "result": {"type": "string", "enum": ["REVISION_CANDIDATE", "NO_REVISION_VALUE"]},
        "title": {"type": "string", "maxLength": _MAX_TITLE},
        "content": {"type": "string", "maxLength": _MAX_CONTENT},
        "scope": {"type": "string", "maxLength": _MAX_SCOPE},
        "revision_reason": {"type": "string", "minLength": 1, "maxLength": _MAX_REASON},
    },
}


def parse_strict_curation_revision_result(raw: str) -> CurationRevisionResult:
    if not isinstance(raw, str) or not raw or raw != raw.strip() or len(raw.encode("utf-8")) > _MAX_RESULT_BYTES:
        raise CurationRevisionContractError("CURATION_REVISION_WORKER_OUTPUT_INVALID")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CurationRevisionContractError("CURATION_REVISION_WORKER_OUTPUT_INVALID") from exc
    if not isinstance(payload, dict):
        raise CurationRevisionContractError("CURATION_REVISION_WORKER_OUTPUT_INVALID")
    return CurationRevisionResult.from_payload(payload)
