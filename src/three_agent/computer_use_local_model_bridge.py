from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .computer_use import ComputerActionRequest, ComputerUseError, operation_policy

LOCAL_MODEL_PROPOSAL_SCHEMA = "workspace-local-computer-proposal/v1"
MAX_LOCAL_MODEL_PAYLOAD_BYTES = 16 * 1024
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ALLOWED_FIELDS = frozenset(
    {
        "schema_version",
        "proposal_id",
        "operation",
        "resource_kind",
        "resource_ref",
        "arguments",
        "expected_postcondition",
    }
)


class LocalModelComputerBridgeError(ValueError):
    """Local-model proposal is malformed or cannot be normalized safely."""


@dataclass(frozen=True)
class LocalModelComputerProposal:
    model_ref: str
    proposal_id: str
    canonical_action: ComputerActionRequest


def _bounded_provider_payload(payload: Mapping[str, Any]) -> None:
    if not isinstance(payload, Mapping):
        raise LocalModelComputerBridgeError("LOCAL_MODEL_PROPOSAL_MUST_BE_OBJECT")
    try:
        canonical = json.dumps(
            dict(payload),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise LocalModelComputerBridgeError("LOCAL_MODEL_PROPOSAL_NOT_CANONICAL_JSON") from exc
    if len(canonical.encode("utf-8")) > MAX_LOCAL_MODEL_PAYLOAD_BYTES:
        raise LocalModelComputerBridgeError("LOCAL_MODEL_PROPOSAL_BOUND_EXCEEDED")


def _provider_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not _ID_RE.fullmatch(value):
        raise LocalModelComputerBridgeError(f"LOCAL_MODEL_INVALID_{field.upper()}")
    return value


def translate_local_model_proposal(
    payload: Mapping[str, Any],
    *,
    model_ref: str,
    session_id: str,
    task_id: str,
    plan_fingerprint: str,
    node_id: str,
    state_precondition_sha256: str,
    idempotency_key: str,
) -> LocalModelComputerProposal:
    """Normalize a local-model proposal without granting authority.

    The model may propose only provider-neutral fields. Trusted execution context
    (session/task/plan/node/state/idempotency) is supplied by the caller. Effect,
    risk class, and writer requirements are always derived from WorkSpace's
    canonical operation policy and can never be overridden by model output.
    """

    _bounded_provider_payload(payload)
    if set(payload) - _ALLOWED_FIELDS:
        raise LocalModelComputerBridgeError("LOCAL_MODEL_PROPOSAL_FIELD_NOT_ALLOWED")
    if payload.get("schema_version") != LOCAL_MODEL_PROPOSAL_SCHEMA:
        raise LocalModelComputerBridgeError("LOCAL_MODEL_PROPOSAL_SCHEMA_VERSION_MISMATCH")

    proposal_id = _provider_id(payload.get("proposal_id"), "proposal_id")
    model_ref = _provider_id(model_ref, "model_ref")

    operation = payload.get("operation")
    if not isinstance(operation, str):
        raise LocalModelComputerBridgeError("LOCAL_MODEL_OPERATION_MUST_BE_STRING")
    try:
        effect, risk_class, requires_writer = operation_policy(operation)
    except ComputerUseError as exc:
        raise LocalModelComputerBridgeError("LOCAL_MODEL_UNKNOWN_COMPUTER_OPERATION") from exc

    resource_kind = payload.get("resource_kind")
    resource_ref = payload.get("resource_ref")
    arguments = payload.get("arguments", {})
    if not isinstance(arguments, Mapping):
        raise LocalModelComputerBridgeError("LOCAL_MODEL_ARGUMENTS_MUST_BE_OBJECT")

    expected_postcondition = payload.get("expected_postcondition")
    if expected_postcondition is not None and not isinstance(expected_postcondition, str):
        raise LocalModelComputerBridgeError("LOCAL_MODEL_EXPECTED_POSTCONDITION_MUST_BE_STRING")

    action = ComputerActionRequest(
        session_id=session_id,
        action_id=f"local:{proposal_id}",
        task_id=task_id,
        plan_fingerprint=plan_fingerprint,
        node_id=node_id,
        provider_ref=f"local:{model_ref}",
        operation=operation,
        effect=effect,
        resource_kind=resource_kind,
        resource_ref=resource_ref,
        arguments=dict(arguments),
        state_precondition_sha256=state_precondition_sha256,
        expected_postcondition=expected_postcondition,
        risk_class=risk_class,
        requires_writer=requires_writer,
        idempotency_key=idempotency_key,
    )
    try:
        action.validate()
    except ComputerUseError as exc:
        raise LocalModelComputerBridgeError(f"LOCAL_MODEL_CANONICAL_ACTION_INVALID:{exc}") from exc

    return LocalModelComputerProposal(
        model_ref=model_ref,
        proposal_id=proposal_id,
        canonical_action=action,
    )
