from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from .computer_use import ComputerActionRequest, ComputerObservation

OPENAI_COMPUTER_CALL_TYPE = "computer_call"
OPENAI_COMPUTER_CALL_OUTPUT_TYPE = "computer_call_output"
OPENAI_COMPUTER_SCREENSHOT_TYPE = "computer_screenshot"
MAX_PROVIDER_ID_CHARS = 128
MAX_PROVIDER_ERROR_CHARS = 512
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_FILE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")


class OpenAIComputerBridgeError(ValueError):
    """OpenAI computer-use payload is malformed or cannot be translated safely."""


@dataclass(frozen=True)
class OpenAIComputerCallProposal:
    call_id: str
    provider_item_id: str | None
    canonical_action: ComputerActionRequest
    pending_safety_check_ids: tuple[str, ...]


@dataclass(frozen=True)
class OpenAIComputerCallOutput:
    call_id: str
    screenshot_file_id: str
    screenshot_sha256: str

    def canonical_provider_dict(self) -> dict[str, Any]:
        return {
            "type": OPENAI_COMPUTER_CALL_OUTPUT_TYPE,
            "call_id": self.call_id,
            "output": {
                "type": OPENAI_COMPUTER_SCREENSHOT_TYPE,
                "file_id": self.screenshot_file_id,
            },
        }


def _provider_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not _ID_RE.fullmatch(value):
        raise OpenAIComputerBridgeError(f"OPENAI_INVALID_{field.upper()}")
    return value


def _pending_safety_checks(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise OpenAIComputerBridgeError("OPENAI_PENDING_SAFETY_CHECKS_MUST_BE_LIST")
    result: list[str] = []
    seen: set[str] = set()
    for row in value:
        if not isinstance(row, Mapping):
            raise OpenAIComputerBridgeError("OPENAI_PENDING_SAFETY_CHECK_INVALID")
        check_id = _provider_id(row.get("id"), "safety_check_id")
        if check_id not in seen:
            seen.add(check_id)
            result.append(check_id)
    return tuple(result)


def translate_openai_computer_call(
    payload: Mapping[str, Any],
    *,
    session_id: str,
    task_id: str,
    plan_fingerprint: str,
    node_id: str,
    browser_resource_ref: str,
    state_precondition_sha256: str,
    idempotency_key: str,
) -> OpenAIComputerCallProposal:
    """Translate only the currently safe OpenAI computer-use subset.

    Provider output is an untrusted proposal. This bridge deliberately supports
    only screenshot/observation requests in v1. Pixel click/type/drag/scroll
    actions do not have a semantics-preserving mapping into the selector-governed
    browser interaction path and therefore fail closed instead of bypassing
    WorkSpace targeting, approval, writer, or stale-state controls.
    """

    if not isinstance(payload, Mapping):
        raise OpenAIComputerBridgeError("OPENAI_COMPUTER_CALL_MUST_BE_OBJECT")
    if payload.get("type") != OPENAI_COMPUTER_CALL_TYPE:
        raise OpenAIComputerBridgeError("OPENAI_COMPUTER_CALL_TYPE_MISMATCH")
    call_id = _provider_id(payload.get("call_id"), "call_id")
    provider_item_id = payload.get("id")
    if provider_item_id is not None:
        provider_item_id = _provider_id(provider_item_id, "item_id")
    action = payload.get("action")
    if not isinstance(action, Mapping):
        raise OpenAIComputerBridgeError("OPENAI_COMPUTER_ACTION_MUST_BE_OBJECT")
    action_type = action.get("type")
    if action_type != "screenshot":
        raise OpenAIComputerBridgeError("OPENAI_COMPUTER_ACTION_REQUIRES_REVIEWED_SEMANTIC_TARGET")
    if set(action) != {"type"}:
        raise OpenAIComputerBridgeError("OPENAI_SCREENSHOT_ACTION_FIELD_NOT_ALLOWED")

    canonical = ComputerActionRequest(
        session_id=session_id,
        action_id=f"openai:{call_id}",
        task_id=task_id,
        plan_fingerprint=plan_fingerprint,
        node_id=node_id,
        provider_ref=f"openai:{call_id}",
        operation="browser.dom.observe",
        effect="read",
        resource_kind="browser_document",
        resource_ref=browser_resource_ref,
        arguments={"provider_request": "screenshot"},
        state_precondition_sha256=state_precondition_sha256,
        idempotency_key=idempotency_key,
        risk_class="R0_OBSERVE",
        requires_writer=False,
    ).validate()
    return OpenAIComputerCallProposal(
        call_id=call_id,
        provider_item_id=provider_item_id,
        canonical_action=canonical,
        pending_safety_check_ids=_pending_safety_checks(payload.get("pending_safety_checks")),
    )


def build_openai_computer_call_output(
    *,
    call_id: str,
    observation: ComputerObservation,
    screenshot_file_id: str,
    screenshot_sha256: str,
) -> OpenAIComputerCallOutput:
    """Build provider output only from an already-retained WorkSpace screenshot.

    The bridge accepts only a provider file identifier, never raw image bytes or
    image URLs. The supplied digest must exactly match the canonical observation,
    so provider output cannot substitute an unreviewed screenshot after retention.
    """

    call_id = _provider_id(call_id, "call_id")
    observation.validate()
    if observation.screenshot_sha256 is None:
        raise OpenAIComputerBridgeError("OPENAI_SCREENSHOT_OUTPUT_NOT_RETAINED")
    if screenshot_sha256 != observation.screenshot_sha256:
        raise OpenAIComputerBridgeError("OPENAI_SCREENSHOT_OUTPUT_DIGEST_MISMATCH")
    if not isinstance(screenshot_file_id, str) or not _FILE_ID_RE.fullmatch(screenshot_file_id):
        raise OpenAIComputerBridgeError("OPENAI_INVALID_SCREENSHOT_FILE_ID")
    return OpenAIComputerCallOutput(
        call_id=call_id,
        screenshot_file_id=screenshot_file_id,
        screenshot_sha256=screenshot_sha256,
    )


def map_openai_computer_error(*, status: Any = None, error: Any = None) -> str:
    """Map provider failures into a bounded internal error vocabulary."""

    text = "" if error is None else str(error)
    if len(text) > MAX_PROVIDER_ERROR_CHARS:
        text = text[:MAX_PROVIDER_ERROR_CHARS]
    normalized = text.lower()
    if status in {408, 504} or "timeout" in normalized:
        return "OPENAI_COMPUTER_TIMEOUT"
    if status in {401, 403}:
        return "OPENAI_COMPUTER_AUTH_DENIED"
    if status == 429 or "rate limit" in normalized:
        return "OPENAI_COMPUTER_RATE_LIMITED"
    if status is not None and isinstance(status, int) and 500 <= status <= 599:
        return "OPENAI_COMPUTER_PROVIDER_UNAVAILABLE"
    return "OPENAI_COMPUTER_PROVIDER_FAILED"
