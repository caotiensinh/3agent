from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .computer_use import ComputerActionRequest, ComputerObservation

ANTHROPIC_TOOL_USE_TYPE = "tool_use"
ANTHROPIC_TOOL_RESULT_TYPE = "tool_result"
ANTHROPIC_DEFAULT_COMPUTER_TOOL_NAMES = ("computer",)
MAX_PROVIDER_ERROR_CHARS = 512
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class AnthropicComputerBridgeError(ValueError):
    """Anthropic computer-use payload is malformed or cannot be translated safely."""


@dataclass(frozen=True)
class AnthropicComputerToolProposal:
    tool_use_id: str
    tool_name: str
    canonical_action: ComputerActionRequest


@dataclass(frozen=True)
class AnthropicComputerToolResult:
    tool_use_id: str
    screenshot_sha256: str
    state_sha256: str

    def canonical_provider_dict(self) -> dict[str, Any]:
        retained = {
            "retention": "workspace_retained_metadata_only",
            "screenshot_sha256": self.screenshot_sha256,
            "state_sha256": self.state_sha256,
        }
        return {
            "type": ANTHROPIC_TOOL_RESULT_TYPE,
            "tool_use_id": self.tool_use_id,
            "is_error": False,
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        retained,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                }
            ],
        }


def _provider_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not _ID_RE.fullmatch(value):
        raise AnthropicComputerBridgeError(f"ANTHROPIC_INVALID_{field.upper()}")
    return value


def _tool_name(value: Any) -> str:
    if not isinstance(value, str) or value != value.strip() or not _TOOL_NAME_RE.fullmatch(value):
        raise AnthropicComputerBridgeError("ANTHROPIC_INVALID_TOOL_NAME")
    return value


def translate_anthropic_computer_tool_use(
    payload: Mapping[str, Any],
    *,
    session_id: str,
    task_id: str,
    plan_fingerprint: str,
    node_id: str,
    browser_resource_ref: str,
    state_precondition_sha256: str,
    idempotency_key: str,
    allowed_tool_names: tuple[str, ...] = ANTHROPIC_DEFAULT_COMPUTER_TOOL_NAMES,
) -> AnthropicComputerToolProposal:
    """Translate only the currently safe Anthropic computer-use subset.

    Anthropic tool_use output is an untrusted proposal. This bridge deliberately
    supports only screenshot observation in v1. Pointer, keyboard, and other
    mutating computer actions do not gain WorkSpace authority merely because the
    provider emitted them; they fail closed until a reviewed semantics-preserving
    mapping exists.
    """

    if not isinstance(payload, Mapping):
        raise AnthropicComputerBridgeError("ANTHROPIC_TOOL_USE_MUST_BE_OBJECT")
    if payload.get("type") != ANTHROPIC_TOOL_USE_TYPE:
        raise AnthropicComputerBridgeError("ANTHROPIC_TOOL_USE_TYPE_MISMATCH")
    tool_use_id = _provider_id(payload.get("id"), "tool_use_id")
    tool_name = _tool_name(payload.get("name"))
    if not isinstance(allowed_tool_names, tuple) or not allowed_tool_names:
        raise AnthropicComputerBridgeError("ANTHROPIC_ALLOWED_TOOL_NAMES_REQUIRED")
    normalized_allowed = tuple(_tool_name(name) for name in allowed_tool_names)
    if tool_name not in normalized_allowed:
        raise AnthropicComputerBridgeError("ANTHROPIC_COMPUTER_TOOL_NAME_NOT_ALLOWED")

    input_value = payload.get("input")
    if not isinstance(input_value, Mapping):
        raise AnthropicComputerBridgeError("ANTHROPIC_COMPUTER_INPUT_MUST_BE_OBJECT")
    action_type = input_value.get("action")
    if action_type != "screenshot":
        raise AnthropicComputerBridgeError(
            "ANTHROPIC_COMPUTER_ACTION_REQUIRES_REVIEWED_SEMANTIC_TARGET"
        )
    if set(input_value) != {"action"}:
        raise AnthropicComputerBridgeError("ANTHROPIC_SCREENSHOT_ACTION_FIELD_NOT_ALLOWED")

    canonical = ComputerActionRequest(
        session_id=session_id,
        action_id=f"anthropic:{tool_use_id}",
        task_id=task_id,
        plan_fingerprint=plan_fingerprint,
        node_id=node_id,
        provider_ref=f"anthropic:{tool_use_id}",
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
    return AnthropicComputerToolProposal(
        tool_use_id=tool_use_id,
        tool_name=tool_name,
        canonical_action=canonical,
    )


def build_anthropic_computer_tool_result(
    *,
    tool_use_id: str,
    observation: ComputerObservation,
    screenshot_sha256: str,
) -> AnthropicComputerToolResult:
    """Build a bounded tool_result from an already-retained WorkSpace screenshot.

    No raw screenshot bytes, data URLs, filesystem paths, or provider-controlled
    URLs cross this bridge. A richer image result requires a separate retention
    review because Anthropic tool_result image content can otherwise become a new
    raw-output path around CU-240.
    """

    tool_use_id = _provider_id(tool_use_id, "tool_use_id")
    observation.validate()
    if observation.screenshot_sha256 is None:
        raise AnthropicComputerBridgeError("ANTHROPIC_SCREENSHOT_OUTPUT_NOT_RETAINED")
    if screenshot_sha256 != observation.screenshot_sha256:
        raise AnthropicComputerBridgeError("ANTHROPIC_SCREENSHOT_OUTPUT_DIGEST_MISMATCH")
    return AnthropicComputerToolResult(
        tool_use_id=tool_use_id,
        screenshot_sha256=screenshot_sha256,
        state_sha256=observation.state_sha256,
    )


def map_anthropic_computer_error(*, status: Any = None, error: Any = None) -> str:
    """Map provider failures into a bounded internal error vocabulary."""

    text = "" if error is None else str(error)
    if len(text) > MAX_PROVIDER_ERROR_CHARS:
        text = text[:MAX_PROVIDER_ERROR_CHARS]
    normalized = text.lower()
    if status in {408, 504} or "timeout" in normalized:
        return "ANTHROPIC_COMPUTER_TIMEOUT"
    if status in {401, 403}:
        return "ANTHROPIC_COMPUTER_AUTH_DENIED"
    if status == 429 or "rate limit" in normalized or "rate_limit" in normalized:
        return "ANTHROPIC_COMPUTER_RATE_LIMITED"
    if status is not None and isinstance(status, int) and 500 <= status <= 599:
        return "ANTHROPIC_COMPUTER_PROVIDER_UNAVAILABLE"
    return "ANTHROPIC_COMPUTER_PROVIDER_FAILED"
