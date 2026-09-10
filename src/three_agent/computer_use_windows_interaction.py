from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .computer_use import (
    ComputerActionRequest,
    ComputerObservation,
    ComputerPolicyDecision,
    decide_computer_action,
)
from .computer_use_approval import (
    ComputerApprovalGrant,
    consume_computer_approval,
    require_valid_computer_approval,
)
from .computer_use_replay import ComputerActionReplayLedger, require_target_fresh
from .computer_use_writer import ComputerWriterBinding, require_current_writer_binding
from .runtime_writer_lease import RuntimeWriterLease, RuntimeWriterLeaseRepository

WINDOWS_UIA_INTERACTIONS = frozenset({"invoke", "value", "select"})
WINDOWS_POINTER_INTERACTIONS = frozenset({"click"})
WINDOWS_KEYBOARD_INTERACTIONS = frozenset({"text"})
MAX_WINDOWS_SELECTOR_CHARS = 256
MAX_WINDOWS_TYPED_TEXT_CHARS = 4096
MIN_POINTER_COORDINATE = -32768
MAX_POINTER_COORDINATE = 32767
_WINDOW_ID_RE = re.compile(r"^0x[0-9A-Fa-f]{1,16}$")
_PROCESS_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

_POSTCONDITION_BY_KIND = {
    ("computer.accessibility.interact", "invoke"): "WINDOWS_UIA_INVOKED",
    ("computer.accessibility.interact", "value"): "WINDOWS_UIA_VALUE_SET",
    ("computer.accessibility.interact", "select"): "WINDOWS_UIA_ITEM_SELECTED",
    ("computer.pointer.interact", "click"): "WINDOWS_POINTER_CLICK_SENT",
    ("computer.keyboard.interact", "text"): "WINDOWS_KEYBOARD_TEXT_SENT",
}


class WindowsInteractionError(RuntimeError):
    """Governed Windows interaction failed admission, dispatch, or verification."""


class WindowsDispatchError(WindowsInteractionError):
    """Backend dispatch failed after approval/replay consumption may have occurred."""

    def __init__(
        self,
        reason_code: str,
        *,
        consumed_approval: ComputerApprovalGrant | None,
    ) -> None:
        self.reason_code = reason_code
        self.consumed_approval = consumed_approval
        super().__init__(reason_code)


@dataclass(frozen=True)
class WindowsInteractionCommand:
    session_id: str
    task_id: str
    operation: str
    interaction_kind: str
    resource_ref: str
    window_id: str
    process_id: int
    process_name: str
    arguments: Mapping[str, Any]
    expected_postcondition: str


@dataclass(frozen=True)
class WindowsTargetInspection:
    window_id: str
    process_id: int
    process_name: str
    automation_id: str | None = None
    name: str | None = None
    control_type: str | None = None
    secure_input: bool = False
    focused: bool = False


@dataclass(frozen=True)
class WindowsInteractionBackendResult:
    post_observation: ComputerObservation
    observed_postconditions: tuple[str, ...]
    result: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class GovernedWindowsInteractionResult:
    backend_result: WindowsInteractionBackendResult
    consumed_approval: ComputerApprovalGrant


class WindowsInteractionBackend(Protocol):
    """Constrained Windows backend; no arbitrary shell or elevated command surface."""

    def inspect_target(self, command: WindowsInteractionCommand) -> WindowsTargetInspection:
        ...

    def dispatch(self, command: WindowsInteractionCommand) -> WindowsInteractionBackendResult:
        ...


def _bounded_text(
    value: Any,
    *,
    field: str,
    limit: int,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise WindowsInteractionError(f"INVALID_WINDOWS_{field.upper()}")
    if not value and not allow_empty:
        raise WindowsInteractionError(f"INVALID_WINDOWS_{field.upper()}")
    if len(value) > limit or "\x00" in value or "\r" in value or "\n" in value:
        raise WindowsInteractionError(f"INVALID_WINDOWS_{field.upper()}")
    return value


def _strict_arguments(arguments: Mapping[str, Any], allowed: frozenset[str]) -> dict[str, Any]:
    if not isinstance(arguments, Mapping):
        raise WindowsInteractionError("WINDOWS_INTERACTION_ARGUMENTS_MUST_BE_OBJECT")
    if set(arguments) - allowed:
        raise WindowsInteractionError("WINDOWS_INTERACTION_ARGUMENT_NOT_ALLOWED")
    return dict(arguments)


def _selector(arguments: Mapping[str, Any]) -> dict[str, str]:
    automation_id = arguments.get("automation_id")
    name = arguments.get("name")
    if (automation_id is None) == (name is None):
        raise WindowsInteractionError("WINDOWS_UIA_SELECTOR_REQUIRES_EXACTLY_ONE_IDENTITY")
    result: dict[str, str] = {}
    if automation_id is not None:
        result["automation_id"] = _bounded_text(
            automation_id,
            field="automation_id",
            limit=MAX_WINDOWS_SELECTOR_CHARS,
        )
    if name is not None:
        result["name"] = _bounded_text(
            name,
            field="element_name",
            limit=MAX_WINDOWS_SELECTOR_CHARS,
        )
    control_type = arguments.get("control_type")
    if control_type is not None:
        result["control_type"] = _bounded_text(
            control_type,
            field="control_type",
            limit=MAX_WINDOWS_SELECTOR_CHARS,
        )
    return result


def _normalize_action_arguments(action: ComputerActionRequest) -> tuple[str, dict[str, Any]]:
    operation = action.operation
    arguments = dict(action.arguments)
    interaction = arguments.get("interaction")

    if operation == "computer.accessibility.interact":
        if interaction not in WINDOWS_UIA_INTERACTIONS:
            raise WindowsInteractionError("UNSUPPORTED_WINDOWS_UIA_INTERACTION")
        allowed = frozenset({"interaction", "automation_id", "name", "control_type", "value"})
        normalized = _strict_arguments(arguments, allowed)
        normalized.update(_selector(normalized))
        if interaction == "value":
            normalized["value"] = _bounded_text(
                normalized.get("value"),
                field="typed_text",
                limit=MAX_WINDOWS_TYPED_TEXT_CHARS,
                allow_empty=True,
            )
        elif "value" in normalized:
            raise WindowsInteractionError("WINDOWS_UIA_VALUE_ARGUMENT_NOT_ALLOWED")
        return interaction, normalized

    if operation == "computer.pointer.interact":
        if interaction not in WINDOWS_POINTER_INTERACTIONS:
            raise WindowsInteractionError("UNSUPPORTED_WINDOWS_POINTER_INTERACTION")
        normalized = _strict_arguments(arguments, frozenset({"interaction", "x", "y"}))
        for field in ("x", "y"):
            value = normalized.get(field)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not MIN_POINTER_COORDINATE <= value <= MAX_POINTER_COORDINATE
            ):
                raise WindowsInteractionError(f"INVALID_WINDOWS_POINTER_{field.upper()}")
        return interaction, normalized

    if operation == "computer.keyboard.interact":
        if interaction not in WINDOWS_KEYBOARD_INTERACTIONS:
            raise WindowsInteractionError("UNSUPPORTED_WINDOWS_KEYBOARD_INTERACTION")
        normalized = _strict_arguments(
            arguments,
            frozenset({"interaction", "text", "focus_automation_id"}),
        )
        normalized["text"] = _bounded_text(
            normalized.get("text"),
            field="typed_text",
            limit=MAX_WINDOWS_TYPED_TEXT_CHARS,
            allow_empty=True,
        )
        normalized["focus_automation_id"] = _bounded_text(
            normalized.get("focus_automation_id"),
            field="focus_automation_id",
            limit=MAX_WINDOWS_SELECTOR_CHARS,
        )
        return interaction, normalized

    raise WindowsInteractionError("UNSUPPORTED_GOVERNED_WINDOWS_OPERATION")


def _observation_identity(observation: ComputerObservation) -> tuple[str, int, str]:
    observation.validate()
    if observation.surface != "desktop":
        raise WindowsInteractionError("WINDOWS_INTERACTION_REQUIRES_DESKTOP_OBSERVATION")
    structured = observation.structured_observation
    if not isinstance(structured, Mapping) or structured.get("platform") != "windows":
        raise WindowsInteractionError("WINDOWS_INTERACTION_REQUIRES_WINDOWS_OBSERVATION")
    window_id = structured.get("window_id")
    process_id = structured.get("process_id")
    process_name = structured.get("process_name")
    if not isinstance(window_id, str) or not _WINDOW_ID_RE.fullmatch(window_id):
        raise WindowsInteractionError("INVALID_WINDOWS_OBSERVATION_WINDOW_ID")
    if isinstance(process_id, bool) or not isinstance(process_id, int) or process_id <= 0:
        raise WindowsInteractionError("INVALID_WINDOWS_OBSERVATION_PROCESS_ID")
    if not isinstance(process_name, str) or not _PROCESS_NAME_RE.fullmatch(process_name):
        raise WindowsInteractionError("INVALID_WINDOWS_OBSERVATION_PROCESS_NAME")
    expected_target_ref = f"windows:window:{window_id}/process:{process_id}"
    if observation.active_target_ref != expected_target_ref:
        raise WindowsInteractionError("WINDOWS_OBSERVATION_TARGET_IDENTITY_MISMATCH")
    return window_id, process_id, process_name


def _find_uia_node(value: Any, *, key: str, expected: str) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    if value.get(key) == expected:
        return value
    children = value.get("children")
    if isinstance(children, list):
        for child in children:
            match = _find_uia_node(child, key=key, expected=expected)
            if match is not None:
                return match
    return None


def _validate_preobserved_selector(
    *,
    observation: ComputerObservation,
    operation: str,
    arguments: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    accessibility = observation.structured_observation.get("accessibility")
    if operation == "computer.accessibility.interact":
        if "automation_id" in arguments:
            node = _find_uia_node(
                accessibility,
                key="automation_id",
                expected=str(arguments["automation_id"]),
            )
        else:
            node = _find_uia_node(
                accessibility,
                key="name",
                expected=str(arguments["name"]),
            )
        if node is None:
            raise WindowsInteractionError("WINDOWS_UIA_TARGET_NOT_IN_PREOBSERVATION")
        expected_control_type = arguments.get("control_type")
        if expected_control_type is not None and node.get("control_type") != expected_control_type:
            raise WindowsInteractionError("WINDOWS_UIA_TARGET_CONTROL_TYPE_STALE")
        if node.get("is_enabled") is False:
            raise WindowsInteractionError("WINDOWS_UIA_TARGET_DISABLED")
        if node.get("is_offscreen") is True:
            raise WindowsInteractionError("WINDOWS_UIA_TARGET_OFFSCREEN")
        return node

    if operation == "computer.keyboard.interact":
        focus_id = str(arguments["focus_automation_id"])
        node = _find_uia_node(accessibility, key="automation_id", expected=focus_id)
        if node is None:
            raise WindowsInteractionError("WINDOWS_KEYBOARD_FOCUS_NOT_IN_PREOBSERVATION")
        return node
    return None


def _command_from_action(
    *,
    action: ComputerActionRequest,
    pre_observation: ComputerObservation,
) -> WindowsInteractionCommand:
    interaction_kind, arguments = _normalize_action_arguments(action)
    window_id, process_id, process_name = _observation_identity(pre_observation)
    expected_resource_ref = f"local:desktop:window:{window_id}"
    if action.resource_ref != expected_resource_ref:
        raise WindowsInteractionError("WINDOWS_ACTION_WINDOW_RESOURCE_STALE")
    expected = _POSTCONDITION_BY_KIND.get((action.operation, interaction_kind))
    if expected is None:
        raise WindowsInteractionError("WINDOWS_POSTCONDITION_KIND_UNSUPPORTED")
    if action.expected_postcondition != expected:
        raise WindowsInteractionError("WINDOWS_EXPECTED_POSTCONDITION_MISMATCH")
    _validate_preobserved_selector(
        observation=pre_observation,
        operation=action.operation,
        arguments=arguments,
    )
    return WindowsInteractionCommand(
        session_id=action.session_id,
        task_id=action.task_id,
        operation=action.operation,
        interaction_kind=interaction_kind,
        resource_ref=action.resource_ref,
        window_id=window_id,
        process_id=process_id,
        process_name=process_name,
        arguments=arguments,
        expected_postcondition=expected,
    )


def _require_inspection_matches(
    *,
    command: WindowsInteractionCommand,
    inspection: WindowsTargetInspection,
) -> None:
    if not isinstance(inspection, WindowsTargetInspection):
        raise WindowsInteractionError("INVALID_WINDOWS_TARGET_INSPECTION")
    if (
        inspection.window_id != command.window_id
        or inspection.process_id != command.process_id
        or inspection.process_name.lower() != command.process_name.lower()
    ):
        raise WindowsInteractionError("WINDOWS_FOREGROUND_TARGET_STALE")

    if command.operation == "computer.accessibility.interact":
        expected_automation_id = command.arguments.get("automation_id")
        expected_name = command.arguments.get("name")
        expected_control_type = command.arguments.get("control_type")
        if expected_automation_id is not None and inspection.automation_id != expected_automation_id:
            raise WindowsInteractionError("WINDOWS_UIA_TARGET_INSPECTION_STALE")
        if expected_name is not None and inspection.name != expected_name:
            raise WindowsInteractionError("WINDOWS_UIA_TARGET_INSPECTION_STALE")
        if expected_control_type is not None and inspection.control_type != expected_control_type:
            raise WindowsInteractionError("WINDOWS_UIA_TARGET_INSPECTION_STALE")

    if command.operation == "computer.keyboard.interact":
        if inspection.automation_id != command.arguments["focus_automation_id"] or not inspection.focused:
            raise WindowsInteractionError("WINDOWS_KEYBOARD_FOCUS_STALE")

    if (
        command.operation in {"computer.accessibility.interact", "computer.keyboard.interact"}
        and command.interaction_kind in {"value", "text"}
        and inspection.secure_input
    ):
        raise WindowsInteractionError("WINDOWS_SECURE_INPUT_USER_TAKEOVER_REQUIRED")


def execute_governed_windows_action(
    *,
    action: ComputerActionRequest,
    pre_observation: ComputerObservation,
    capability_decision: Any,
    policy_decision: ComputerPolicyDecision,
    backend: WindowsInteractionBackend,
    replay_ledger: ComputerActionReplayLedger,
    approver_session_ref: str,
    now: str,
    approval: ComputerApprovalGrant | None,
    lease_repository: RuntimeWriterLeaseRepository | None,
    lease: RuntimeWriterLease | None,
    writer_binding: ComputerWriterBinding | None,
    user_takeover_active: bool,
    allow_input_fallback: bool = False,
) -> GovernedWindowsInteractionResult:
    """Execute one bounded Windows action under existing WorkSpace governance.

    Accessibility mutation is the preferred desktop route. Pointer/keyboard
    fallback is never selected implicitly: it must be represented as its own
    canonical action, receive its own approval/writer binding, and the caller
    must explicitly enable fallback for that attempt.
    """

    if not isinstance(user_takeover_active, bool):
        raise WindowsInteractionError("INVALID_WINDOWS_USER_TAKEOVER_STATE")
    if user_takeover_active:
        raise WindowsInteractionError("WINDOWS_USER_TAKEOVER_ACTIVE")

    action.validate()
    pre_observation.validate()
    policy_decision.validate()
    require_target_fresh(action=action, observation=pre_observation)

    derived_policy = decide_computer_action(action, capability_decision)
    if derived_policy.fingerprint != policy_decision.fingerprint:
        raise WindowsInteractionError("WINDOWS_POLICY_DECISION_MISMATCH")
    if policy_decision.outcome == "DENY":
        raise WindowsInteractionError("WINDOWS_ACTION_POLICY_DENIED")
    if policy_decision.outcome != "REQUIRE_APPROVAL":
        raise WindowsInteractionError("WINDOWS_MUTATION_MUST_REQUIRE_APPROVAL")
    if not action.requires_writer:
        raise WindowsInteractionError("WINDOWS_MUTATION_MUST_REQUIRE_WRITER")

    if action.operation in {"computer.pointer.interact", "computer.keyboard.interact"}:
        if not allow_input_fallback:
            raise WindowsInteractionError("WINDOWS_INPUT_FALLBACK_NOT_AUTHORIZED")
    elif allow_input_fallback:
        raise WindowsInteractionError("WINDOWS_INPUT_FALLBACK_FLAG_UNEXPECTED")

    command = _command_from_action(action=action, pre_observation=pre_observation)
    inspection = backend.inspect_target(command)
    _require_inspection_matches(command=command, inspection=inspection)

    if approval is None:
        raise WindowsInteractionError("WINDOWS_ACTION_APPROVAL_REQUIRED")
    require_valid_computer_approval(
        grant=approval,
        action=action,
        policy_decision=policy_decision,
        approver_session_ref=approver_session_ref,
        now=now,
    )

    if lease_repository is None or lease is None or writer_binding is None:
        raise WindowsInteractionError("WINDOWS_ACTION_WRITER_FENCE_REQUIRED")
    require_current_writer_binding(
        action=action,
        binding=writer_binding,
        lease_repository=lease_repository,
        lease=lease,
    )

    replay_ledger.admit_once(action=action, observation=pre_observation)
    consumed_approval = consume_computer_approval(
        grant=approval,
        action=action,
        policy_decision=policy_decision,
        approver_session_ref=approver_session_ref,
        now=now,
    )

    require_current_writer_binding(
        action=action,
        binding=writer_binding,
        lease_repository=lease_repository,
        lease=lease,
    )

    try:
        backend_result = backend.dispatch(command)
    except Exception as exc:
        raise WindowsDispatchError(
            "WINDOWS_BACKEND_DISPATCH_FAILED",
            consumed_approval=consumed_approval,
        ) from exc
    if not isinstance(backend_result, WindowsInteractionBackendResult):
        raise WindowsDispatchError(
            "INVALID_WINDOWS_BACKEND_RESULT",
            consumed_approval=consumed_approval,
        )

    post = backend_result.post_observation
    post.validate()
    if post.task_id != action.task_id or post.session_id != action.session_id:
        raise WindowsDispatchError(
            "WINDOWS_POST_OBSERVATION_IDENTITY_MISMATCH",
            consumed_approval=consumed_approval,
        )
    if action.expected_postcondition not in backend_result.observed_postconditions:
        raise WindowsDispatchError(
            "WINDOWS_POSTCONDITION_NOT_SATISFIED",
            consumed_approval=consumed_approval,
        )
    return GovernedWindowsInteractionResult(
        backend_result=backend_result,
        consumed_approval=consumed_approval,
    )
