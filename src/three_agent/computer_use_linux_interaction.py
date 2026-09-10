from __future__ import annotations

import re
import sys
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
from .computer_use_linux_observation import (
    LinuxAtspiObservationBackend,
    LinuxObservationConfig,
    LinuxReadOnlyBackend,
    _accessible_identity,
    _find_active_window,
    _is_secure_accessible,
    _load_atspi,
    _safe_call_text,
    capture_linux_observation,
)
from .computer_use_replay import ComputerActionReplayLedger, require_target_fresh
from .computer_use_writer import ComputerWriterBinding, require_current_writer_binding
from .runtime_writer_lease import RuntimeWriterLease, RuntimeWriterLeaseRepository

LINUX_ATSPI_INTERACTIONS = frozenset({"invoke", "value"})
MAX_LINUX_SELECTOR_CHARS = 128
MAX_LINUX_TYPED_TEXT_CHARS = 4096
MAX_LINUX_RESOLVE_NODES = 512
_ACCESSIBLE_ID_RE = re.compile(r"^atspi-[0-9a-f]{32}$")
_POSTCONDITION_BY_KIND = {
    "invoke": "LINUX_ATSPI_ACTION_INVOKED",
    "value": "LINUX_ATSPI_TEXT_SET",
}
_ALLOWED_ATSPI_ACTION_NAMES = frozenset({"activate", "click", "open", "press"})


class LinuxInteractionError(RuntimeError):
    """Governed Linux interaction failed admission, dispatch, or verification."""


class LinuxDispatchError(LinuxInteractionError):
    """AT-SPI dispatch failed after approval/replay consumption may have occurred."""

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
class LinuxInteractionCommand:
    session_id: str
    task_id: str
    operation: str
    interaction_kind: str
    resource_ref: str
    target_id: str
    process_id: int
    accessible_id: str
    role: str | None
    arguments: Mapping[str, Any]
    expected_postcondition: str


@dataclass(frozen=True)
class LinuxTargetInspection:
    target_id: str
    process_id: int
    accessible_id: str
    role: str
    secure_input: bool = False
    focused: bool = False


@dataclass(frozen=True)
class LinuxInteractionBackendResult:
    post_observation: ComputerObservation
    observed_postconditions: tuple[str, ...]
    result: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class GovernedLinuxInteractionResult:
    backend_result: LinuxInteractionBackendResult
    consumed_approval: ComputerApprovalGrant


class LinuxInteractionBackend(Protocol):
    """Constrained semantic Linux backend; no shell, pointer, or privilege surface."""

    def inspect_target(self, command: LinuxInteractionCommand) -> LinuxTargetInspection:
        ...

    def dispatch(self, command: LinuxInteractionCommand) -> LinuxInteractionBackendResult:
        ...


def _bounded_text(
    value: Any,
    *,
    field: str,
    limit: int,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise LinuxInteractionError(f"INVALID_LINUX_{field.upper()}")
    if not value and not allow_empty:
        raise LinuxInteractionError(f"INVALID_LINUX_{field.upper()}")
    if len(value) > limit or "\x00" in value or "\r" in value or "\n" in value:
        raise LinuxInteractionError(f"INVALID_LINUX_{field.upper()}")
    return value


def _normalize_action_arguments(action: ComputerActionRequest) -> tuple[str, dict[str, Any]]:
    if action.operation != "computer.accessibility.interact":
        if action.operation in {"computer.pointer.interact", "computer.keyboard.interact"}:
            raise LinuxInteractionError("LINUX_INPUT_FALLBACK_NOT_IMPLEMENTED")
        raise LinuxInteractionError("UNSUPPORTED_GOVERNED_LINUX_OPERATION")
    if not isinstance(action.arguments, Mapping):
        raise LinuxInteractionError("LINUX_INTERACTION_ARGUMENTS_MUST_BE_OBJECT")
    arguments = dict(action.arguments)
    if set(arguments) - {"interaction", "accessible_id", "role", "value"}:
        raise LinuxInteractionError("LINUX_INTERACTION_ARGUMENT_NOT_ALLOWED")
    interaction = arguments.get("interaction")
    if interaction not in LINUX_ATSPI_INTERACTIONS:
        raise LinuxInteractionError("UNSUPPORTED_LINUX_ATSPI_INTERACTION")
    accessible_id = arguments.get("accessible_id")
    if not isinstance(accessible_id, str) or not _ACCESSIBLE_ID_RE.fullmatch(accessible_id):
        raise LinuxInteractionError("INVALID_LINUX_ACCESSIBLE_ID")
    normalized: dict[str, Any] = {
        "interaction": interaction,
        "accessible_id": accessible_id,
    }
    role = arguments.get("role")
    if role is not None:
        normalized["role"] = _bounded_text(
            role,
            field="role",
            limit=MAX_LINUX_SELECTOR_CHARS,
        )
    if interaction == "value":
        normalized["value"] = _bounded_text(
            arguments.get("value"),
            field="typed_text",
            limit=MAX_LINUX_TYPED_TEXT_CHARS,
            allow_empty=True,
        )
    elif "value" in arguments:
        raise LinuxInteractionError("LINUX_ATSPI_VALUE_ARGUMENT_NOT_ALLOWED")
    return str(interaction), normalized


def _find_snapshot_node(value: Any, accessible_id: str) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    if value.get("accessible_id") == accessible_id:
        return value
    children = value.get("children")
    if isinstance(children, list):
        for child in children:
            match = _find_snapshot_node(child, accessible_id)
            if match is not None:
                return match
    return None


def _observation_identity(observation: ComputerObservation) -> tuple[str, int]:
    observation.validate()
    if observation.surface != "desktop":
        raise LinuxInteractionError("LINUX_INTERACTION_REQUIRES_DESKTOP_OBSERVATION")
    structured = observation.structured_observation
    if not isinstance(structured, Mapping) or structured.get("platform") != "linux":
        raise LinuxInteractionError("LINUX_INTERACTION_REQUIRES_LINUX_OBSERVATION")
    if structured.get("backend") != "atspi2":
        raise LinuxInteractionError("LINUX_INTERACTION_REQUIRES_ATSPI2_OBSERVATION")
    target_id = structured.get("target_id")
    process_id = structured.get("process_id")
    if not isinstance(target_id, str) or not _ACCESSIBLE_ID_RE.fullmatch(target_id):
        raise LinuxInteractionError("INVALID_LINUX_OBSERVATION_TARGET_ID")
    if isinstance(process_id, bool) or not isinstance(process_id, int) or process_id <= 0:
        raise LinuxInteractionError("INVALID_LINUX_OBSERVATION_PROCESS_ID")
    expected = f"linux:atspi:{target_id}/process:{process_id}"
    if observation.active_target_ref != expected:
        raise LinuxInteractionError("LINUX_OBSERVATION_TARGET_IDENTITY_MISMATCH")
    return target_id, process_id


def _command_from_action(
    *,
    action: ComputerActionRequest,
    pre_observation: ComputerObservation,
) -> LinuxInteractionCommand:
    interaction, arguments = _normalize_action_arguments(action)
    target_id, process_id = _observation_identity(pre_observation)
    if action.resource_ref != f"local:desktop:window:{target_id}":
        raise LinuxInteractionError("LINUX_ACTION_WINDOW_RESOURCE_STALE")
    expected = _POSTCONDITION_BY_KIND[interaction]
    if action.expected_postcondition != expected:
        raise LinuxInteractionError("LINUX_EXPECTED_POSTCONDITION_MISMATCH")
    accessibility = pre_observation.structured_observation.get("accessibility")
    node = _find_snapshot_node(accessibility, str(arguments["accessible_id"]))
    if node is None:
        raise LinuxInteractionError("LINUX_ATSPI_TARGET_NOT_IN_PREOBSERVATION")
    if node.get("is_enabled") is False:
        raise LinuxInteractionError("LINUX_ATSPI_TARGET_DISABLED")
    if node.get("is_showing") is False or node.get("is_visible") is False:
        raise LinuxInteractionError("LINUX_ATSPI_TARGET_NOT_VISIBLE")
    expected_role = arguments.get("role")
    if expected_role is not None and node.get("role") != expected_role:
        raise LinuxInteractionError("LINUX_ATSPI_TARGET_ROLE_STALE")
    if interaction == "value" and node.get("is_secure") is True:
        raise LinuxInteractionError("LINUX_SECURE_INPUT_USER_TAKEOVER_REQUIRED")
    return LinuxInteractionCommand(
        session_id=action.session_id,
        task_id=action.task_id,
        operation=action.operation,
        interaction_kind=interaction,
        resource_ref=action.resource_ref,
        target_id=target_id,
        process_id=process_id,
        accessible_id=str(arguments["accessible_id"]),
        role=str(expected_role) if expected_role is not None else None,
        arguments=arguments,
        expected_postcondition=expected,
    )


def _require_inspection_matches(
    *,
    command: LinuxInteractionCommand,
    inspection: LinuxTargetInspection,
) -> None:
    if not isinstance(inspection, LinuxTargetInspection):
        raise LinuxInteractionError("INVALID_LINUX_TARGET_INSPECTION")
    if (
        inspection.target_id != command.target_id
        or inspection.process_id != command.process_id
        or inspection.accessible_id != command.accessible_id
    ):
        raise LinuxInteractionError("LINUX_ATSPI_TARGET_INSPECTION_STALE")
    if command.role is not None and inspection.role != command.role:
        raise LinuxInteractionError("LINUX_ATSPI_TARGET_INSPECTION_STALE")
    if command.interaction_kind == "value" and inspection.secure_input:
        raise LinuxInteractionError("LINUX_SECURE_INPUT_USER_TAKEOVER_REQUIRED")


def execute_governed_linux_action(
    *,
    action: ComputerActionRequest,
    pre_observation: ComputerObservation,
    capability_decision: Any,
    policy_decision: ComputerPolicyDecision,
    backend: LinuxInteractionBackend,
    replay_ledger: ComputerActionReplayLedger,
    approver_session_ref: str,
    now: str,
    approval: ComputerApprovalGrant | None,
    lease_repository: RuntimeWriterLeaseRepository | None,
    lease: RuntimeWriterLease | None,
    writer_binding: ComputerWriterBinding | None,
    user_takeover_active: bool,
) -> GovernedLinuxInteractionResult:
    """Execute one semantic Linux action under canonical WorkSpace governance."""

    if not isinstance(user_takeover_active, bool):
        raise LinuxInteractionError("INVALID_LINUX_USER_TAKEOVER_STATE")
    if user_takeover_active:
        raise LinuxInteractionError("LINUX_USER_TAKEOVER_ACTIVE")

    action.validate()
    pre_observation.validate()
    policy_decision.validate()
    require_target_fresh(action=action, observation=pre_observation)

    derived_policy = decide_computer_action(action, capability_decision)
    if derived_policy.fingerprint != policy_decision.fingerprint:
        raise LinuxInteractionError("LINUX_POLICY_DECISION_MISMATCH")
    if policy_decision.outcome == "DENY":
        raise LinuxInteractionError("LINUX_ACTION_POLICY_DENIED")
    if policy_decision.outcome != "REQUIRE_APPROVAL":
        raise LinuxInteractionError("LINUX_MUTATION_MUST_REQUIRE_APPROVAL")
    if not action.requires_writer:
        raise LinuxInteractionError("LINUX_MUTATION_MUST_REQUIRE_WRITER")

    command = _command_from_action(action=action, pre_observation=pre_observation)
    inspection = backend.inspect_target(command)
    _require_inspection_matches(command=command, inspection=inspection)

    if approval is None:
        raise LinuxInteractionError("LINUX_ACTION_APPROVAL_REQUIRED")
    require_valid_computer_approval(
        grant=approval,
        action=action,
        policy_decision=policy_decision,
        approver_session_ref=approver_session_ref,
        now=now,
    )
    if lease_repository is None or lease is None or writer_binding is None:
        raise LinuxInteractionError("LINUX_ACTION_WRITER_FENCE_REQUIRED")
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
        raise LinuxDispatchError(
            "LINUX_ATSPI_BACKEND_DISPATCH_FAILED",
            consumed_approval=consumed_approval,
        ) from exc
    if not isinstance(backend_result, LinuxInteractionBackendResult):
        raise LinuxDispatchError(
            "INVALID_LINUX_BACKEND_RESULT",
            consumed_approval=consumed_approval,
        )
    post = backend_result.post_observation
    post.validate()
    if post.task_id != action.task_id or post.session_id != action.session_id:
        raise LinuxDispatchError(
            "LINUX_POST_OBSERVATION_IDENTITY_MISMATCH",
            consumed_approval=consumed_approval,
        )
    if action.expected_postcondition not in backend_result.observed_postconditions:
        raise LinuxDispatchError(
            "LINUX_POSTCONDITION_NOT_SATISFIED",
            consumed_approval=consumed_approval,
        )
    return GovernedLinuxInteractionResult(
        backend_result=backend_result,
        consumed_approval=consumed_approval,
    )


def _walk_find(node: Any, accessible_id: str, remaining: list[int]) -> Any | None:
    if node is None or remaining[0] <= 0:
        return None
    remaining[0] -= 1
    if _accessible_identity(node) == accessible_id:
        return node
    try:
        child_count = max(0, int(node.get_child_count()))
    except Exception:
        return None
    for index in range(child_count):
        if remaining[0] <= 0:
            break
        try:
            child = node.get_child_at_index(index)
        except Exception:
            continue
        match = _walk_find(child, accessible_id, remaining)
        if match is not None:
            return match
    return None


class LinuxAtspiInteractionBackend:
    """Direct semantic AT-SPI2 mutation backend with no shell or elevation path."""

    def __init__(
        self,
        *,
        observation_backend: LinuxReadOnlyBackend | None = None,
        observation_config: LinuxObservationConfig | None = None,
    ) -> None:
        self._observation_backend = observation_backend or LinuxAtspiObservationBackend()
        self._observation_config = observation_config or LinuxObservationConfig(
            max_atspi_nodes=128,
            max_atspi_depth=6,
        )

    @staticmethod
    def _require_linux_host() -> None:
        if not sys.platform.startswith("linux"):
            raise LinuxInteractionError("LINUX_ATSPI_BACKEND_REQUIRES_LINUX")

    def _resolve(self, command: LinuxInteractionCommand) -> tuple[Any, Any, Any]:
        self._require_linux_host()
        atspi = _load_atspi()
        try:
            desktop = atspi.get_desktop(0)
        except Exception as exc:
            raise LinuxInteractionError("LINUX_ATSPI_DESKTOP_UNAVAILABLE") from exc
        if desktop is None:
            raise LinuxInteractionError("LINUX_ATSPI_DESKTOP_UNAVAILABLE")
        window = _find_active_window(atspi, desktop)
        target_id = _accessible_identity(window)
        try:
            process_id = int(window.get_process_id())
        except Exception as exc:
            raise LinuxInteractionError("LINUX_ATSPI_PROCESS_ID_UNAVAILABLE") from exc
        if target_id != command.target_id or process_id != command.process_id:
            raise LinuxInteractionError("LINUX_ATSPI_FOREGROUND_TARGET_STALE")
        element = _walk_find(window, command.accessible_id, [MAX_LINUX_RESOLVE_NODES])
        if element is None:
            raise LinuxInteractionError("LINUX_ATSPI_TARGET_NOT_FOUND")
        return atspi, window, element

    def inspect_target(self, command: LinuxInteractionCommand) -> LinuxTargetInspection:
        atspi, window, element = self._resolve(command)
        role = _safe_call_text(element, "get_role_name", limit=MAX_LINUX_SELECTOR_CHARS) or "unknown"
        secure = _is_secure_accessible(atspi, element, role)
        try:
            state_type = getattr(atspi.StateType, "FOCUSED", None)
            states = element.get_state_set()
            focused = bool(state_type is not None and states is not None and states.contains(state_type))
        except Exception:
            focused = False
        return LinuxTargetInspection(
            target_id=_accessible_identity(window),
            process_id=command.process_id,
            accessible_id=_accessible_identity(element),
            role=role,
            secure_input=secure,
            focused=focused,
        )

    @staticmethod
    def _invoke(element: Any) -> None:
        try:
            interface = element.get_action_iface()
        except Exception as exc:
            raise LinuxInteractionError("LINUX_ATSPI_ACTION_INTERFACE_UNAVAILABLE") from exc
        if interface is None:
            raise LinuxInteractionError("LINUX_ATSPI_ACTION_INTERFACE_UNAVAILABLE")
        try:
            count = max(0, int(interface.get_n_actions()))
        except Exception as exc:
            raise LinuxInteractionError("LINUX_ATSPI_ACTION_INTERFACE_UNAVAILABLE") from exc
        selected = None
        for index in range(count):
            try:
                name = str(interface.get_action_name(index) or "").strip().lower()
            except Exception:
                continue
            if name in _ALLOWED_ATSPI_ACTION_NAMES:
                selected = index
                break
        if selected is None:
            raise LinuxInteractionError("LINUX_ATSPI_REVIEWED_ACTION_NOT_AVAILABLE")
        try:
            succeeded = interface.do_action(selected)
        except Exception as exc:
            raise LinuxInteractionError("LINUX_ATSPI_ACTION_FAILED") from exc
        if succeeded is not True:
            raise LinuxInteractionError("LINUX_ATSPI_ACTION_FAILED")

    @staticmethod
    def _set_value(atspi: Any, element: Any, value: str) -> None:
        try:
            interface = element.get_editable_text_iface()
        except Exception as exc:
            raise LinuxInteractionError("LINUX_ATSPI_EDITABLE_TEXT_UNAVAILABLE") from exc
        if interface is None:
            raise LinuxInteractionError("LINUX_ATSPI_EDITABLE_TEXT_UNAVAILABLE")
        try:
            succeeded = interface.set_text_contents(value)
        except Exception as exc:
            raise LinuxInteractionError("LINUX_ATSPI_TEXT_SET_FAILED") from exc
        if succeeded is not True:
            raise LinuxInteractionError("LINUX_ATSPI_TEXT_SET_FAILED")

        try:
            text_interface = element.get_text_iface()
        except Exception as exc:
            raise LinuxInteractionError("LINUX_ATSPI_TEXT_POSTCONDITION_UNREADABLE") from exc
        if text_interface is not None:
            try:
                observed = atspi.Text.get_text(text_interface, 0, -1)
            except Exception as exc:
                raise LinuxInteractionError("LINUX_ATSPI_TEXT_POSTCONDITION_UNREADABLE") from exc
            if observed is None or str(observed) != value:
                raise LinuxInteractionError("LINUX_ATSPI_TEXT_POSTCONDITION_FAILED")

    def dispatch(self, command: LinuxInteractionCommand) -> LinuxInteractionBackendResult:
        atspi, _window, element = self._resolve(command)
        role = _safe_call_text(element, "get_role_name", limit=MAX_LINUX_SELECTOR_CHARS) or "unknown"
        if command.role is not None and role != command.role:
            raise LinuxInteractionError("LINUX_ATSPI_TARGET_ROLE_STALE")
        if command.interaction_kind == "value" and _is_secure_accessible(atspi, element, role):
            raise LinuxInteractionError("LINUX_SECURE_INPUT_USER_TAKEOVER_REQUIRED")
        if command.interaction_kind == "invoke":
            self._invoke(element)
        elif command.interaction_kind == "value":
            self._set_value(atspi, element, str(command.arguments["value"]))
        else:
            raise LinuxInteractionError("UNSUPPORTED_LINUX_ATSPI_INTERACTION")

        post_observation = capture_linux_observation(
            config=self._observation_config,
            backend=self._observation_backend,
            session_id=command.session_id,
            task_id=command.task_id,
        )
        postcondition = _POSTCONDITION_BY_KIND[command.interaction_kind]
        return LinuxInteractionBackendResult(
            post_observation=post_observation,
            observed_postconditions=(postcondition,),
            result={
                "operation": command.operation,
                "interaction_kind": command.interaction_kind,
                "target_id": command.target_id,
                "process_id": command.process_id,
                "accessible_id": command.accessible_id,
            },
        )
