from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol
from urllib.parse import urlparse

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

BROWSER_INTERACTION_KINDS = frozenset(
    {"click", "type", "select", "scroll", "form_submit", "download_request"}
)
MAX_SELECTOR_CHARS = 512
MAX_TYPED_TEXT_CHARS = 4096
MAX_SELECT_VALUE_CHARS = 1024
MAX_SCROLL_DELTA = 10_000


class BrowserInteractionError(RuntimeError):
    """Governed browser interaction failed admission, dispatch, or verification."""


class BrowserDispatchError(BrowserInteractionError):
    """Backend dispatch failed after approval/replay consumption may have occurred."""

    def __init__(self, reason_code: str, *, consumed_approval: ComputerApprovalGrant | None) -> None:
        self.reason_code = reason_code
        self.consumed_approval = consumed_approval
        super().__init__(reason_code)


@dataclass(frozen=True)
class BrowserInteractionCommand:
    operation: str
    interaction_kind: str | None
    resource_ref: str
    arguments: Mapping[str, Any]
    navigation_url: str | None = None
    download_quarantine_ref: str | None = None


@dataclass(frozen=True)
class BrowserInteractionBackendResult:
    post_observation: ComputerObservation
    observed_postconditions: tuple[str, ...] = ()
    result: Mapping[str, Any] | None = None
    download_quarantine_ref: str | None = None


@dataclass(frozen=True)
class GovernedBrowserInteractionResult:
    backend_result: BrowserInteractionBackendResult
    consumed_approval: ComputerApprovalGrant | None


class BrowserInteractionBackend(Protocol):
    """Constrained backend surface; no arbitrary CDP or shell command passthrough."""

    def dispatch(self, command: BrowserInteractionCommand) -> BrowserInteractionBackendResult:
        ...


def _bounded_text(value: Any, *, field: str, limit: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or value != value.strip() or (not value and not allow_empty):
        raise BrowserInteractionError(f"INVALID_BROWSER_{field.upper()}")
    if len(value) > limit or "\x00" in value:
        raise BrowserInteractionError(f"INVALID_BROWSER_{field.upper()}")
    return value


def _strict_arguments(arguments: Mapping[str, Any], allowed: frozenset[str]) -> dict[str, Any]:
    keys = set(arguments)
    if keys - allowed:
        raise BrowserInteractionError("BROWSER_INTERACTION_ARGUMENT_NOT_ALLOWED")
    return dict(arguments)


def _normalized_https_url(value: Any, *, allowed_hosts: tuple[str, ...]) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise BrowserInteractionError("BROWSER_NAVIGATION_URL_REQUIRED")
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise BrowserInteractionError("BROWSER_NAVIGATION_HTTPS_REQUIRED")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise BrowserInteractionError("BROWSER_NAVIGATION_URL_UNSAFE")
    host = parsed.hostname.lower().rstrip(".")
    normalized_hosts = tuple(item.lower().rstrip(".") for item in allowed_hosts)
    if host not in normalized_hosts:
        raise BrowserInteractionError("BROWSER_NAVIGATION_HOST_NOT_ALLOWLISTED")
    return value


def _interaction_arguments(arguments: Mapping[str, Any], kind: str) -> dict[str, Any]:
    if kind == "click":
        result = _strict_arguments(arguments, frozenset({"interaction", "selector"}))
        result["selector"] = _bounded_text(result.get("selector"), field="selector", limit=MAX_SELECTOR_CHARS)
        return result
    if kind == "type":
        result = _strict_arguments(arguments, frozenset({"interaction", "selector", "text"}))
        result["selector"] = _bounded_text(result.get("selector"), field="selector", limit=MAX_SELECTOR_CHARS)
        result["text"] = _bounded_text(result.get("text"), field="typed_text", limit=MAX_TYPED_TEXT_CHARS, allow_empty=True)
        return result
    if kind == "select":
        result = _strict_arguments(arguments, frozenset({"interaction", "selector", "value"}))
        result["selector"] = _bounded_text(result.get("selector"), field="selector", limit=MAX_SELECTOR_CHARS)
        result["value"] = _bounded_text(result.get("value"), field="select_value", limit=MAX_SELECT_VALUE_CHARS)
        return result
    if kind == "scroll":
        result = _strict_arguments(arguments, frozenset({"interaction", "delta_y"}))
        delta = result.get("delta_y")
        if isinstance(delta, bool) or not isinstance(delta, int) or not -MAX_SCROLL_DELTA <= delta <= MAX_SCROLL_DELTA:
            raise BrowserInteractionError("INVALID_BROWSER_SCROLL_DELTA")
        return result
    if kind == "form_submit":
        result = _strict_arguments(arguments, frozenset({"interaction", "selector"}))
        result["selector"] = _bounded_text(result.get("selector"), field="selector", limit=MAX_SELECTOR_CHARS)
        return result
    if kind == "download_request":
        result = _strict_arguments(arguments, frozenset({"interaction", "selector"}))
        result["selector"] = _bounded_text(result.get("selector"), field="selector", limit=MAX_SELECTOR_CHARS)
        return result
    raise BrowserInteractionError("UNSUPPORTED_BROWSER_INTERACTION_KIND")


def _command_from_action(
    action: ComputerActionRequest,
    *,
    allowed_navigation_hosts: tuple[str, ...],
    download_quarantine_ref: str | None,
) -> BrowserInteractionCommand:
    arguments = dict(action.arguments)
    if action.operation == "browser.navigate":
        arguments = _strict_arguments(arguments, frozenset({"url"}))
        target = _normalized_https_url(arguments.get("url"), allowed_hosts=allowed_navigation_hosts)
        return BrowserInteractionCommand(
            operation=action.operation,
            interaction_kind=None,
            resource_ref=action.resource_ref,
            arguments={"url": target},
            navigation_url=target,
        )
    if action.operation != "browser.interact":
        raise BrowserInteractionError("UNSUPPORTED_GOVERNED_BROWSER_OPERATION")
    kind = arguments.get("interaction")
    if kind not in BROWSER_INTERACTION_KINDS:
        raise BrowserInteractionError("UNSUPPORTED_BROWSER_INTERACTION_KIND")
    normalized = _interaction_arguments(arguments, kind)
    if kind == "download_request" and (not isinstance(download_quarantine_ref, str) or not download_quarantine_ref):
        raise BrowserInteractionError("DOWNLOAD_QUARANTINE_REQUIRED")
    return BrowserInteractionCommand(
        operation=action.operation,
        interaction_kind=kind,
        resource_ref=action.resource_ref,
        arguments=normalized,
        download_quarantine_ref=(download_quarantine_ref if kind == "download_request" else None),
    )


def execute_governed_browser_action(
    *,
    action: ComputerActionRequest,
    pre_observation: ComputerObservation,
    capability_decision: Any,
    policy_decision: ComputerPolicyDecision,
    backend: BrowserInteractionBackend,
    replay_ledger: ComputerActionReplayLedger,
    approver_session_ref: str,
    now: str,
    approval: ComputerApprovalGrant | None = None,
    lease_repository: RuntimeWriterLeaseRepository | None = None,
    lease: RuntimeWriterLease | None = None,
    writer_binding: ComputerWriterBinding | None = None,
    allowed_navigation_hosts: tuple[str, ...] = (),
    download_quarantine_ref: str | None = None,
) -> GovernedBrowserInteractionResult:
    """Dispatch one bounded browser action after existing WorkSpace governance passes.

    Freshness/policy/command validation happens first. Approval and writer validity
    are checked without consuming anything; replay is then fenced; approval is
    consumed before a possible side effect; the writer generation is rechecked
    immediately before mutating dispatch; and the declared postcondition must be
    verified afterwards. Ambiguous dispatch exposes the consumed approval so it
    cannot be reused.
    """

    action.validate()
    pre_observation.validate()
    policy_decision.validate()
    require_target_fresh(action=action, observation=pre_observation)

    derived_policy = decide_computer_action(action, capability_decision)
    if derived_policy.fingerprint != policy_decision.fingerprint:
        raise BrowserInteractionError("BROWSER_POLICY_DECISION_MISMATCH")
    if policy_decision.outcome == "DENY":
        raise BrowserInteractionError("BROWSER_ACTION_POLICY_DENIED")
    if action.expected_postcondition is None:
        raise BrowserInteractionError("BROWSER_EXPECTED_POSTCONDITION_REQUIRED")

    command = _command_from_action(
        action,
        allowed_navigation_hosts=allowed_navigation_hosts,
        download_quarantine_ref=download_quarantine_ref,
    )

    if policy_decision.outcome == "REQUIRE_APPROVAL":
        if approval is None:
            raise BrowserInteractionError("BROWSER_ACTION_APPROVAL_REQUIRED")
        require_valid_computer_approval(
            grant=approval,
            action=action,
            policy_decision=policy_decision,
            approver_session_ref=approver_session_ref,
            now=now,
        )
    elif approval is not None:
        raise BrowserInteractionError("UNEXPECTED_BROWSER_ACTION_APPROVAL")

    if action.requires_writer:
        if lease_repository is None or lease is None or writer_binding is None:
            raise BrowserInteractionError("BROWSER_ACTION_WRITER_FENCE_REQUIRED")
        require_current_writer_binding(
            action=action,
            binding=writer_binding,
            lease_repository=lease_repository,
            lease=lease,
        )
    elif lease is not None or writer_binding is not None:
        raise BrowserInteractionError("UNEXPECTED_BROWSER_WRITER_BINDING")

    replay_ledger.admit_once(action=action, observation=pre_observation)

    consumed_approval: ComputerApprovalGrant | None = None
    if policy_decision.outcome == "REQUIRE_APPROVAL":
        consumed_approval = consume_computer_approval(
            grant=approval,
            action=action,
            policy_decision=policy_decision,
            approver_session_ref=approver_session_ref,
            now=now,
        )

    if action.requires_writer:
        require_current_writer_binding(
            action=action,
            binding=writer_binding,
            lease_repository=lease_repository,
            lease=lease,
        )

    try:
        backend_result = backend.dispatch(command)
    except Exception as exc:
        raise BrowserDispatchError("BROWSER_BACKEND_DISPATCH_FAILED", consumed_approval=consumed_approval) from exc
    if not isinstance(backend_result, BrowserInteractionBackendResult):
        raise BrowserDispatchError("INVALID_BROWSER_BACKEND_RESULT", consumed_approval=consumed_approval)

    post = backend_result.post_observation
    post.validate()
    if post.task_id != action.task_id or post.session_id != action.session_id:
        raise BrowserDispatchError("BROWSER_POST_OBSERVATION_IDENTITY_MISMATCH", consumed_approval=consumed_approval)
    if action.expected_postcondition not in backend_result.observed_postconditions:
        raise BrowserDispatchError("BROWSER_POSTCONDITION_NOT_SATISFIED", consumed_approval=consumed_approval)
    if command.interaction_kind == "download_request" and backend_result.download_quarantine_ref != command.download_quarantine_ref:
        raise BrowserDispatchError("DOWNLOAD_NOT_QUARANTINED", consumed_approval=consumed_approval)

    return GovernedBrowserInteractionResult(
        backend_result=backend_result,
        consumed_approval=consumed_approval,
    )
