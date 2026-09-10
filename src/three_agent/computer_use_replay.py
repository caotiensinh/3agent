from __future__ import annotations

from dataclasses import dataclass

from .computer_use import (
    ComputerActionRequest,
    ComputerObservation,
    ComputerUseError,
    require_fresh_observation,
)


class ComputerReplayError(RuntimeError):
    """A computer-use action is replayed or no longer bound to the observed target."""


@dataclass(frozen=True)
class ComputerActionReplayReceipt:
    task_id: str
    session_id: str
    action_id: str
    action_fingerprint: str
    state_precondition_sha256: str


class ComputerActionReplayLedger:
    """Process-local deterministic replay fence for one runtime session.

    This is not an authorization source. It records action identities only after
    existing action/observation validation succeeds. Durable runtimes may back the
    same semantics with their canonical store before release.
    """

    def __init__(self) -> None:
        self._seen: dict[tuple[str, str, str], ComputerActionReplayReceipt] = {}

    def admit_once(
        self,
        *,
        action: ComputerActionRequest,
        observation: ComputerObservation,
    ) -> ComputerActionReplayReceipt:
        require_target_fresh(action=action, observation=observation)
        key = (action.task_id, action.session_id, action.action_id)
        if key in self._seen:
            raise ComputerReplayError("COMPUTER_ACTION_ID_REPLAYED")
        receipt = ComputerActionReplayReceipt(
            task_id=action.task_id,
            session_id=action.session_id,
            action_id=action.action_id,
            action_fingerprint=action.fingerprint,
            state_precondition_sha256=action.state_precondition_sha256,
        )
        self._seen[key] = receipt
        return receipt

    @property
    def receipts(self) -> tuple[ComputerActionReplayReceipt, ...]:
        return tuple(self._seen.values())


def require_target_fresh(
    *,
    action: ComputerActionRequest,
    observation: ComputerObservation,
) -> None:
    """Reject stale state and stale target references before UI dispatch."""

    try:
        require_fresh_observation(action, observation)
    except ComputerUseError as exc:
        raise ComputerReplayError("COMPUTER_ACTION_OBSERVATION_STALE") from exc

    target_bound_kinds = {
        "browser_document",
        "window",
        "accessibility_tree",
    }
    if action.resource_kind in target_bound_kinds and action.resource_ref != observation.active_target_ref:
        raise ComputerReplayError("COMPUTER_ACTION_TARGET_REF_STALE")
