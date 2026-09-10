from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Any

from .computer_use import ComputerActionRequest, ComputerObservation


class ComputerFakeExecutorError(RuntimeError):
    """A deterministic fake-executor scenario is invalid or unsafe to execute."""


@dataclass(frozen=True)
class FakeExecutionScenario:
    outcome: str = "SUCCEEDED"
    post_state_sha256: str | None = None
    post_target_ref: str | None = None
    post_observation: Mapping[str, Any] | None = None
    error_class: str | None = None

    def validate(self) -> "FakeExecutionScenario":
        if self.outcome not in {"SUCCEEDED", "FAILED", "PARTIAL", "POSTCONDITION_MISMATCH"}:
            raise ComputerFakeExecutorError("UNKNOWN_FAKE_EXECUTION_OUTCOME")
        if self.outcome == "FAILED" and not self.error_class:
            raise ComputerFakeExecutorError("FAILED_FAKE_EXECUTION_REQUIRES_ERROR_CLASS")
        if self.outcome != "FAILED" and self.error_class is not None:
            raise ComputerFakeExecutorError("NON_FAILED_FAKE_EXECUTION_HAS_ERROR_CLASS")
        if self.post_observation is not None and not isinstance(self.post_observation, Mapping):
            raise ComputerFakeExecutorError("FAKE_POST_OBSERVATION_MUST_BE_OBJECT")
        return self


@dataclass(frozen=True)
class FakeExecutionRecord:
    action_fingerprint: str
    action_id: str
    task_id: str
    session_id: str
    operation: str
    pre_state_sha256: str
    post_state_sha256: str
    outcome: str
    postcondition_satisfied: bool | None
    error_class: str | None


class DeterministicComputerFakeExecutor:
    """Non-OS executor for deterministic Computer Use CI scenarios.

    It never authorizes an action. Callers must pass an already admitted action and
    the exact fresh observation it was based on. The executor records only actions
    whose admission outcome is ALLOW_AUTOMATIC or REQUIRE_APPROVAL with an explicit
    approval_valid flag supplied by the caller.
    """

    def __init__(self) -> None:
        self._records: list[FakeExecutionRecord] = []

    @property
    def records(self) -> tuple[FakeExecutionRecord, ...]:
        return tuple(self._records)

    def execute(
        self,
        *,
        action: ComputerActionRequest,
        observation: ComputerObservation,
        admission_outcome: str,
        approval_valid: bool = False,
        scenario: FakeExecutionScenario | None = None,
    ) -> tuple[FakeExecutionRecord, ComputerObservation]:
        action.validate()
        observation.validate()
        scenario = (scenario or FakeExecutionScenario()).validate()

        if action.task_id != observation.task_id or action.session_id != observation.session_id:
            raise ComputerFakeExecutorError("FAKE_EXECUTOR_ACTION_OBSERVATION_SCOPE_MISMATCH")
        if action.state_precondition_sha256 != observation.state_sha256:
            raise ComputerFakeExecutorError("FAKE_EXECUTOR_STALE_STATE")
        if admission_outcome == "DENY":
            raise ComputerFakeExecutorError("FAKE_EXECUTOR_ACTION_NOT_ADMITTED")
        if admission_outcome == "REQUIRE_APPROVAL" and approval_valid is not True:
            raise ComputerFakeExecutorError("FAKE_EXECUTOR_APPROVAL_REQUIRED")
        if admission_outcome not in {"ALLOW_AUTOMATIC", "REQUIRE_APPROVAL"}:
            raise ComputerFakeExecutorError("UNKNOWN_FAKE_ADMISSION_OUTCOME")

        post_state = scenario.post_state_sha256 or observation.state_sha256
        post_target = scenario.post_target_ref or observation.active_target_ref
        structured = dict(scenario.post_observation or observation.structured_observation)
        post = ComputerObservation(
            session_id=observation.session_id,
            task_id=observation.task_id,
            state_id=f"state:fake:{len(self._records) + 1}",
            state_sha256=post_state,
            surface=observation.surface,
            active_target_ref=post_target,
            captured_at=observation.captured_at,
            structured_observation=structured,
            screenshot_sha256=observation.screenshot_sha256,
        ).validate()

        postcondition_satisfied: bool | None = None
        if action.expected_postcondition is not None:
            postcondition_satisfied = scenario.outcome != "POSTCONDITION_MISMATCH"

        record = FakeExecutionRecord(
            action_fingerprint=action.fingerprint,
            action_id=action.action_id,
            task_id=action.task_id,
            session_id=action.session_id,
            operation=action.operation,
            pre_state_sha256=observation.state_sha256,
            post_state_sha256=post.state_sha256,
            outcome=scenario.outcome,
            postcondition_satisfied=postcondition_satisfied,
            error_class=scenario.error_class,
        )
        self._records.append(record)
        return record, post
