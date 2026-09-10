import unittest

from three_agent.computer_use import ComputerActionRequest, ComputerObservation
from three_agent.computer_use_fake_executor import (
    ComputerFakeExecutorError,
    DeterministicComputerFakeExecutor,
    FakeExecutionScenario,
)

H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64
H3 = "sha256:" + "3" * 64


def observation(*, state=H1):
    return ComputerObservation(
        session_id="session:fake",
        task_id="task:fake",
        state_id="state:before",
        state_sha256=state,
        surface="browser",
        active_target_ref="browser:profile:isolated/tab:tab1",
        captured_at="2026-09-10T00:00:00Z",
        structured_observation={"title": "Fixture"},
        screenshot_sha256=H2,
    ).validate()


def action(*, state=H1, operation="browser.dom.observe", expected_postcondition=None):
    policies = {
        "browser.dom.observe": ("read", "R0_OBSERVE", False),
        "browser.interact": ("write", "R2_STATE_CHANGE", True),
    }
    effect, risk, writer = policies[operation]
    return ComputerActionRequest(
        session_id="session:fake",
        action_id="action:fake",
        task_id="task:fake",
        plan_fingerprint=H2,
        node_id="node:fake",
        operation=operation,
        effect=effect,
        resource_kind="browser_document",
        resource_ref="browser:profile:isolated/tab:tab1",
        arguments={},
        state_precondition_sha256=state,
        idempotency_key=H3,
        risk_class=risk,
        requires_writer=writer,
        expected_postcondition=expected_postcondition,
    ).validate()


class ComputerUseFakeExecutorTests(unittest.TestCase):
    def test_records_only_admitted_normalized_action(self):
        executor = DeterministicComputerFakeExecutor()
        item = action()
        record, post = executor.execute(
            action=item,
            observation=observation(),
            admission_outcome="ALLOW_AUTOMATIC",
        )
        self.assertEqual(record.action_fingerprint, item.fingerprint)
        self.assertEqual(executor.records, (record,))
        self.assertEqual(post.state_sha256, H1)

    def test_denied_action_is_not_recorded(self):
        executor = DeterministicComputerFakeExecutor()
        with self.assertRaisesRegex(ComputerFakeExecutorError, "FAKE_EXECUTOR_ACTION_NOT_ADMITTED"):
            executor.execute(
                action=action(),
                observation=observation(),
                admission_outcome="DENY",
            )
        self.assertEqual(executor.records, ())

    def test_stale_state_fails_closed(self):
        executor = DeterministicComputerFakeExecutor()
        with self.assertRaisesRegex(ComputerFakeExecutorError, "FAKE_EXECUTOR_STALE_STATE"):
            executor.execute(
                action=action(state=H1),
                observation=observation(state=H2),
                admission_outcome="ALLOW_AUTOMATIC",
            )
        self.assertEqual(executor.records, ())

    def test_state_change_requires_explicit_approval_signal(self):
        executor = DeterministicComputerFakeExecutor()
        item = action(operation="browser.interact")
        with self.assertRaisesRegex(ComputerFakeExecutorError, "FAKE_EXECUTOR_APPROVAL_REQUIRED"):
            executor.execute(
                action=item,
                observation=observation(),
                admission_outcome="REQUIRE_APPROVAL",
            )
        record, _ = executor.execute(
            action=item,
            observation=observation(),
            admission_outcome="REQUIRE_APPROVAL",
            approval_valid=True,
        )
        self.assertEqual(record.outcome, "SUCCEEDED")

    def test_failure_and_partial_result_are_deterministic(self):
        failed = DeterministicComputerFakeExecutor()
        failed_record, _ = failed.execute(
            action=action(),
            observation=observation(),
            admission_outcome="ALLOW_AUTOMATIC",
            scenario=FakeExecutionScenario(
                outcome="FAILED",
                error_class="FAKE_IO_ERROR",
            ),
        )
        self.assertEqual(failed_record.outcome, "FAILED")
        self.assertEqual(failed_record.error_class, "FAKE_IO_ERROR")

        partial = DeterministicComputerFakeExecutor()
        partial_record, partial_post = partial.execute(
            action=action(),
            observation=observation(),
            admission_outcome="ALLOW_AUTOMATIC",
            scenario=FakeExecutionScenario(
                outcome="PARTIAL",
                post_state_sha256=H3,
                post_observation={"partial": True},
            ),
        )
        self.assertEqual(partial_record.outcome, "PARTIAL")
        self.assertEqual(partial_post.state_sha256, H3)
        self.assertEqual(partial_post.structured_observation, {"partial": True})

    def test_postcondition_mismatch_is_explicit(self):
        executor = DeterministicComputerFakeExecutor()
        item = action(expected_postcondition="title becomes Ready")
        record, _ = executor.execute(
            action=item,
            observation=observation(),
            admission_outcome="ALLOW_AUTOMATIC",
            scenario=FakeExecutionScenario(outcome="POSTCONDITION_MISMATCH"),
        )
        self.assertEqual(record.outcome, "POSTCONDITION_MISMATCH")
        self.assertFalse(record.postcondition_satisfied)


if __name__ == "__main__":
    unittest.main()
