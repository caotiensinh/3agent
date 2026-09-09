from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from three_agent.computer_use import ComputerActionRequest
from three_agent.computer_use_writer import (
    ComputerWriterError,
    bind_current_writer,
    decide_uncertain_side_effect_retry,
    require_current_writer_binding,
)
from three_agent.runtime_writer_lease import RuntimeWriterLeaseError, RuntimeWriterLeaseRepository
from three_agent.store import TaskStore


def _sha(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


class ComputerUseWriterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "workspace.sqlite3"
        self.store = TaskStore(self.db)
        self.store.initialize()
        self.task = self.store.create_task("computer writer", "fence mutating computer actions")
        self.plan = _sha("computer-plan")
        self.repo = RuntimeWriterLeaseRepository(self.store)
        self.repo.initialize()

    def tearDown(self):
        self.tmp.cleanup()

    def _action(
        self,
        *,
        action_id: str = "action:1",
        state: str | None = None,
        expected_postcondition: str | None = "dialog closed",
        operation: str = "browser.interact",
    ) -> ComputerActionRequest:
        if operation == "browser.interact":
            effect = "write"
            risk = "R2_STATE_CHANGE"
            writer = True
            kind = "browser_document"
            ref = "browser:profile:isolated/tab:tab1"
        elif operation == "computer.screen.observe":
            effect = "read"
            risk = "R0_OBSERVE"
            writer = False
            kind = "screen"
            ref = "local:desktop:screen:primary"
        else:
            raise AssertionError(operation)
        return ComputerActionRequest(
            session_id="session:1",
            action_id=action_id,
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            node_id="node:1",
            operation=operation,
            effect=effect,
            resource_kind=kind,
            resource_ref=ref,
            arguments={},
            state_precondition_sha256=state or _sha("state:1"),
            idempotency_key=_sha("idem:" + action_id),
            risk_class=risk,
            requires_writer=writer,
            expected_postcondition=expected_postcondition,
        ).validate()

    def _lease(self, run_id: str = "RUN-A", issued_at: str = "2026-09-10T00:00:00Z"):
        return self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id=run_id,
            issued_at=issued_at,
        )

    def test_mutating_action_binds_to_exact_current_writer_generation(self):
        action = self._action()
        lease = self._lease()
        binding = bind_current_writer(
            action=action,
            lease_repository=self.repo,
            lease=lease,
        )
        self.assertEqual(binding.action_fingerprint, action.fingerprint)
        self.assertEqual(binding.lease_fingerprint, lease.fingerprint)
        self.assertEqual(binding.generation, 1)
        self.assertEqual(
            require_current_writer_binding(
                action=action,
                binding=binding,
                lease_repository=self.repo,
                lease=lease,
            ),
            lease,
        )

    def test_read_only_action_cannot_claim_writer_binding(self):
        action = self._action(operation="computer.screen.observe", expected_postcondition=None)
        lease = self._lease()
        with self.assertRaisesRegex(ComputerWriterError, "COMPUTER_ACTION_DOES_NOT_REQUIRE_WRITER"):
            bind_current_writer(
                action=action,
                lease_repository=self.repo,
                lease=lease,
            )

    def test_takeover_invalidates_previously_bound_action(self):
        action = self._action()
        first = self._lease("RUN-A", "2026-09-10T00:00:00Z")
        binding = bind_current_writer(
            action=action,
            lease_repository=self.repo,
            lease=first,
        )
        second = self._lease("RUN-B", "2026-09-10T00:01:00Z")
        self.assertEqual(second.generation, 2)
        with self.assertRaisesRegex(RuntimeWriterLeaseError, "WRITER_LEASE_STALE"):
            require_current_writer_binding(
                action=action,
                binding=binding,
                lease_repository=self.repo,
                lease=first,
            )

    def test_binding_for_action_a_cannot_authorize_action_b(self):
        first_action = self._action(action_id="action:1")
        second_action = self._action(action_id="action:2")
        lease = self._lease()
        binding = bind_current_writer(
            action=first_action,
            lease_repository=self.repo,
            lease=lease,
        )
        with self.assertRaisesRegex(ComputerWriterError, "COMPUTER_WRITER_BINDING_ACTION_STALE"):
            require_current_writer_binding(
                action=second_action,
                binding=binding,
                lease_repository=self.repo,
                lease=lease,
            )

    def test_uncertain_retry_is_suppressed_when_postcondition_is_already_satisfied(self):
        action = self._action()
        lease = self._lease()
        binding = bind_current_writer(
            action=action,
            lease_repository=self.repo,
            lease=lease,
        )
        decision = decide_uncertain_side_effect_retry(
            action=action,
            binding=binding,
            lease_repository=self.repo,
            lease=lease,
            postcondition_status="SATISFIED",
            idempotency_status="NOT_SEEN",
        )
        self.assertEqual(decision.outcome, "NO_RETRY")
        self.assertEqual(decision.reason_code, "POSTCONDITION_ALREADY_SATISFIED")

    def test_uncertain_retry_is_suppressed_when_idempotency_key_was_seen(self):
        action = self._action()
        lease = self._lease()
        binding = bind_current_writer(
            action=action,
            lease_repository=self.repo,
            lease=lease,
        )
        decision = decide_uncertain_side_effect_retry(
            action=action,
            binding=binding,
            lease_repository=self.repo,
            lease=lease,
            postcondition_status="UNSATISFIED",
            idempotency_status="SEEN",
        )
        self.assertEqual(decision.outcome, "NO_RETRY")
        self.assertEqual(decision.reason_code, "IDEMPOTENCY_KEY_ALREADY_OBSERVED")

    def test_retry_requires_known_unsatisfied_postcondition_and_unseen_idempotency(self):
        action = self._action()
        lease = self._lease()
        binding = bind_current_writer(
            action=action,
            lease_repository=self.repo,
            lease=lease,
        )
        decision = decide_uncertain_side_effect_retry(
            action=action,
            binding=binding,
            lease_repository=self.repo,
            lease=lease,
            postcondition_status="UNSATISFIED",
            idempotency_status="NOT_SEEN",
        )
        self.assertEqual(decision.outcome, "RETRY_ALLOWED")
        self.assertEqual(
            decision.reason_code,
            "POSTCONDITION_UNSATISFIED_AND_IDEMPOTENCY_NOT_SEEN",
        )

    def test_unknown_retry_evidence_fails_closed(self):
        action = self._action()
        lease = self._lease()
        binding = bind_current_writer(
            action=action,
            lease_repository=self.repo,
            lease=lease,
        )
        decision = decide_uncertain_side_effect_retry(
            action=action,
            binding=binding,
            lease_repository=self.repo,
            lease=lease,
            postcondition_status="UNKNOWN",
            idempotency_status="UNKNOWN",
        )
        self.assertEqual(decision.outcome, "DENY_RETRY")
        self.assertEqual(decision.reason_code, "RETRY_EVIDENCE_UNCERTAIN")

    def test_retry_without_declared_postcondition_fails_closed(self):
        action = self._action(expected_postcondition=None)
        lease = self._lease()
        binding = bind_current_writer(
            action=action,
            lease_repository=self.repo,
            lease=lease,
        )
        decision = decide_uncertain_side_effect_retry(
            action=action,
            binding=binding,
            lease_repository=self.repo,
            lease=lease,
            postcondition_status="UNSATISFIED",
            idempotency_status="NOT_SEEN",
        )
        self.assertEqual(decision.outcome, "DENY_RETRY")
        self.assertEqual(decision.reason_code, "RETRY_POSTCONDITION_NOT_DECLARED")


if __name__ == "__main__":
    unittest.main()
