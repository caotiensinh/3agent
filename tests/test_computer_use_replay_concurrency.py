import hashlib
import tempfile
import unittest
from pathlib import Path

from three_agent.computer_use import ComputerActionRequest, ComputerObservation
from three_agent.computer_use_replay import (
    ComputerActionReplayLedger,
    ComputerReplayError,
    require_target_fresh,
)
from three_agent.runtime_writer_lease import RuntimeWriterLeaseError, RuntimeWriterLeaseRepository
from three_agent.store import TaskStore

H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64
H3 = "sha256:" + "3" * 64


def action(*, action_id="action:1", state=H1, resource_ref="browser:profile:isolated/tab:tab1"):
    return ComputerActionRequest(
        session_id="session:replay",
        action_id=action_id,
        task_id="task:replay",
        plan_fingerprint=H2,
        node_id="node:replay",
        operation="browser.interact",
        effect="write",
        resource_kind="browser_document",
        resource_ref=resource_ref,
        arguments={},
        state_precondition_sha256=state,
        idempotency_key=H3,
        risk_class="R2_STATE_CHANGE",
        requires_writer=True,
    ).validate()


def observation(*, state=H1, target="browser:profile:isolated/tab:tab1"):
    return ComputerObservation(
        session_id="session:replay",
        task_id="task:replay",
        state_id="state:replay",
        state_sha256=state,
        surface="browser",
        active_target_ref=target,
        captured_at="2026-09-10T00:00:00Z",
        structured_observation={"target": target},
    ).validate()


class ComputerUseReplayConcurrencyTests(unittest.TestCase):
    def test_replayed_action_id_is_rejected(self):
        ledger = ComputerActionReplayLedger()
        item = action()
        receipt = ledger.admit_once(action=item, observation=observation())
        self.assertEqual(receipt.action_fingerprint, item.fingerprint)
        with self.assertRaisesRegex(ComputerReplayError, "COMPUTER_ACTION_ID_REPLAYED"):
            ledger.admit_once(action=item, observation=observation())

    def test_same_action_id_with_changed_payload_is_still_replay(self):
        ledger = ComputerActionReplayLedger()
        ledger.admit_once(action=action(), observation=observation())
        changed = ComputerActionRequest(
            session_id="session:replay",
            action_id="action:1",
            task_id="task:replay",
            plan_fingerprint=H2,
            node_id="node:replay",
            operation="browser.interact",
            effect="write",
            resource_kind="browser_document",
            resource_ref="browser:profile:isolated/tab:tab1",
            arguments={"selector": "#other"},
            state_precondition_sha256=H1,
            idempotency_key=H3,
            risk_class="R2_STATE_CHANGE",
            requires_writer=True,
        ).validate()
        with self.assertRaisesRegex(ComputerReplayError, "COMPUTER_ACTION_ID_REPLAYED"):
            ledger.admit_once(action=changed, observation=observation())

    def test_old_dom_ref_is_rejected_after_navigation(self):
        item = action(resource_ref="browser:profile:isolated/tab:tab1")
        after_navigation = observation(target="browser:profile:isolated/tab:tab2")
        with self.assertRaisesRegex(ComputerReplayError, "COMPUTER_ACTION_TARGET_REF_STALE"):
            require_target_fresh(action=item, observation=after_navigation)

    def test_coordinate_style_action_is_rejected_after_state_hash_change(self):
        item = action(state=H1)
        changed = observation(state=H2)
        with self.assertRaisesRegex(ComputerReplayError, "COMPUTER_ACTION_OBSERVATION_STALE"):
            require_target_fresh(action=item, observation=changed)

    def test_previous_writer_generation_is_rejected_and_only_new_writer_remains_current(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStore(Path(tmp) / "workspace.sqlite3")
            store.initialize()
            task = store.create_task("replay concurrency", "fence concurrent writers")
            plan = "sha256:" + hashlib.sha256(b"plan").hexdigest()
            repo = RuntimeWriterLeaseRepository(store)
            repo.initialize()
            first = repo.claim(
                task_id=task.task_id,
                plan_fingerprint=plan,
                run_id="RUN-A",
                issued_at="2026-09-10T00:00:00Z",
            )
            second = repo.claim(
                task_id=task.task_id,
                plan_fingerprint=plan,
                run_id="RUN-B",
                issued_at="2026-09-10T00:00:01Z",
            )
            with self.assertRaisesRegex(RuntimeWriterLeaseError, "WRITER_LEASE_STALE"):
                repo.require_current(first)
            self.assertEqual(repo.require_current(second), second)


if __name__ == "__main__":
    unittest.main()
