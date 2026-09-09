from __future__ import annotations

import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.execution_budget import TaskExecutionBudgetState
from three_agent.execution_checkpoint_writer_fence import (
    WriterFencedExecutionCheckpointRepository,
)
from three_agent.execution_dispatch_budget import (
    AtomicBudgetWriterFencedExecutionCheckpointRepository,
    ExecutionDispatchBudgetError,
)
from three_agent.execution_observation import ExecutionObservationBuilder
from three_agent.execution_plan import ExecutionPlanBuilder
from three_agent.execution_runtime_composition import compose_writer_fenced_execution_runtime
from three_agent.execution_scheduler import ExecutionScheduler, ExecutionSchedulerError
from three_agent.harness_acceptance import AcceptanceContract, AcceptanceCriterion
from three_agent.harness_task_compiler import HarnessTaskCompiler
from three_agent.runtime_writer_lease import RuntimeWriterLeaseRepository
from three_agent.store import TaskStore
from three_agent.task_context import TaskContextBuilder
from three_agent.task_contract import TaskContractCompiler


class NoopBudgetGuard:
    def assert_active(self):
        return None

    def reserve(self, *, steps=0, tool_calls=0, retries=0, escalations=0):
        return None


class FakeRevocationGuard:
    def is_revoked(self, task_id, capability):
        return False


def one_node_workflow():
    return {
        "title": "Atomic dispatch budget",
        "objective": "Commit one dispatch budget step with its durable checkpoint.",
        "trigger": "manual",
        "risk_level": "low",
        "data_class": "internal",
        "nodes": [
            {
                "id": "start",
                "label": "Start",
                "kind": "input",
                "action": "input",
                "depends_on": [],
                "condition": "",
                "approval_required": False,
            }
        ],
        "outputs": ["Atomic receipt"],
        "warnings": [],
    }


class ExecutionDispatchBudgetTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.store = TaskStore(self.root / "workspace.sqlite3")
        self.store.initialize()
        self.task = self.store.create_task(
            "atomic dispatch budget",
            "PRIVATE_DISPATCH_REQUEST_MARKER",
        )
        self.contract = TaskContractCompiler().compile(
            task_id=self.task.task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
            write_scope="none",
        )
        self.store.bind_task_contract(self.task.task_id, self.contract.to_dict())
        self.budget = TaskExecutionBudgetState.from_bound_contract(
            self.store,
            self.task.task_id,
        )
        acceptance = AcceptanceContract(
            task_id=self.task.task_id,
            criteria=(
                AcceptanceCriterion(
                    criterion_id="atomic-dispatch-budget",
                    statement="Budget and dispatch checkpoint commit atomically",
                    verifier="unit_test",
                ),
            ),
        )
        canonical = HarnessTaskCompiler().compile(
            user_prompt="Prove atomic dispatch budget persistence.",
            task_contract=self.contract,
            acceptance_contract=acceptance,
        )
        self.context = TaskContextBuilder.build(
            task_contract=self.contract,
            canonical_task=canonical,
            session_id="SESSION-DISPATCH-BUDGET-1",
            trace_id="TRACE-DISPATCH-BUDGET-1",
            actor_id="ACTOR-DISPATCH-BUDGET-1",
            purpose="atomic dispatch budget regression",
            project_id="PROJECT-DISPATCH-BUDGET-1",
            created_at=datetime(2026, 9, 10, 2, 0, tzinfo=timezone.utc),
        )
        self.authority = TaskCapabilityAuthority.from_contract(self.contract)
        self.plan = ExecutionPlanBuilder.build(
            task_context=self.context,
            parent_authority=self.authority,
            workflow_contract=one_node_workflow(),
            node_bindings={},
        )
        self.revocations = FakeRevocationGuard()

    def tearDown(self):
        self.tempdir.cleanup()

    def _compose(self, run_id="RUN-DISPATCH-BUDGET-A"):
        return compose_writer_fenced_execution_runtime(
            task_store=self.store,
            run_id=run_id,
            task_context=self.context,
            plan=self.plan,
            parent_authority=self.authority,
            budget_guard=self.budget,
            revocation_guard=self.revocations,
            max_concurrency=1,
        )

    def _observation(self):
        return ExecutionObservationBuilder.build(
            plan=self.plan,
            node_id="start",
            parent_authority=self.authority,
            status="SUCCEEDED",
            started_at="2026-09-10T02:01:00Z",
            finished_at="2026-09-10T02:01:01Z",
            normalized_output={"status": "SUCCEEDED"},
        )

    def _counts(self):
        with self.store.connect() as conn:
            dispatches = conn.execute(
                "SELECT COUNT(*) AS n FROM execution_dispatch_checkpoints"
            ).fetchone()["n"]
            reservations = conn.execute(
                "SELECT COUNT(*) AS n FROM execution_dispatch_budget_reservations"
            ).fetchone()["n"]
        return int(dispatches), int(reservations)

    def test_successful_dispatch_commits_one_step_checkpoint_and_reservation(self):
        runtime = self._compose()
        before = int(self.budget.snapshot()["steps_used"])

        ticket = runtime.scheduler.issue_dispatch("start")

        self.assertEqual(int(self.budget.snapshot()["steps_used"]), before + 1)
        self.assertEqual(self._counts(), (1, 1))
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT reservation_json FROM execution_dispatch_budget_reservations"
            ).fetchone()
        self.assertIn(ticket.node_fingerprint, str(row["reservation_json"]))
        self.assertNotIn("PRIVATE_DISPATCH_REQUEST_MARKER", str(row["reservation_json"]))

    def test_failure_after_budget_update_rolls_back_all_dispatch_state_then_retry_charges_once(self):
        runtime = self._compose()
        before = int(self.budget.snapshot()["steps_used"])
        repository = runtime.checkpoint_repository
        original_append_event = repository._append_event

        def fail_after_budget_reservation(*args, **kwargs):
            raise RuntimeError("SIMULATED_CHECKPOINT_FAILURE")

        repository._append_event = fail_after_budget_reservation
        with self.assertRaisesRegex(
            ExecutionSchedulerError,
            "SCHEDULER_CHECKPOINT_DISPATCH_FAILED:start",
        ):
            runtime.scheduler.issue_dispatch("start")

        self.assertEqual(int(self.budget.snapshot()["steps_used"]), before)
        self.assertEqual(self._counts(), (0, 0))

        repository._append_event = original_append_event
        ticket = runtime.scheduler.issue_dispatch("start")
        self.assertEqual(ticket.dispatch_sequence, 2)
        self.assertEqual(int(self.budget.snapshot()["steps_used"]), before + 1)
        self.assertEqual(self._counts(), (1, 1))

    def test_exact_dispatch_replay_is_idempotent_and_does_not_double_charge(self):
        runtime = self._compose()
        before = int(self.budget.snapshot()["steps_used"])
        ticket = runtime.scheduler.issue_dispatch("start")
        after_first = int(self.budget.snapshot()["steps_used"])

        runtime.checkpoint_repository.record_dispatch(ticket)

        self.assertEqual(after_first, before + 1)
        self.assertEqual(int(self.budget.snapshot()["steps_used"]), after_first)
        self.assertEqual(self._counts(), (1, 1))

    def test_concurrent_exact_first_write_converges_to_one_budget_charge(self):
        leases = RuntimeWriterLeaseRepository(self.store)
        leases.initialize()
        lease = leases.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan.fingerprint,
            run_id="RUN-DISPATCH-BUDGET-CONCURRENT",
        )
        producer = ExecutionScheduler(
            task_context=self.context,
            plan=self.plan,
            parent_authority=self.authority,
            budget_guard=NoopBudgetGuard(),
            revocation_guard=self.revocations,
            max_concurrency=1,
        )
        ticket = producer.issue_dispatch("start")
        repo_a = AtomicBudgetWriterFencedExecutionCheckpointRepository(
            self.store,
            lease,
            self.budget,
        )
        repo_b = AtomicBudgetWriterFencedExecutionCheckpointRepository(
            TaskStore(self.store.db_path),
            lease,
            TaskExecutionBudgetState.from_bound_contract(
                TaskStore(self.store.db_path),
                self.task.task_id,
            ),
        )
        repo_a.initialize()
        repo_b.initialize()
        before = int(self.budget.snapshot()["steps_used"])
        results = []
        failures = []
        barrier = threading.Barrier(2)

        def persist(repository):
            try:
                barrier.wait()
                results.append(repository.record_dispatch(ticket).ticket_id)
            except Exception as exc:  # pragma: no cover - assertion captures type below
                failures.append(exc)

        threads = [
            threading.Thread(target=persist, args=(repo_a,)),
            threading.Thread(target=persist, args=(repo_b,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(failures, [])
        self.assertEqual(results, [ticket.ticket_id, ticket.ticket_id])
        self.assertEqual(int(self.budget.snapshot()["steps_used"]), before + 1)
        self.assertEqual(self._counts(), (1, 1))

    def test_exhausted_step_budget_denies_before_checkpoint_or_reservation(self):
        remaining = self.budget.max_steps - int(self.budget.snapshot()["steps_used"])
        self.budget.reserve(steps=remaining)
        runtime = self._compose()

        with self.assertRaisesRegex(
            ExecutionSchedulerError,
            "SCHEDULER_BUDGET_DENIED:TASK_STEP_BUDGET_EXHAUSTED",
        ):
            runtime.scheduler.issue_dispatch("start")

        self.assertEqual(self._counts(), (0, 0))
        self.assertEqual(int(self.budget.snapshot()["steps_used"]), self.budget.max_steps)

    def test_expired_deadline_denies_without_dispatch_side_effect(self):
        expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE task_execution_budget_usage SET deadline_at = ? WHERE task_id = ?",
                (expired, self.task.task_id),
            )
        runtime = self._compose()

        with self.assertRaisesRegex(
            ExecutionSchedulerError,
            "SCHEDULER_BUDGET_DENIED:TASK_WALL_TIME_BUDGET_EXHAUSTED",
        ):
            runtime.scheduler.issue_dispatch("start")

        self.assertEqual(self._counts(), (0, 0))

    def test_cancellation_and_observation_settlement_do_not_charge_extra_steps(self):
        cancelled = self._compose("RUN-DISPATCH-BUDGET-CANCEL")
        before_cancel = int(self.budget.snapshot()["steps_used"])
        cancelled.scheduler.cancel(reason_code="OPERATOR_CANCELLED")
        self.assertEqual(int(self.budget.snapshot()["steps_used"]), before_cancel)

        # Use a fresh database scope for the settlement assertion because the
        # cancellation is intentionally durable for this task/plan.
        with tempfile.TemporaryDirectory() as tmp:
            other_store = TaskStore(Path(tmp) / "workspace.sqlite3")
            other_store.initialize()
            other_task = other_store.create_task("settlement", "request")
            contract = TaskContractCompiler().compile(
                task_id=other_task.task_id,
                task_type="analysis",
                sensitivity="internal",
                risk_level="low",
                write_scope="none",
            )
            other_store.bind_task_contract(other_task.task_id, contract.to_dict())
            budget = TaskExecutionBudgetState.from_bound_contract(other_store, other_task.task_id)
            acceptance = AcceptanceContract(
                task_id=other_task.task_id,
                criteria=(AcceptanceCriterion("settle", "settle", "unit_test"),),
            )
            canonical = HarnessTaskCompiler().compile(
                user_prompt="settle",
                task_contract=contract,
                acceptance_contract=acceptance,
            )
            context = TaskContextBuilder.build(
                task_contract=contract,
                canonical_task=canonical,
                session_id="SESSION-SETTLE",
                trace_id="TRACE-SETTLE",
                actor_id="ACTOR-SETTLE",
                purpose="settlement budget test",
                project_id="PROJECT-SETTLE",
                created_at=datetime(2026, 9, 10, 2, 30, tzinfo=timezone.utc),
            )
            authority = TaskCapabilityAuthority.from_contract(contract)
            plan = ExecutionPlanBuilder.build(
                task_context=context,
                parent_authority=authority,
                workflow_contract=one_node_workflow(),
                node_bindings={},
            )
            runtime = compose_writer_fenced_execution_runtime(
                task_store=other_store,
                run_id="RUN-SETTLE",
                task_context=context,
                plan=plan,
                parent_authority=authority,
                budget_guard=budget,
                revocation_guard=FakeRevocationGuard(),
                max_concurrency=1,
            )
            runtime.scheduler.issue_dispatch("start")
            after_dispatch = int(budget.snapshot()["steps_used"])
            observation = ExecutionObservationBuilder.build(
                plan=plan,
                node_id="start",
                parent_authority=authority,
                status="SUCCEEDED",
                started_at="2026-09-10T02:31:00Z",
                finished_at="2026-09-10T02:31:01Z",
                normalized_output={"status": "SUCCEEDED"},
            )
            runtime.scheduler.accept_observation(observation)
            self.assertEqual(int(budget.snapshot()["steps_used"]), after_dispatch)

    def test_legacy_writer_fenced_dispatch_recovers_without_synthetic_second_charge(self):
        leases = RuntimeWriterLeaseRepository(self.store)
        leases.initialize()
        lease = leases.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan.fingerprint,
            run_id="RUN-LEGACY-G5",
        )
        legacy_repo = WriterFencedExecutionCheckpointRepository(self.store, lease)
        legacy_scheduler = ExecutionScheduler(
            task_context=self.context,
            plan=self.plan,
            parent_authority=self.authority,
            budget_guard=self.budget,
            revocation_guard=self.revocations,
            max_concurrency=1,
            checkpoint_repository=legacy_repo,
        )
        before = int(self.budget.snapshot()["steps_used"])
        ticket = legacy_scheduler.issue_dispatch("start")
        self.assertEqual(int(self.budget.snapshot()["steps_used"]), before + 1)

        upgraded = self._compose("RUN-LEGACY-G5")
        self.assertEqual(upgraded.scheduler.recovery_required_ticket_ids, (ticket.ticket_id,))
        self.assertEqual(int(self.budget.snapshot()["steps_used"]), before + 1)
        upgraded.scheduler.accept_observation(self._observation())
        self.assertEqual(int(self.budget.snapshot()["steps_used"]), before + 1)

        with self.assertRaisesRegex(
            ExecutionDispatchBudgetError,
            "DISPATCH_BUDGET_RESERVATION_MISSING",
        ):
            upgraded.checkpoint_repository.record_dispatch(ticket)


if __name__ == "__main__":
    unittest.main()
