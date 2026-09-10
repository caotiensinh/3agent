from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.execution_budget import ExecutionBudgetExceeded
from three_agent.execution_checkpoint import ExecutionCheckpointRepository
from three_agent.execution_checkpoint_writer_fence import (
    ExecutionWriterFenceError,
    WRITER_FENCE_EVENT_TYPE,
    WriterFencedExecutionCheckpointRepository,
)
from three_agent.execution_observation import ExecutionObservationBuilder
from three_agent.execution_plan import ExecutionNodeBinding, ExecutionPlanBuilder
from three_agent.execution_scheduler import ExecutionScheduler, ExecutionSchedulerError
from three_agent.harness_acceptance import AcceptanceContract, AcceptanceCriterion
from three_agent.harness_task_compiler import HarnessTaskCompiler
from three_agent.runtime_writer_lease import RuntimeWriterLeaseRepository
from three_agent.store import TaskStore
from three_agent.task_context import TaskContextBuilder, TaskResourceBudget
from three_agent.task_contract import TaskContractCompiler


class FakeBudgetGuard:
    def __init__(self):
        self.active = True
        self.steps = 0

    def assert_active(self):
        if not self.active:
            raise ExecutionBudgetExceeded("TASK_WALL_TIME_BUDGET_EXHAUSTED")

    def reserve(self, *, steps=0, tool_calls=0, retries=0, escalations=0):
        self.assert_active()
        self.steps += steps


class FakeRevocationGuard:
    def is_revoked(self, task_id, capability):
        return False


def workflow():
    return {
        "title": "Writer-fenced execution checkpoint",
        "objective": "Persist execution only under the current writer generation.",
        "trigger": "manual",
        "risk_level": "medium",
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
            },
            {
                "id": "collect",
                "label": "Collect evidence",
                "kind": "agent",
                "action": "research",
                "depends_on": ["start"],
                "condition": "",
                "approval_required": False,
            },
            {
                "id": "done",
                "label": "Return result",
                "kind": "output",
                "action": "output",
                "depends_on": ["collect"],
                "condition": "",
                "approval_required": False,
            },
        ],
        "outputs": ["Writer-fenced result"],
        "warnings": [],
    }


class ExecutionCheckpointWriterFenceTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = TaskStore(Path(self.tempdir.name) / "workspace.sqlite3")
        self.store.initialize()
        self.task = self.store.create_task(
            "Writer fence test",
            "Protect scheduler persistence from stale runs.",
        )
        self.context, self.authority, self.plan = self._build_plan()
        self.leases = RuntimeWriterLeaseRepository(self.store)
        self.leases.initialize()

    def tearDown(self):
        self.tempdir.cleanup()

    def _build_plan(self):
        task_id = self.task.task_id
        contract = TaskContractCompiler().compile(
            task_id=task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level="medium",
            allowed_sources=("repo", "evidence"),
            allowed_tools=("read_file",),
            write_scope="none",
        )
        acceptance = AcceptanceContract(
            task_id=task_id,
            criteria=(
                AcceptanceCriterion(
                    criterion_id="writer-fence",
                    statement="Only the current run generation may persist execution state",
                    verifier="unit_test",
                ),
            ),
        )
        canonical = HarnessTaskCompiler().compile(
            user_prompt="Persist execution under a generation fence.",
            task_contract=contract,
            acceptance_contract=acceptance,
        )
        context = TaskContextBuilder.build(
            task_contract=contract,
            canonical_task=canonical,
            session_id="SESSION-WRITER-FENCE-1",
            trace_id="TRACE-WRITER-FENCE-1",
            actor_id="ACTOR-WRITER-FENCE-1",
            purpose="writer-generation persistence enforcement",
            project_id="PROJECT-WRITER-FENCE-1",
            created_at=datetime(2026, 9, 9, 13, 30, tzinfo=timezone.utc),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        plan = ExecutionPlanBuilder.build(
            task_context=context,
            parent_authority=authority,
            workflow_contract=workflow(),
            node_bindings={
                "collect": ExecutionNodeBinding(
                    allowed_sources=("repo",),
                    allowed_tools=("read_file",),
                    resource_budget=TaskResourceBudget(
                        wall_time_s=10,
                        model_tokens=100,
                        tool_calls=1,
                    ),
                ),
            },
        )
        return context, authority, plan

    def _claim(self, run_id):
        return self.leases.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan.fingerprint,
            run_id=run_id,
        )

    def _repository(self, lease):
        return WriterFencedExecutionCheckpointRepository(self.store, lease)

    def _scheduler(self, repository):
        return ExecutionScheduler(
            task_context=self.context,
            plan=self.plan,
            parent_authority=self.authority,
            budget_guard=FakeBudgetGuard(),
            revocation_guard=FakeRevocationGuard(),
            max_concurrency=1,
            checkpoint_repository=repository,
        )

    def _observation(self, node_id):
        return ExecutionObservationBuilder.build(
            plan=self.plan,
            node_id=node_id,
            parent_authority=self.authority,
            status="SUCCEEDED",
            started_at="2026-09-09T13:31:00Z",
            finished_at="2026-09-09T13:31:01Z",
            normalized_output={"node": node_id, "status": "SUCCEEDED"},
        )

    def test_existing_scheduler_works_without_architecture_replacement(self):
        lease = self._claim("RUN-A")
        repository = self._repository(lease)
        scheduler = self._scheduler(repository)

        ticket = scheduler.issue_dispatch("start")
        observation = scheduler.accept_observation(self._observation("start"))

        self.assertEqual(ticket.node_id, "start")
        self.assertEqual(observation.node_id, "start")
        self.assertTrue(repository.verify_event_chain(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan.fingerprint,
        ))
        self.assertTrue(repository.verify_writer_fence_bindings())
        with self.store.connect() as conn:
            event_types = [
                str(row["event_type"])
                for row in conn.execute(
                    """
                    SELECT event_type FROM execution_checkpoint_events
                    WHERE task_id = ? AND plan_fingerprint = ?
                    ORDER BY sequence ASC
                    """,
                    (self.task.task_id, self.plan.fingerprint),
                ).fetchall()
            ]
        self.assertEqual(
            event_types,
            [
                "DISPATCH_RECORDED",
                WRITER_FENCE_EVENT_TYPE,
                "OBSERVATION_RECORDED",
                WRITER_FENCE_EVENT_TYPE,
            ],
        )

    def test_stale_scheduler_cannot_persist_observation_after_supersession(self):
        lease_a = self._claim("RUN-A")
        scheduler_a = self._scheduler(self._repository(lease_a))
        scheduler_a.issue_dispatch("start")

        lease_b = self._claim("RUN-B")
        self.assertEqual(lease_b.generation, lease_a.generation + 1)

        with self.assertRaisesRegex(
            ExecutionSchedulerError,
            "SCHEDULER_CHECKPOINT_OBSERVATION_FAILED:start",
        ):
            scheduler_a.accept_observation(self._observation("start"))

        with self.store.connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) AS n FROM execution_observation_checkpoints"
            ).fetchone()["n"]
        self.assertEqual(count, 0)

    def test_new_generation_cannot_settle_dispatch_owned_by_old_generation(self):
        lease_a = self._claim("RUN-A")
        scheduler_a = self._scheduler(self._repository(lease_a))
        ticket = scheduler_a.issue_dispatch("start")

        lease_b = self._claim("RUN-B")
        scheduler_b = self._scheduler(self._repository(lease_b))
        self.assertEqual(scheduler_b.recovery_required_ticket_ids, (ticket.ticket_id,))

        with self.assertRaisesRegex(
            ExecutionSchedulerError,
            "SCHEDULER_CHECKPOINT_OBSERVATION_FAILED:start",
        ):
            scheduler_b.accept_observation(self._observation("start"))

        with self.store.connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) AS n FROM execution_observation_checkpoints"
            ).fetchone()["n"]
        self.assertEqual(count, 0)

    def test_same_active_run_can_restart_and_finish_its_recovery_required_dispatch(self):
        lease = self._claim("RUN-A")
        first = self._scheduler(self._repository(lease))
        ticket = first.issue_dispatch("start")

        same_lease = self._claim("RUN-A")
        self.assertEqual(same_lease, lease)
        restarted = self._scheduler(self._repository(same_lease))
        self.assertEqual(restarted.recovery_required_ticket_ids, (ticket.ticket_id,))

        accepted = restarted.accept_observation(self._observation("start"))
        self.assertEqual(accepted.node_id, "start")
        self.assertEqual(restarted.recovery_required_ticket_ids, ())

    def test_stale_writer_cannot_idempotently_replay_existing_dispatch(self):
        lease_a = self._claim("RUN-A")
        repository_a = self._repository(lease_a)
        scheduler_a = self._scheduler(repository_a)
        ticket = scheduler_a.issue_dispatch("start")

        self._claim("RUN-B")
        with self.assertRaisesRegex(
            ExecutionWriterFenceError,
            "EXECUTION_WRITER_FENCE_DENIED:WRITER_LEASE_STALE",
        ):
            repository_a.record_dispatch(ticket)

    def test_legacy_unfenced_checkpoint_requires_manual_migration(self):
        base = ExecutionCheckpointRepository(self.store)
        legacy_scheduler = self._scheduler(base)
        ticket = legacy_scheduler.issue_dispatch("start")

        lease = self._claim("RUN-A")
        fenced = self._repository(lease)
        fenced.initialize()
        with self.assertRaisesRegex(
            ExecutionWriterFenceError,
            "EXECUTION_WRITER_FENCE_BINDINGS_INVALID",
        ):
            fenced.load(
                task_id=self.task.task_id,
                plan_fingerprint=self.plan.fingerprint,
            )
        self.assertEqual(ticket.node_id, "start")

    def test_current_generation_cancellation_is_fenced_and_stale_generation_is_denied(self):
        lease_a = self._claim("RUN-A")
        repository_a = self._repository(lease_a)
        repository_a.initialize()
        repository_a.record_cancellation(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan.fingerprint,
            reason_code="OPERATOR_CANCELLED",
        )
        self.assertTrue(repository_a.verify_writer_fence_bindings())

        self._claim("RUN-B")
        with self.assertRaisesRegex(
            ExecutionWriterFenceError,
            "EXECUTION_WRITER_FENCE_DENIED:WRITER_LEASE_STALE",
        ):
            repository_a.record_cancellation(
                task_id=self.task.task_id,
                plan_fingerprint=self.plan.fingerprint,
                reason_code="OPERATOR_CANCELLED",
            )


if __name__ == "__main__":
    unittest.main()
