from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.execution_budget import ExecutionBudgetExceeded
from three_agent.execution_checkpoint import ExecutionCheckpointRepository
from three_agent.execution_observation import ExecutionObservationBuilder
from three_agent.execution_plan import ExecutionNodeBinding, ExecutionPlanBuilder
from three_agent.execution_scheduler import ExecutionScheduler, ExecutionSchedulerError
from three_agent.harness_acceptance import AcceptanceContract, AcceptanceCriterion
from three_agent.harness_task_compiler import HarnessTaskCompiler
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


class DispatchFailingRepository:
    def __init__(self, delegate):
        self.delegate = delegate

    def initialize(self):
        return self.delegate.initialize()

    def load(self, *, task_id, plan_fingerprint):
        return self.delegate.load(
            task_id=task_id,
            plan_fingerprint=plan_fingerprint,
        )

    def record_dispatch(self, ticket):
        raise RuntimeError("simulated dispatch persistence failure")

    def record_observation(self, observation):
        return self.delegate.record_observation(observation)

    def record_cancellation(self, *, task_id, plan_fingerprint, reason_code):
        return self.delegate.record_cancellation(
            task_id=task_id,
            plan_fingerprint=plan_fingerprint,
            reason_code=reason_code,
        )


class ObservationFailingRepository:
    def __init__(self, delegate):
        self.delegate = delegate

    def initialize(self):
        return self.delegate.initialize()

    def load(self, *, task_id, plan_fingerprint):
        return self.delegate.load(
            task_id=task_id,
            plan_fingerprint=plan_fingerprint,
        )

    def record_dispatch(self, ticket):
        return self.delegate.record_dispatch(ticket)

    def record_observation(self, observation):
        raise RuntimeError("simulated observation persistence failure")

    def record_cancellation(self, *, task_id, plan_fingerprint, reason_code):
        return self.delegate.record_cancellation(
            task_id=task_id,
            plan_fingerprint=plan_fingerprint,
            reason_code=reason_code,
        )


def fork_join_workflow(*, approval=False):
    return {
        "title": "Persistent bounded runtime dependency scheduler",
        "objective": "Recover delegated dispatches without automatic replay.",
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
                "id": "lane_a",
                "label": "Read lane A",
                "kind": "agent",
                "action": "research",
                "depends_on": ["start"],
                "condition": "",
                "approval_required": False,
            },
            {
                "id": "lane_b",
                "label": "Read lane B",
                "kind": "agent",
                "action": "research",
                "depends_on": ["start"],
                "condition": "",
                "approval_required": False,
            },
            {
                "id": "join",
                "label": "Join observations",
                "kind": "validation",
                "action": "validate",
                "depends_on": ["lane_a", "lane_b"],
                "condition": "",
                "approval_required": approval,
            },
            {
                "id": "done",
                "label": "Return result",
                "kind": "output",
                "action": "output",
                "depends_on": ["join"],
                "condition": "",
                "approval_required": False,
            },
        ],
        "outputs": ["Validated result"],
        "warnings": [],
    }


def build_runtime(
    task_id,
    checkpoint_repository,
    *,
    approval=False,
    checkpoint_reapproved_nodes=frozenset(),
):
    contract = TaskContractCompiler().compile(
        task_id=task_id,
        task_type="analysis",
        sensitivity="internal",
        risk_level="medium",
        allowed_sources=("repo", "evidence"),
        allowed_tools=("read_file", "search_docs"),
        write_scope="none",
    )
    acceptance = AcceptanceContract(
        task_id=task_id,
        criteria=(
            AcceptanceCriterion(
                criterion_id="checkpoint",
                statement="Recover scheduler state without replaying unfinished work",
                verifier="unit_test",
            ),
        ),
    )
    canonical = HarnessTaskCompiler().compile(
        user_prompt="Persist and restore the canonical runtime plan.",
        task_contract=contract,
        acceptance_contract=acceptance,
    )
    context = TaskContextBuilder.build(
        task_contract=contract,
        canonical_task=canonical,
        session_id="SESSION-CHECKPOINT-1",
        trace_id="TRACE-CHECKPOINT-1",
        actor_id="ACTOR-CHECKPOINT-1",
        purpose="persistent runtime checkpoint",
        project_id="PROJECT-CHECKPOINT-1",
        created_at=datetime(2026, 9, 9, tzinfo=timezone.utc),
    )
    authority = TaskCapabilityAuthority.from_contract(contract)
    lane_budget = TaskResourceBudget(
        wall_time_s=10,
        model_tokens=100,
        tool_calls=1,
    )
    plan = ExecutionPlanBuilder.build(
        task_context=context,
        parent_authority=authority,
        workflow_contract=fork_join_workflow(approval=approval),
        node_bindings={
            "lane_a": ExecutionNodeBinding(
                allowed_sources=("repo",),
                allowed_tools=("read_file",),
                resource_budget=lane_budget,
            ),
            "lane_b": ExecutionNodeBinding(
                allowed_sources=("evidence",),
                allowed_tools=("search_docs",),
                resource_budget=lane_budget,
            ),
            "join": ExecutionNodeBinding(
                resource_budget=TaskResourceBudget(
                    wall_time_s=5,
                    model_tokens=0,
                    tool_calls=0,
                ),
                approval_required=approval,
            ),
        },
    )
    budget = FakeBudgetGuard()
    scheduler = ExecutionScheduler(
        task_context=context,
        plan=plan,
        parent_authority=authority,
        budget_guard=budget,
        revocation_guard=FakeRevocationGuard(),
        max_concurrency=2,
        checkpoint_repository=checkpoint_repository,
        checkpoint_reapproved_nodes=checkpoint_reapproved_nodes,
    )
    return authority, plan, scheduler, budget


def observe(plan, authority, node_id):
    return ExecutionObservationBuilder.build(
        plan=plan,
        node_id=node_id,
        parent_authority=authority,
        status="SUCCEEDED",
        started_at="2026-09-09T00:00:00Z",
        finished_at="2026-09-09T00:00:01Z",
        normalized_output={"node": node_id, "status": "SUCCEEDED"},
    )


class ExecutionSchedulerCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = TaskStore(Path(self.tempdir.name) / "workspace.sqlite3")
        self.store.initialize()
        self.task = self.store.create_task(
            "Checkpoint scheduler test",
            "Persist delegated execution receipts.",
        )
        self.repository = ExecutionCheckpointRepository(self.store)
        self.repository.initialize()

    def tearDown(self):
        self.tempdir.cleanup()

    def _complete(
        self,
        scheduler,
        plan,
        authority,
        node_id,
        *,
        approval=False,
    ):
        scheduler.issue_dispatch(node_id, approval_granted=approval)
        return scheduler.accept_observation(
            observe(plan, authority, node_id)
        )

    def test_completed_observation_restores_without_replay(self):
        authority, plan, scheduler, _ = build_runtime(
            self.task.task_id,
            self.repository,
        )
        self._complete(scheduler, plan, authority, "start")

        _, _, restored, _ = build_runtime(
            self.task.task_id,
            self.repository,
        )

        self.assertEqual(restored.blocked_reason("start"), "OBSERVED")
        self.assertEqual(restored.ready_node_ids(), ("lane_a", "lane_b"))
        self.assertEqual(restored.recovery_required_ticket_ids, ())
        self.assertTrue(restored.snapshot()["checkpoint_bound"])

    def test_unfinished_dispatch_freezes_new_work_until_reconciled(self):
        authority, plan, scheduler, _ = build_runtime(
            self.task.task_id,
            self.repository,
        )
        self._complete(scheduler, plan, authority, "start")
        ticket = scheduler.issue_dispatch("lane_a")

        restored_authority, restored_plan, restored, _ = build_runtime(
            self.task.task_id,
            self.repository,
        )

        self.assertEqual(
            restored.recovery_required_ticket_ids,
            (ticket.ticket_id,),
        )
        self.assertEqual(restored.blocked_reason("lane_a"), "RECOVERY_REQUIRED")
        self.assertEqual(
            restored.blocked_reason("lane_b"),
            "SCHEDULER_RECOVERY_REQUIRED",
        )
        self.assertEqual(restored.ready_node_ids(), ())
        with self.assertRaisesRegex(
            ExecutionSchedulerError,
            "SCHEDULER_RECOVERY_REQUIRED",
        ):
            restored.issue_dispatch("lane_b")

        restored.accept_observation(
            observe(restored_plan, restored_authority, "lane_a")
        )
        self.assertEqual(restored.recovery_required_ticket_ids, ())
        self.assertEqual(restored.ready_node_ids(), ("lane_b",))

    def test_late_observation_reconciliation_is_durable_across_restart(self):
        authority, plan, scheduler, _ = build_runtime(
            self.task.task_id,
            self.repository,
        )
        self._complete(scheduler, plan, authority, "start")
        scheduler.issue_dispatch("lane_a")

        restored_authority, restored_plan, restored, _ = build_runtime(
            self.task.task_id,
            self.repository,
        )
        restored.accept_observation(
            observe(restored_plan, restored_authority, "lane_a")
        )

        _, _, restarted, _ = build_runtime(
            self.task.task_id,
            self.repository,
        )
        self.assertEqual(restarted.blocked_reason("lane_a"), "OBSERVED")
        self.assertEqual(restarted.recovery_required_ticket_ids, ())
        self.assertEqual(restarted.ready_node_ids(), ("lane_b",))

    def test_dispatch_persistence_failure_never_enters_in_flight(self):
        failing = DispatchFailingRepository(self.repository)
        _, _, scheduler, _ = build_runtime(
            self.task.task_id,
            failing,
        )

        with self.assertRaisesRegex(
            ExecutionSchedulerError,
            "SCHEDULER_CHECKPOINT_DISPATCH_FAILED:start",
        ):
            scheduler.issue_dispatch("start")

        snapshot = scheduler.snapshot()
        self.assertEqual(snapshot["in_flight"], [])
        self.assertEqual(snapshot["recovery_required_ticket_ids"], [])
        recovered = self.repository.load(
            task_id=scheduler.plan.task_id,
            plan_fingerprint=scheduler.plan.fingerprint,
        )
        self.assertEqual(recovered.dispatches, ())

    def test_observation_persistence_failure_keeps_dispatch_unfinished(self):
        failing = ObservationFailingRepository(self.repository)
        authority, plan, scheduler, _ = build_runtime(
            self.task.task_id,
            failing,
        )
        scheduler.issue_dispatch("start")

        with self.assertRaisesRegex(
            ExecutionSchedulerError,
            "SCHEDULER_CHECKPOINT_OBSERVATION_FAILED:start",
        ):
            scheduler.accept_observation(observe(plan, authority, "start"))

        self.assertEqual(scheduler.blocked_reason("start"), "IN_FLIGHT")

        _, _, restored, _ = build_runtime(
            self.task.task_id,
            self.repository,
        )
        self.assertEqual(restored.blocked_reason("start"), "RECOVERY_REQUIRED")
        self.assertEqual(len(restored.recovery_required_ticket_ids), 1)

    def test_persisted_cancellation_is_restored_fail_closed(self):
        _, _, scheduler, _ = build_runtime(
            self.task.task_id,
            self.repository,
        )
        scheduler.cancel(reason_code="OPERATOR_CANCELLED")

        _, _, restored, _ = build_runtime(
            self.task.task_id,
            self.repository,
        )
        self.assertTrue(restored.cancelled)
        self.assertEqual(restored.ready_node_ids(), ())
        self.assertEqual(
            restored.snapshot()["cancellation_reason"],
            "OPERATOR_CANCELLED",
        )

    def test_tampered_checkpoint_rejects_scheduler_restore(self):
        _, _, scheduler, _ = build_runtime(
            self.task.task_id,
            self.repository,
        )
        scheduler.issue_dispatch("start")

        with self.store.connect() as conn:
            conn.execute(
                """
                UPDATE execution_dispatch_checkpoints
                SET ticket_json = '{}'
                WHERE task_id = ?
                """,
                (self.task.task_id,),
            )

        with self.assertRaisesRegex(
            ExecutionSchedulerError,
            "SCHEDULER_CHECKPOINT_RESTORE_FAILED",
        ):
            build_runtime(
                self.task.task_id,
                self.repository,
            )

    def test_approval_dispatch_requires_explicit_reapproval_on_restore(self):
        authority, plan, scheduler, _ = build_runtime(
            self.task.task_id,
            self.repository,
            approval=True,
        )
        self._complete(scheduler, plan, authority, "start")
        self._complete(scheduler, plan, authority, "lane_a")
        self._complete(scheduler, plan, authority, "lane_b")
        self._complete(
            scheduler,
            plan,
            authority,
            "join",
            approval=True,
        )

        with self.assertRaisesRegex(
            ExecutionSchedulerError,
            "SCHEDULER_CHECKPOINT_REAPPROVAL_REQUIRED:join",
        ):
            build_runtime(
                self.task.task_id,
                self.repository,
                approval=True,
            )

        _, _, restored, _ = build_runtime(
            self.task.task_id,
            self.repository,
            approval=True,
            checkpoint_reapproved_nodes=frozenset({"join"}),
        )
        self.assertEqual(restored.blocked_reason("join"), "OBSERVED")
        self.assertEqual(restored.ready_node_ids(), ("done",))


if __name__ == "__main__":
    unittest.main()
