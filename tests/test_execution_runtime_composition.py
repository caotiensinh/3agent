from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.execution_budget import TaskExecutionBudgetState
from three_agent.execution_dispatch_budget import (
    AtomicBudgetWriterFencedExecutionCheckpointRepository,
    DispatchBudgetPreflightGuard,
)
from three_agent.execution_observation import ExecutionObservationBuilder
from three_agent.execution_plan import ExecutionNodeBinding, ExecutionPlanBuilder
from three_agent.execution_runtime_composition import (
    ExecutionRuntimeCompositionError,
    compose_writer_fenced_execution_runtime,
)
from three_agent.execution_scheduler import ExecutionSchedulerError
from three_agent.harness_acceptance import AcceptanceContract, AcceptanceCriterion
from three_agent.harness_task_compiler import HarnessTaskCompiler
from three_agent.runtime_writer_lease import RuntimeWriterLeaseRepository
from three_agent.store import TaskStore
from three_agent.task_context import TaskContextBuilder, TaskResourceBudget
from three_agent.task_contract import TaskContractCompiler


class FakeRevocationGuard:
    def is_revoked(self, task_id, capability):
        return False


def workflow():
    return {
        "title": "Production writer-fenced composition",
        "objective": "Compose canonical execution under one durable run identity.",
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


class ExecutionRuntimeCompositionTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = TaskStore(Path(self.tempdir.name) / "workspace.sqlite3")
        self.store.initialize()
        self.task = self.store.create_task(
            "Production composition test",
            "Require writer-fenced persistence for canonical execution.",
        )
        self.context, self.authority, self.plan, self.contract = self._build_plan()
        self.store.bind_task_contract(self.task.task_id, self.contract.to_dict())
        self.budget = TaskExecutionBudgetState.from_bound_contract(
            self.store,
            self.task.task_id,
        )
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
                    criterion_id="production-composition",
                    statement="Canonical execution always uses current writer generation",
                    verifier="unit_test",
                ),
            ),
        )
        canonical = HarnessTaskCompiler().compile(
            user_prompt="Compose the canonical writer-fenced execution runtime.",
            task_contract=contract,
            acceptance_contract=acceptance,
        )
        context = TaskContextBuilder.build(
            task_contract=contract,
            canonical_task=canonical,
            session_id="SESSION-COMPOSITION-1",
            trace_id="TRACE-COMPOSITION-1",
            actor_id="ACTOR-COMPOSITION-1",
            purpose="production writer-fenced composition",
            project_id="PROJECT-COMPOSITION-1",
            created_at=datetime(2026, 9, 10, 1, 0, tzinfo=timezone.utc),
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
        return context, authority, plan, contract

    def _compose(self, run_id, **overrides):
        arguments = {
            "task_store": self.store,
            "run_id": run_id,
            "task_context": self.context,
            "plan": self.plan,
            "parent_authority": self.authority,
            "budget_guard": self.budget,
            "revocation_guard": FakeRevocationGuard(),
            "max_concurrency": 1,
        }
        arguments.update(overrides)
        return compose_writer_fenced_execution_runtime(**arguments)

    def _observation(self, node_id):
        return ExecutionObservationBuilder.build(
            plan=self.plan,
            node_id=node_id,
            parent_authority=self.authority,
            status="SUCCEEDED",
            started_at="2026-09-10T01:01:00Z",
            finished_at="2026-09-10T01:01:01Z",
            normalized_output={"node": node_id, "status": "SUCCEEDED"},
        )

    def _current_lease(self):
        return self.leases.current(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan.fingerprint,
        )

    def test_composition_requires_caller_supplied_run_identity_without_fallback(self):
        with self.assertRaisesRegex(
            ExecutionRuntimeCompositionError,
            "EXECUTION_RUNTIME_RUN_ID_REQUIRED",
        ):
            self._compose(" ")

        self.assertIsNone(self._current_lease())

    def test_composition_mandates_atomic_budget_writer_fenced_repository(self):
        runtime = self._compose("RUN-COMPOSITION-A")

        self.assertIsInstance(
            runtime.checkpoint_repository,
            AtomicBudgetWriterFencedExecutionCheckpointRepository,
        )
        self.assertIs(
            runtime.scheduler.checkpoint_repository,
            runtime.checkpoint_repository,
        )
        self.assertIsInstance(runtime.scheduler.budget_guard, DispatchBudgetPreflightGuard)
        self.assertIs(
            runtime.scheduler.budget_guard.controller,
            runtime.checkpoint_repository.dispatch_budget_controller,
        )
        self.assertEqual(runtime.run_id, "RUN-COMPOSITION-A")
        self.assertEqual(runtime.writer_lease.run_id, runtime.run_id)
        self.assertEqual(runtime.writer_lease.generation, 1)

    def test_same_durable_run_restart_reuses_generation_without_double_charging(self):
        first = self._compose("RUN-COMPOSITION-A")
        before = self.budget.snapshot()["steps_used"]
        ticket = first.scheduler.issue_dispatch("start")
        self.assertEqual(self.budget.snapshot()["steps_used"], before + 1)

        restarted = self._compose("RUN-COMPOSITION-A")
        self.assertEqual(restarted.writer_lease, first.writer_lease)
        self.assertEqual(
            restarted.scheduler.recovery_required_ticket_ids,
            (ticket.ticket_id,),
        )
        self.assertEqual(self.budget.snapshot()["steps_used"], before + 1)

        accepted = restarted.scheduler.accept_observation(self._observation("start"))
        self.assertEqual(accepted.node_id, "start")
        self.assertEqual(restarted.scheduler.recovery_required_ticket_ids, ())
        self.assertEqual(self.budget.snapshot()["steps_used"], before + 1)
        self.assertTrue(restarted.checkpoint_repository.verify_writer_fence_bindings())

    def test_superseding_run_fences_stale_runtime_and_cannot_settle_old_dispatch(self):
        first = self._compose("RUN-COMPOSITION-A")
        before = self.budget.snapshot()["steps_used"]
        ticket = first.scheduler.issue_dispatch("start")

        second = self._compose("RUN-COMPOSITION-B")
        self.assertEqual(
            second.writer_lease.generation,
            first.writer_lease.generation + 1,
        )
        self.assertEqual(
            second.scheduler.recovery_required_ticket_ids,
            (ticket.ticket_id,),
        )
        self.assertEqual(self.budget.snapshot()["steps_used"], before + 1)

        with self.assertRaisesRegex(
            ExecutionSchedulerError,
            "SCHEDULER_CHECKPOINT_OBSERVATION_FAILED:start",
        ):
            first.scheduler.accept_observation(self._observation("start"))

        with self.assertRaisesRegex(
            ExecutionSchedulerError,
            "SCHEDULER_CHECKPOINT_OBSERVATION_FAILED:start",
        ):
            second.scheduler.accept_observation(self._observation("start"))

        with self.store.connect() as conn:
            observations = conn.execute(
                "SELECT COUNT(*) AS n FROM execution_observation_checkpoints"
            ).fetchone()["n"]
        self.assertEqual(observations, 0)
        self.assertEqual(self.budget.snapshot()["steps_used"], before + 1)

    def test_noncanonical_budget_cannot_enter_production_composition(self):
        with self.assertRaisesRegex(
            ExecutionRuntimeCompositionError,
            "EXECUTION_RUNTIME_CANONICAL_BUDGET_STATE_REQUIRED",
        ):
            self._compose("RUN-COMPOSITION-A", budget_guard=object())
        self.assertIsNone(self._current_lease())

    def test_invalid_admission_or_scheduler_shape_does_not_supersede_current_writer(self):
        first = self._compose("RUN-COMPOSITION-A")

        with self.assertRaisesRegex(
            ExecutionRuntimeCompositionError,
            "EXECUTION_RUNTIME_CANONICAL_ADMISSION_FAILED",
        ):
            self._compose("RUN-COMPOSITION-B", parent_authority=object())
        self.assertEqual(self._current_lease(), first.writer_lease)

        with self.assertRaisesRegex(
            ExecutionRuntimeCompositionError,
            "EXECUTION_RUNTIME_MAX_CONCURRENCY_INVALID",
        ):
            self._compose("RUN-COMPOSITION-C", max_concurrency=0)
        self.assertEqual(self._current_lease(), first.writer_lease)


if __name__ == "__main__":
    unittest.main()
