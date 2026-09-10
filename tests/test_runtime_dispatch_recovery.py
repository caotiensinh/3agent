import unittest
from datetime import datetime, timezone

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.capability_revocation import CapabilityRevocation
from three_agent.execution_budget import ExecutionBudgetExceeded
from three_agent.execution_observation import ExecutionObservationBuilder
from three_agent.execution_plan import ExecutionNodeBinding, ExecutionPlanBuilder
from three_agent.execution_scheduler import ExecutionScheduler
from three_agent.harness_acceptance import AcceptanceContract, AcceptanceCriterion
from three_agent.harness_task_compiler import HarnessTaskCompiler
from three_agent.runtime_checkpoint import RuntimeCheckpointBuilder
from three_agent.runtime_dispatch_recovery import (
    RuntimeDispatchRecovery,
    RuntimeDispatchRecoveryBindingBuilder,
    RuntimeDispatchRecoveryBindingCodec,
    RuntimeDispatchRecoveryError,
)
from three_agent.task_context import TaskContextBuilder, TaskResourceBudget
from three_agent.task_contract import TaskContractCompiler


class FakePersistentBudget:
    def __init__(self, task_id):
        self.active = True
        self.state = {
            "schema_version": "workspace-task-execution-budget-state/v2",
            "task_id": task_id,
            "max_steps": 8,
            "max_tool_calls": 0,
            "max_model_retries": 0,
            "max_model_escalations": 0,
            "max_wall_time_ms": 60_000,
            "steps_used": 0,
            "tool_calls_used": 0,
            "model_retries_used": 0,
            "model_escalations_used": 0,
            "deadline_at": "2026-09-08T04:00:00Z",
        }

    def assert_active(self):
        if not self.active:
            raise ExecutionBudgetExceeded("TASK_WALL_TIME_BUDGET_EXHAUSTED")

    def reserve(self, *, steps=0, tool_calls=0, retries=0, escalations=0):
        self.assert_active()
        updates = {
            "steps_used": steps,
            "tool_calls_used": tool_calls,
            "model_retries_used": retries,
            "model_escalations_used": escalations,
        }
        limits = {
            "steps_used": "max_steps",
            "tool_calls_used": "max_tool_calls",
            "model_retries_used": "max_model_retries",
            "model_escalations_used": "max_model_escalations",
        }
        for key, delta in updates.items():
            if self.state[key] + delta > self.state[limits[key]]:
                raise ExecutionBudgetExceeded("TASK_STEP_BUDGET_EXHAUSTED")
        for key, delta in updates.items():
            self.state[key] += delta

    def snapshot(self):
        return dict(self.state)


class FakePersistentRevocations:
    def __init__(self):
        self.rows = []

    def is_revoked(self, task_id, capability):
        return any(
            row.task_id == task_id and row.capability == capability
            for row in self.rows
        )

    def list_for_task(self, task_id):
        return tuple(
            sorted(
                (row for row in self.rows if row.task_id == task_id),
                key=lambda row: row.capability,
            )
        )

    def revoke(self, task_id, capability, second):
        row = CapabilityRevocation(
            task_id=task_id,
            capability=capability,
            reason_code="OPERATOR_REVOKED",
            revoked_at=f"2026-09-08T03:00:{second:02d}Z",
        )
        self.rows.append(row)
        return row


def workflow():
    return {
        "title": "Dispatch recovery",
        "objective": "Recover control state without replaying ambiguous work.",
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
        "outputs": ["Recovered result"],
        "warnings": [],
    }


class RuntimeDispatchRecoveryTests(unittest.TestCase):
    @staticmethod
    def _runtime():
        task_id = "TASK-DISPATCH-RECOVERY-1"
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
                    criterion_id="recovery",
                    statement="Recover dispatch state without automatic replay",
                    verifier="unit_test",
                ),
            ),
        )
        canonical = HarnessTaskCompiler().compile(
            user_prompt="Recover bounded dispatch state.",
            task_contract=contract,
            acceptance_contract=acceptance,
        )
        context = TaskContextBuilder.build(
            task_contract=contract,
            canonical_task=canonical,
            session_id="SESSION-DISPATCH-RECOVERY-1",
            trace_id="TRACE-DISPATCH-RECOVERY-1",
            actor_id="ACTOR-DISPATCH-RECOVERY-1",
            purpose="dispatch recovery binding",
            project_id="PROJECT-1",
            created_at=datetime(2026, 9, 8, 3, 0, tzinfo=timezone.utc),
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
                )
            },
        )
        budget = FakePersistentBudget(task_id)
        revocations = FakePersistentRevocations()
        scheduler = ExecutionScheduler(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            budget_guard=budget,
            revocation_guard=revocations,
            max_concurrency=2,
        )
        return context, authority, plan, scheduler, budget, revocations

    @staticmethod
    def _checkpoint(context, authority, plan, observations=(), approved_node_ids=()):
        return RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=observations,
            approved_node_ids=approved_node_ids,
            captured_at=datetime(2026, 9, 8, 3, 5, tzinfo=timezone.utc),
        )

    @staticmethod
    def _observation(plan, authority, node_id, status="SUCCEEDED"):
        return ExecutionObservationBuilder.build(
            plan=plan,
            node_id=node_id,
            parent_authority=authority,
            status=status,
            started_at="2026-09-08T03:00:00Z",
            finished_at="2026-09-08T03:00:01Z",
            normalized_output={"node": node_id},
        )

    @staticmethod
    def _binding(checkpoint, scheduler, budget, revocations):
        return RuntimeDispatchRecoveryBindingBuilder.build(
            checkpoint=checkpoint,
            scheduler_snapshot=scheduler.snapshot(),
            budget_snapshot=budget.snapshot(),
            revocations=revocations.list_for_task(checkpoint.task_id),
        )

    def test_binding_is_deterministic_codec_round_trips_and_zero_limits_are_valid(self):
        context, authority, plan, scheduler, budget, revocations = self._runtime()
        checkpoint = self._checkpoint(context, authority, plan)
        first = self._binding(checkpoint, scheduler, budget, revocations)
        second = self._binding(checkpoint, scheduler, budget, revocations)

        self.assertEqual(first, second)
        self.assertEqual(first.budget.max_tool_calls, 0)
        self.assertEqual(first.budget.max_model_retries, 0)
        self.assertEqual(first.budget.max_model_escalations, 0)
        restored = RuntimeDispatchRecoveryBindingCodec.loads(
            RuntimeDispatchRecoveryBindingCodec.dumps(first)
        )
        self.assertEqual(restored, first)
        self.assertEqual(restored.fingerprint, first.fingerprint)

    def test_quiescent_state_is_recoverable_without_execution(self):
        context, authority, plan, scheduler, budget, revocations = self._runtime()
        checkpoint = self._checkpoint(context, authority, plan)
        binding = self._binding(checkpoint, scheduler, budget, revocations)

        decision = RuntimeDispatchRecovery.evaluate(
            binding=binding,
            checkpoint=checkpoint,
            task_context=context,
            plan=plan,
            parent_authority=authority,
            budget_guard=budget,
            revocation_guard=revocations,
        )
        self.assertEqual(decision.status, "RECOVERABLE")
        self.assertEqual(
            decision.reason_code,
            "DISPATCH_RECOVERY_REVALIDATED_NO_EXECUTION_PERFORMED",
        )
        self.assertEqual(decision.checkpoint_recovery.scheduling_decision.ready_node_ids, ("start",))
        self.assertEqual(budget.state["steps_used"], 0)

    def test_in_flight_dispatch_requires_manual_reconciliation_and_is_not_replayed(self):
        context, authority, plan, scheduler, budget, revocations = self._runtime()
        ticket = scheduler.issue_dispatch("start")
        checkpoint = self._checkpoint(context, authority, plan)
        binding = self._binding(checkpoint, scheduler, budget, revocations)
        used_before_recovery = budget.state["steps_used"]

        decision = RuntimeDispatchRecovery.evaluate(
            binding=binding,
            checkpoint=checkpoint,
            task_context=context,
            plan=plan,
            parent_authority=authority,
            budget_guard=budget,
            revocation_guard=revocations,
        )
        self.assertEqual(decision.status, "MANUAL_RECONCILIATION")
        self.assertEqual(
            decision.reason_code,
            "IN_FLIGHT_DISPATCH_REQUIRES_MANUAL_RECONCILIATION",
        )
        self.assertEqual(decision.manual_dispatch_fingerprints, (ticket.fingerprint,))
        self.assertEqual(budget.state["steps_used"], used_before_recovery)

    def test_budget_counter_rollback_and_immutable_change_fail_closed(self):
        context, authority, plan, scheduler, budget, revocations = self._runtime()
        scheduler.issue_dispatch("start")
        checkpoint = self._checkpoint(context, authority, plan)
        binding = self._binding(checkpoint, scheduler, budget, revocations)

        budget.state["steps_used"] = 0
        with self.assertRaisesRegex(
            RuntimeDispatchRecoveryError,
            "LIVE_BUDGET_COUNTER_ROLLBACK_DETECTED",
        ):
            RuntimeDispatchRecovery.evaluate(
                binding=binding,
                checkpoint=checkpoint,
                task_context=context,
                plan=plan,
                parent_authority=authority,
                budget_guard=budget,
                revocation_guard=revocations,
            )

        budget.state["steps_used"] = 1
        budget.state["deadline_at"] = "2026-09-08T05:00:00Z"
        with self.assertRaisesRegex(
            RuntimeDispatchRecoveryError,
            "LIVE_BUDGET_IMMUTABLE_STATE_MISMATCH",
        ):
            RuntimeDispatchRecovery.evaluate(
                binding=binding,
                checkpoint=checkpoint,
                task_context=context,
                plan=plan,
                parent_authority=authority,
                budget_guard=budget,
                revocation_guard=revocations,
            )

    def test_revocation_is_monotonic_and_new_revocation_is_reported(self):
        context, authority, plan, scheduler, budget, revocations = self._runtime()
        captured = revocations.revoke(plan.task_id, "read_file", 1)
        checkpoint = self._checkpoint(context, authority, plan)
        binding = self._binding(checkpoint, scheduler, budget, revocations)

        revocations.rows.clear()
        with self.assertRaisesRegex(
            RuntimeDispatchRecoveryError,
            "LIVE_REVOCATION_ROLLBACK_DETECTED",
        ):
            RuntimeDispatchRecovery.evaluate(
                binding=binding,
                checkpoint=checkpoint,
                task_context=context,
                plan=plan,
                parent_authority=authority,
                budget_guard=budget,
                revocation_guard=revocations,
            )

        revocations.rows.append(captured)
        revocations.revoke(plan.task_id, "search_docs", 2)
        decision = RuntimeDispatchRecovery.evaluate(
            binding=binding,
            checkpoint=checkpoint,
            task_context=context,
            plan=plan,
            parent_authority=authority,
            budget_guard=budget,
            revocation_guard=revocations,
        )
        self.assertEqual(decision.status, "RECOVERABLE")
        self.assertEqual(
            decision.reason_code,
            "DISPATCH_RECOVERY_REVALIDATED_WITH_NEW_REVOCATIONS",
        )
        self.assertEqual(decision.newly_revoked_capabilities, ("search_docs",))

    def test_cancelled_scheduler_remains_blocked_after_recovery(self):
        context, authority, plan, scheduler, budget, revocations = self._runtime()
        scheduler.cancel(reason_code="operator requested stop")
        checkpoint = self._checkpoint(context, authority, plan)
        binding = self._binding(checkpoint, scheduler, budget, revocations)

        decision = RuntimeDispatchRecovery.evaluate(
            binding=binding,
            checkpoint=checkpoint,
            task_context=context,
            plan=plan,
            parent_authority=authority,
            budget_guard=budget,
            revocation_guard=revocations,
        )
        self.assertEqual(decision.status, "BLOCKED")
        self.assertEqual(decision.reason_code, "SCHEDULER_CANCELLED_AT_CHECKPOINT")

    def test_binding_rejects_scheduler_state_that_disagrees_with_checkpoint(self):
        context, authority, plan, scheduler, budget, revocations = self._runtime()
        checkpoint = self._checkpoint(context, authority, plan)
        snapshot = scheduler.snapshot()
        snapshot["observations"] = ["sha256:" + "0" * 64]

        with self.assertRaisesRegex(
            RuntimeDispatchRecoveryError,
            "SCHEDULER_OBSERVATION_STATE_MISMATCH",
        ):
            RuntimeDispatchRecoveryBindingBuilder.build(
                checkpoint=checkpoint,
                scheduler_snapshot=snapshot,
                budget_snapshot=budget.snapshot(),
                revocations=revocations.list_for_task(plan.task_id),
            )

    def test_inactive_live_budget_blocks_quiescent_recovery(self):
        context, authority, plan, scheduler, budget, revocations = self._runtime()
        checkpoint = self._checkpoint(context, authority, plan)
        binding = self._binding(checkpoint, scheduler, budget, revocations)
        budget.active = False

        decision = RuntimeDispatchRecovery.evaluate(
            binding=binding,
            checkpoint=checkpoint,
            task_context=context,
            plan=plan,
            parent_authority=authority,
            budget_guard=budget,
            revocation_guard=revocations,
        )
        self.assertEqual(decision.status, "BLOCKED")
        self.assertEqual(decision.reason_code, "LIVE_BUDGET_NOT_ACTIVE")


if __name__ == "__main__":
    unittest.main()
