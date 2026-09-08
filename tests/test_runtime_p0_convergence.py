import inspect
import unittest
from datetime import datetime, timezone

from three_agent import capability_authority
from three_agent import execution_observation
from three_agent import execution_plan
from three_agent import execution_scheduler
from three_agent import runtime_checkpoint
from three_agent import runtime_dispatch_recovery
from three_agent import runtime_scheduler
from three_agent import task_context
from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.capability_revocation import CapabilityRevocation
from three_agent.execution_budget import ExecutionBudgetExceeded
from three_agent.execution_observation import ExecutionObservationBuilder
from three_agent.execution_plan import ExecutionNodeBinding, ExecutionPlanBuilder
from three_agent.execution_scheduler import ExecutionScheduler, ExecutionSchedulerError
from three_agent.harness_acceptance import AcceptanceContract, AcceptanceCriterion
from three_agent.harness_task_compiler import HarnessTaskCompiler
from three_agent.runtime_checkpoint import RuntimeCheckpointBuilder, RuntimeRecovery
from three_agent.runtime_dispatch_recovery import (
    RuntimeDispatchRecovery,
    RuntimeDispatchRecoveryBindingBuilder,
)
from three_agent.runtime_scheduler import RuntimeScheduler
from three_agent.task_context import TaskContextBuilder, TaskResourceBudget
from three_agent.task_contract import TaskContractCompiler


class _GatePersistentBudget:
    def __init__(self, task_id):
        self.active = True
        self.state = {
            "schema_version": "workspace-task-execution-budget-state/v2",
            "task_id": task_id,
            "max_steps": 8,
            "max_tool_calls": 4,
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
                raise ExecutionBudgetExceeded("TASK_EXECUTION_BUDGET_EXHAUSTED")
        for key, delta in updates.items():
            self.state[key] += delta

    def snapshot(self):
        return dict(self.state)


class _GatePersistentRevocations:
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


class RuntimeP0ConvergenceGateTests(unittest.TestCase):
    @staticmethod
    def _workflow():
        return {
            "title": "P0 runtime convergence gate",
            "objective": "Verify the canonical runtime chain without executing tools.",
            "trigger": "manual",
            "risk_level": "medium",
            "data_class": "internal",
            "nodes": [
                {
                    "id": "collect",
                    "label": "Collect",
                    "kind": "input",
                    "action": "input",
                    "depends_on": [],
                    "condition": "",
                    "approval_required": False,
                },
                {
                    "id": "analyze",
                    "label": "Analyze",
                    "kind": "agent",
                    "action": "research",
                    "depends_on": ["collect"],
                    "condition": "",
                    "approval_required": False,
                },
                {
                    "id": "approve",
                    "label": "Approve",
                    "kind": "approval",
                    "action": "human_approval",
                    "depends_on": ["analyze"],
                    "condition": "analysis accepted",
                    "approval_required": True,
                },
                {
                    "id": "report",
                    "label": "Report",
                    "kind": "output",
                    "action": "output",
                    "depends_on": ["approve"],
                    "condition": "",
                    "approval_required": False,
                },
            ],
            "outputs": ["Canonical result"],
            "warnings": [],
        }

    @classmethod
    def _runtime(cls):
        task_id = "TASK-P0-GATE-1"
        contract = TaskContractCompiler().compile(
            task_id=task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level="medium",
            allowed_sources=("repo", "evidence"),
            allowed_tools=("search_docs", "read_file"),
            write_scope="none",
        )
        acceptance = AcceptanceContract(
            task_id=task_id,
            criteria=(
                AcceptanceCriterion(
                    criterion_id="p0",
                    statement="Canonical runtime remains bounded and fail closed",
                    verifier="unit_test",
                ),
            ),
        )
        canonical = HarnessTaskCompiler().compile(
            user_prompt="Verify the P0 runtime chain.",
            task_contract=contract,
            acceptance_contract=acceptance,
        )
        context = TaskContextBuilder.build(
            task_contract=contract,
            canonical_task=canonical,
            session_id="SESSION-P0-GATE-1",
            trace_id="TRACE-P0-GATE-1",
            actor_id="ACTOR-P0-GATE-1",
            purpose="P0 convergence verification",
            project_id="PROJECT-P0",
            created_at=datetime(2026, 9, 8, 2, 0, tzinfo=timezone.utc),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        plan = ExecutionPlanBuilder.build(
            task_context=context,
            parent_authority=authority,
            workflow_contract=cls._workflow(),
            node_bindings={
                "analyze": ExecutionNodeBinding(
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
        return context, authority, plan

    @staticmethod
    def _observation(plan, authority, node_id, status, second, *, error_class=None):
        return ExecutionObservationBuilder.build(
            plan=plan,
            node_id=node_id,
            parent_authority=authority,
            status=status,
            started_at=f"2026-09-08T02:00:{second:02d}Z",
            finished_at=f"2026-09-08T02:00:{second:02d}Z",
            error_class=error_class,
        )

    @staticmethod
    def _stateful_runtime(context, authority, plan):
        budget = _GatePersistentBudget(plan.task_id)
        revocations = _GatePersistentRevocations()
        scheduler = ExecutionScheduler(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            budget_guard=budget,
            revocation_guard=revocations,
            max_concurrency=2,
        )
        return scheduler, budget, revocations

    def test_authority_context_plan_observation_scheduler_checkpoint_chain(self):
        context, authority, plan = self._runtime()
        self.assertEqual(context.authority_fingerprint, authority.fingerprint)
        self.assertEqual(plan.parent_authority_fingerprint, authority.fingerprint)
        self.assertEqual(plan.task_context_fingerprint, context.fingerprint)
        self.assertFalse(plan.execution_authorized)
        self.assertEqual(plan.execution_mode, "plan_only")

        initial = RuntimeScheduler.evaluate(
            task_context=context,
            plan=plan,
            parent_authority=authority,
        )
        self.assertEqual(initial.ready_node_ids, ("collect",))

        collected = self._observation(plan, authority, "collect", "SUCCEEDED", 0)
        decision = RuntimeScheduler.evaluate(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(collected,),
        )
        self.assertEqual(decision.ready_node_ids, ("analyze",))

        checkpoint = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(collected,),
            captured_at=datetime(2026, 9, 8, 2, 5, tzinfo=timezone.utc),
        )
        recovery = RuntimeRecovery.evaluate(
            checkpoint=checkpoint,
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(collected,),
        )
        self.assertEqual(recovery.status, "RECOVERABLE")
        self.assertEqual(recovery.scheduling_decision.fingerprint, decision.fingerprint)
        self.assertEqual(recovery.scheduling_decision.ready_node_ids, ("analyze",))

    def test_stateful_dispatch_security_state_survives_checkpoint_recovery(self):
        context, authority, plan = self._runtime()
        scheduler, budget, revocations = self._stateful_runtime(context, authority, plan)

        scheduler.issue_dispatch("collect")
        collected = self._observation(plan, authority, "collect", "SUCCEEDED", 0)
        scheduler.accept_observation(collected)
        self.assertEqual(scheduler.ready_node_ids(), ("analyze",))

        revocations.revoke(plan.task_id, "read_file", 1)
        with self.assertRaisesRegex(
            ExecutionSchedulerError,
            "SCHEDULER_CAPABILITY_REVOKED:analyze:read_file",
        ):
            scheduler.issue_dispatch("analyze")

        checkpoint = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(collected,),
            captured_at=datetime(2026, 9, 8, 2, 5, tzinfo=timezone.utc),
        )
        binding = RuntimeDispatchRecoveryBindingBuilder.build(
            checkpoint=checkpoint,
            scheduler_snapshot=scheduler.snapshot(),
            budget_snapshot=budget.snapshot(),
            revocations=revocations.list_for_task(plan.task_id),
        )
        budget_before_recovery = budget.snapshot()

        recovery = RuntimeDispatchRecovery.evaluate(
            binding=binding,
            checkpoint=checkpoint,
            task_context=context,
            plan=plan,
            parent_authority=authority,
            budget_guard=budget,
            revocation_guard=revocations,
        )
        self.assertEqual(recovery.status, "RECOVERABLE")
        self.assertEqual(
            recovery.checkpoint_recovery.scheduling_decision.ready_node_ids,
            ("analyze",),
        )
        self.assertEqual(recovery.newly_revoked_capabilities, ())
        self.assertEqual(budget.snapshot(), budget_before_recovery)

    def test_inflight_dispatch_is_manual_reconciliation_across_full_chain(self):
        context, authority, plan = self._runtime()
        scheduler, budget, revocations = self._stateful_runtime(context, authority, plan)
        ticket = scheduler.issue_dispatch("collect")
        checkpoint = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            captured_at=datetime(2026, 9, 8, 2, 5, tzinfo=timezone.utc),
        )
        binding = RuntimeDispatchRecoveryBindingBuilder.build(
            checkpoint=checkpoint,
            scheduler_snapshot=scheduler.snapshot(),
            budget_snapshot=budget.snapshot(),
            revocations=revocations.list_for_task(plan.task_id),
        )
        budget_before_recovery = budget.snapshot()

        recovery = RuntimeDispatchRecovery.evaluate(
            binding=binding,
            checkpoint=checkpoint,
            task_context=context,
            plan=plan,
            parent_authority=authority,
            budget_guard=budget,
            revocation_guard=revocations,
        )
        self.assertEqual(recovery.status, "MANUAL_RECONCILIATION")
        self.assertEqual(
            recovery.reason_code,
            "IN_FLIGHT_DISPATCH_REQUIRES_MANUAL_RECONCILIATION",
        )
        self.assertEqual(recovery.manual_dispatch_fingerprints, (ticket.fingerprint,))
        self.assertEqual(budget.snapshot(), budget_before_recovery)

    def test_human_approval_cannot_be_inferred_from_successful_dependencies(self):
        context, authority, plan = self._runtime()
        collect = self._observation(plan, authority, "collect", "SUCCEEDED", 0)
        analyze = self._observation(plan, authority, "analyze", "SUCCEEDED", 1)
        blocked = RuntimeScheduler.evaluate(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(collect, analyze),
        )
        self.assertEqual(blocked.status, "BLOCKED")
        self.assertIn("approve", blocked.blocked_node_ids)
        self.assertNotIn("approve", blocked.ready_node_ids)

        approved = RuntimeScheduler.evaluate(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(collect, analyze),
            approved_node_ids=("approve",),
        )
        self.assertEqual(approved.ready_node_ids, ("approve",))

    def test_partial_execution_is_never_auto_replayed_after_recovery(self):
        context, authority, plan = self._runtime()
        partial = self._observation(plan, authority, "collect", "PARTIAL", 0)
        checkpoint = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(partial,),
            captured_at=datetime(2026, 9, 8, 2, 5, tzinfo=timezone.utc),
        )
        recovery = RuntimeRecovery.evaluate(
            checkpoint=checkpoint,
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(partial,),
        )
        self.assertEqual(recovery.status, "MANUAL_RECONCILIATION")
        self.assertEqual(recovery.manual_node_ids, ("collect",))
        self.assertNotIn("collect", recovery.scheduling_decision.ready_node_ids)

    def test_runtime_core_has_no_direct_process_or_network_execution_primitives(self):
        modules = (
            capability_authority,
            task_context,
            execution_plan,
            execution_observation,
            runtime_scheduler,
            execution_scheduler,
            runtime_checkpoint,
            runtime_dispatch_recovery,
        )
        forbidden = (
            "import subprocess",
            "from subprocess",
            "os.system(",
            "os.popen(",
            "import socket",
            "from socket",
            "import requests",
            "from requests",
            "import httpx",
            "from httpx",
            "urllib.request",
        )
        for module in modules:
            source = inspect.getsource(module)
            for token in forbidden:
                self.assertNotIn(token, source, f"{module.__name__} contains {token}")


if __name__ == "__main__":
    unittest.main()
