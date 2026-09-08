import inspect
import unittest
from datetime import datetime, timezone

from three_agent import capability_authority
from three_agent import execution_observation
from three_agent import execution_plan
from three_agent import runtime_checkpoint
from three_agent import runtime_scheduler
from three_agent import task_context
from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.execution_observation import ExecutionObservationBuilder
from three_agent.execution_plan import ExecutionPlanBuilder
from three_agent.harness_acceptance import AcceptanceContract, AcceptanceCriterion
from three_agent.harness_task_compiler import HarnessTaskCompiler
from three_agent.runtime_checkpoint import RuntimeCheckpointBuilder, RuntimeRecovery
from three_agent.runtime_scheduler import RuntimeScheduler
from three_agent.task_context import TaskContextBuilder
from three_agent.task_contract import TaskContractCompiler


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
                    "action": "analysis",
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
            runtime_checkpoint,
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
