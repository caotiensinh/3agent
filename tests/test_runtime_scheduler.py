import unittest
from dataclasses import replace

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.execution_observation import ExecutionObservationBuilder
from three_agent.execution_plan import ExecutionPlanBuilder
from three_agent.harness_acceptance import AcceptanceContract, AcceptanceCriterion
from three_agent.harness_task_compiler import HarnessTaskCompiler
from three_agent.runtime_scheduler import RuntimeScheduler, RuntimeSchedulerError
from three_agent.task_context import TaskContextBuilder
from three_agent.task_contract import TaskContractCompiler


def sample_workflow():
    return {
        "title": "Runtime scheduler",
        "objective": "Schedule canonical nodes without executing them.",
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
                "id": "research",
                "label": "Collect evidence",
                "kind": "agent",
                "action": "research",
                "depends_on": ["start"],
                "condition": "",
                "approval_required": False,
            },
            {
                "id": "approve",
                "label": "Human approval",
                "kind": "approval",
                "action": "human_approval",
                "depends_on": ["research"],
                "condition": "evidence accepted",
                "approval_required": True,
            },
            {
                "id": "done",
                "label": "Return result",
                "kind": "output",
                "action": "output",
                "depends_on": ["approve"],
                "condition": "",
                "approval_required": False,
            },
        ],
        "outputs": ["Bounded result"],
        "warnings": [],
    }


class RuntimeSchedulerTests(unittest.TestCase):
    @staticmethod
    def _runtime():
        task_id = "TASK-SCHED-1"
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
                    criterion_id="result",
                    statement="Produce a deterministic scheduling decision",
                    verifier="unit_test",
                ),
            ),
        )
        canonical = HarnessTaskCompiler().compile(
            user_prompt="Schedule canonical runtime nodes.",
            task_contract=contract,
            acceptance_contract=acceptance,
        )
        context = TaskContextBuilder.build(
            task_contract=contract,
            canonical_task=canonical,
            session_id="SESSION-SCHED-1",
            trace_id="TRACE-SCHED-1",
            actor_id="ACTOR-SCHED-1",
            purpose="runtime scheduler admission",
            project_id="PROJECT-1",
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        plan = ExecutionPlanBuilder.build(
            task_context=context,
            parent_authority=authority,
            workflow_contract=sample_workflow(),
        )
        return context, authority, plan

    @staticmethod
    def _observation(plan, authority, node_id, status, second, *, error_class=None):
        return ExecutionObservationBuilder.build(
            plan=plan,
            node_id=node_id,
            parent_authority=authority,
            status=status,
            started_at=f"2026-09-08T01:00:{second:02d}Z",
            finished_at=f"2026-09-08T01:00:{second:02d}Z",
            error_class=error_class,
        )

    def test_initial_decision_only_admits_entry_node(self):
        context, authority, plan = self._runtime()
        decision = RuntimeScheduler.evaluate(
            task_context=context,
            plan=plan,
            parent_authority=authority,
        )
        self.assertEqual(decision.status, "READY")
        self.assertEqual(decision.ready_node_ids, ("start",))
        self.assertEqual(decision.waiting_node_ids, ("research", "approve", "done"))
        self.assertEqual(decision.blocked_node_ids, ())
        self.assertTrue(decision.fingerprint.startswith("sha256:"))

    def test_success_observations_advance_in_plan_order(self):
        context, authority, plan = self._runtime()
        start = self._observation(plan, authority, "start", "SUCCEEDED", 0)
        first = RuntimeScheduler.evaluate(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(start,),
        )
        self.assertEqual(first.ready_node_ids, ("research",))

        research = self._observation(plan, authority, "research", "SUCCEEDED", 1)
        approval_wait = RuntimeScheduler.evaluate(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(research, start),
        )
        self.assertEqual(approval_wait.status, "BLOCKED")
        self.assertEqual(approval_wait.blocked_node_ids, ("approve", "done"))

        approved = RuntimeScheduler.evaluate(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(start, research),
            approved_node_ids=("approve",),
        )
        self.assertEqual(approved.status, "READY")
        self.assertEqual(approved.ready_node_ids, ("approve",))

    def test_failed_dependency_blocks_descendants_without_reexecution(self):
        context, authority, plan = self._runtime()
        start = self._observation(plan, authority, "start", "FAILED", 0, error_class="TOOL_ERROR")
        decision = RuntimeScheduler.evaluate(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(start,),
        )
        self.assertEqual(decision.status, "BLOCKED")
        self.assertEqual(decision.ready_node_ids, ())
        self.assertEqual(decision.blocked_node_ids, ("research", "approve", "done"))
        self.assertEqual(decision.terminal_node_ids, ("start",))

    def test_partial_observation_requires_reconciliation_and_is_not_auto_replayed(self):
        context, authority, plan = self._runtime()
        partial = self._observation(plan, authority, "start", "PARTIAL", 0)
        decision = RuntimeScheduler.evaluate(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(partial,),
        )
        self.assertEqual(decision.status, "WAITING")
        self.assertNotIn("start", decision.ready_node_ids)
        start_record = next(record for record in decision.records if record.node_id == "start")
        self.assertEqual(start_record.state, "WAITING")
        self.assertEqual(
            start_record.reason_code,
            "PARTIAL_OBSERVATION_REQUIRES_RECONCILIATION",
        )

    def test_exact_duplicate_observation_is_idempotent_but_two_terminal_results_fail_closed(self):
        context, authority, plan = self._runtime()
        start = self._observation(plan, authority, "start", "SUCCEEDED", 0)
        decision = RuntimeScheduler.evaluate(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(start, start),
        )
        self.assertEqual(decision.ready_node_ids, ("research",))

        failed = self._observation(
            plan,
            authority,
            "start",
            "FAILED",
            1,
            error_class="TOOL_ERROR",
        )
        with self.assertRaisesRegex(
            RuntimeSchedulerError,
            "SCHEDULER_MULTIPLE_TERMINAL_OBSERVATIONS:start",
        ):
            RuntimeScheduler.evaluate(
                task_context=context,
                plan=plan,
                parent_authority=authority,
                observations=(start, failed),
            )

    def test_tampered_or_cross_context_observation_is_rejected(self):
        context, authority, plan = self._runtime()
        start = self._observation(plan, authority, "start", "SUCCEEDED", 0)
        tampered = replace(start, plan_fingerprint="sha256:" + "0" * 64)
        with self.assertRaisesRegex(
            RuntimeSchedulerError,
            "SCHEDULER_OBSERVATION_REVALIDATION_FAILED",
        ):
            RuntimeScheduler.evaluate(
                task_context=context,
                plan=plan,
                parent_authority=authority,
                observations=(tampered,),
            )

        changed_context = context.derive(evidence_refs=("evidence:new",))
        with self.assertRaisesRegex(
            RuntimeSchedulerError,
            "SCHEDULER_TASK_CONTEXT_FINGERPRINT_MISMATCH",
        ):
            RuntimeScheduler.evaluate(
                task_context=changed_context,
                plan=plan,
                parent_authority=authority,
            )

    def test_all_success_is_complete_and_observation_order_is_deterministic(self):
        context, authority, plan = self._runtime()
        observations = tuple(
            self._observation(plan, authority, node_id, "SUCCEEDED", index)
            for index, node_id in enumerate(("start", "research", "approve", "done"))
        )
        first = RuntimeScheduler.evaluate(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=observations,
            approved_node_ids=("approve",),
        )
        second = RuntimeScheduler.evaluate(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=tuple(reversed(observations)),
            approved_node_ids=("approve",),
        )
        self.assertEqual(first.status, "COMPLETE")
        self.assertEqual(first.ready_node_ids, ())
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.canonical_dict(), second.canonical_dict())


if __name__ == "__main__":
    unittest.main()
