import unittest

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.execution_budget import ExecutionBudgetExceeded
from three_agent.execution_observation import ExecutionObservationBuilder
from three_agent.execution_plan import ExecutionNodeBinding, ExecutionPlanBuilder
from three_agent.execution_scheduler import ExecutionScheduler, ExecutionSchedulerError
from three_agent.harness_acceptance import AcceptanceContract, AcceptanceCriterion
from three_agent.harness_task_compiler import HarnessTaskCompiler
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
    def __init__(self):
        self.revoked = set()

    def is_revoked(self, task_id, capability):
        return (task_id, capability) in self.revoked


def fork_join_workflow(*, approval=False):
    return {
        "title": "Bounded runtime dependency scheduler",
        "objective": "Fan out two evidence reads and deterministically join their observations.",
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
                "depends_on": ["lane_b", "lane_a"],
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


class ExecutionSchedulerTests(unittest.TestCase):
    @staticmethod
    def _runtime(*, approval=False, max_concurrency=2):
        task_id = "TASK-SCHED-1"
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
                    criterion_id="scheduler",
                    statement="Run a bounded dependency-aware scheduler",
                    verifier="unit_test",
                ),
            ),
        )
        canonical = HarnessTaskCompiler().compile(
            user_prompt="Schedule the canonical runtime plan.",
            task_contract=contract,
            acceptance_contract=acceptance,
        )
        context = TaskContextBuilder.build(
            task_contract=contract,
            canonical_task=canonical,
            session_id="SESSION-SCHED-1",
            trace_id="TRACE-SCHED-1",
            actor_id="ACTOR-SCHED-1",
            purpose="runtime dependency scheduling",
            project_id="PROJECT-1",
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
        revocations = FakeRevocationGuard()
        scheduler = ExecutionScheduler(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            budget_guard=budget,
            revocation_guard=revocations,
            max_concurrency=max_concurrency,
        )
        return authority, plan, scheduler, budget, revocations

    @staticmethod
    def _observe(plan, authority, node_id, status="SUCCEEDED"):
        kwargs = {}
        if status == "FAILED":
            kwargs["error_class"] = "TOOL_ERROR"
        return ExecutionObservationBuilder.build(
            plan=plan,
            node_id=node_id,
            parent_authority=authority,
            status=status,
            started_at="2026-09-08T02:00:00Z",
            finished_at="2026-09-08T02:00:01Z",
            normalized_output={"node": node_id, "status": status},
            **kwargs,
        )

    def _complete(self, scheduler, plan, authority, node_id, status="SUCCEEDED", approval=False):
        scheduler.issue_dispatch(node_id, approval_granted=approval)
        observation = self._observe(plan, authority, node_id, status=status)
        return scheduler.accept_observation(observation)

    def test_ready_set_is_dependency_aware_bounded_and_deterministic(self):
        authority, plan, scheduler, budget, _ = self._runtime(max_concurrency=2)
        self.assertEqual(scheduler.ready_node_ids(), ("start",))
        self._complete(scheduler, plan, authority, "start")

        self.assertEqual(scheduler.ready_node_ids(), ("lane_a", "lane_b"))
        tickets = scheduler.issue_ready()
        self.assertEqual(tuple(ticket.node_id for ticket in tickets), ("lane_a", "lane_b"))
        self.assertEqual(scheduler.ready_node_ids(), ())
        self.assertEqual(budget.steps, 3)

    def test_fan_in_uses_declared_dependency_order_not_completion_order(self):
        authority, plan, scheduler, _, _ = self._runtime()
        self._complete(scheduler, plan, authority, "start")
        scheduler.issue_dispatch("lane_a")
        scheduler.issue_dispatch("lane_b")

        observation_a = self._observe(plan, authority, "lane_a")
        observation_b = self._observe(plan, authority, "lane_b")
        scheduler.accept_observation(observation_a)
        scheduler.accept_observation(observation_b)

        fan_in = scheduler.fan_in("join")
        self.assertEqual(tuple(row.node_id for row in fan_in), ("lane_b", "lane_a"))
        self.assertEqual(scheduler.ready_node_ids(), ("join",))

    def test_partial_or_failed_dependency_never_unlocks_downstream(self):
        for terminal in ("PARTIAL", "FAILED", "CANCELLED"):
            with self.subTest(terminal=terminal):
                authority, plan, scheduler, _, _ = self._runtime()
                self._complete(scheduler, plan, authority, "start")
                self._complete(scheduler, plan, authority, "lane_a", status="SUCCEEDED")
                self._complete(scheduler, plan, authority, "lane_b", status=terminal)
                self.assertNotIn("join", scheduler.ready_node_ids())
                self.assertEqual(
                    scheduler.blocked_reason("join"),
                    f"DEPENDENCY_{terminal}:lane_b",
                )
                with self.assertRaisesRegex(
                    ExecutionSchedulerError,
                    "SCHEDULER_DEPENDENCY_NOT_SUCCEEDED",
                ):
                    scheduler.fan_in("join")

    def test_revocation_is_rechecked_immediately_before_dispatch(self):
        authority, plan, scheduler, _, revocations = self._runtime()
        self._complete(scheduler, plan, authority, "start")
        revocations.revoked.add((plan.task_id, "read_file"))

        with self.assertRaisesRegex(
            ExecutionSchedulerError,
            "SCHEDULER_CAPABILITY_REVOKED:lane_a:read_file",
        ):
            scheduler.issue_dispatch("lane_a")
        self.assertEqual(scheduler.ready_node_ids(), ("lane_a", "lane_b"))

    def test_persistent_budget_deadline_is_rechecked_before_dispatch(self):
        authority, plan, scheduler, budget, _ = self._runtime()
        self._complete(scheduler, plan, authority, "start")
        budget.active = False

        with self.assertRaisesRegex(
            ExecutionSchedulerError,
            "SCHEDULER_BUDGET_DENIED:TASK_WALL_TIME_BUDGET_EXHAUSTED",
        ):
            scheduler.issue_dispatch("lane_a")

    def test_approval_is_fail_closed_at_dispatch_boundary(self):
        authority, plan, scheduler, _, _ = self._runtime(approval=True)
        self._complete(scheduler, plan, authority, "start")
        self._complete(scheduler, plan, authority, "lane_a")
        self._complete(scheduler, plan, authority, "lane_b")

        self.assertNotIn("join", scheduler.ready_node_ids())
        self.assertEqual(
            scheduler.ready_node_ids(approved_nodes=frozenset({"join"})),
            ("join",),
        )
        with self.assertRaisesRegex(ExecutionSchedulerError, "NODE_APPROVAL_REQUIRED:join"):
            scheduler.issue_dispatch("join")
        ticket = scheduler.issue_dispatch("join", approval_granted=True)
        self.assertEqual(ticket.node_id, "join")

    def test_only_in_flight_canonical_observation_is_accepted(self):
        authority, plan, scheduler, _, _ = self._runtime()
        self._complete(scheduler, plan, authority, "start")
        scheduler.issue_dispatch("lane_a")
        forged_route = self._observe(plan, authority, "lane_b")

        with self.assertRaisesRegex(
            ExecutionSchedulerError,
            "OBSERVATION_NODE_NOT_IN_FLIGHT:lane_b",
        ):
            scheduler.accept_observation(forged_route)

        accepted = scheduler.accept_observation(self._observe(plan, authority, "lane_a"))
        self.assertEqual(accepted.node_id, "lane_a")
        with self.assertRaisesRegex(ExecutionSchedulerError, "OBSERVATION_NODE_NOT_IN_FLIGHT"):
            scheduler.accept_observation(accepted)

    def test_cancellation_stops_new_dispatch_but_preserves_inflight_audit(self):
        authority, plan, scheduler, _, _ = self._runtime()
        self._complete(scheduler, plan, authority, "start")
        scheduler.issue_dispatch("lane_a")
        scheduler.cancel(reason_code="OPERATOR_CANCELLED")

        self.assertTrue(scheduler.cancelled)
        self.assertEqual(scheduler.ready_node_ids(), ())
        with self.assertRaisesRegex(ExecutionSchedulerError, "SCHEDULER_CANCELLED"):
            scheduler.issue_dispatch("lane_b")

        accepted = scheduler.accept_observation(self._observe(plan, authority, "lane_a"))
        self.assertEqual(accepted.status, "SUCCEEDED")
        self.assertEqual(scheduler.ready_node_ids(), ())
        snapshot = scheduler.snapshot()
        self.assertTrue(snapshot["cancelled"])
        self.assertEqual(snapshot["cancellation_reason"], "OPERATOR_CANCELLED")

    def test_backpressure_and_duplicate_dispatch_fail_closed(self):
        authority, plan, scheduler, _, _ = self._runtime(max_concurrency=1)
        self._complete(scheduler, plan, authority, "start")
        scheduler.issue_dispatch("lane_a")

        with self.assertRaisesRegex(ExecutionSchedulerError, "NODE_ALREADY_IN_FLIGHT:lane_a"):
            scheduler.issue_dispatch("lane_a")
        with self.assertRaisesRegex(ExecutionSchedulerError, "SCHEDULER_BACKPRESSURE"):
            scheduler.issue_dispatch("lane_b")

    def test_admission_decision_is_runtime_scheduler_source_of_truth(self):
        _, _, scheduler, _, _ = self._runtime()
        decision = scheduler.admission_decision()
        self.assertEqual(decision.ready_node_ids, ("start",))
        self.assertEqual(scheduler.ready_node_ids(), decision.ready_node_ids)
        self.assertTrue(decision.fingerprint.startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
