from __future__ import annotations

from three_agent.execution_budget import TaskExecutionBudgetState
from three_agent.workflow_state_machine_v4_budgeted import BudgetedWorkflowStateMachineV4Controller
from test_workflow_state_machine_v4 import WorkflowStateMachineV4Tests


class BudgetedWorkflowStateMachineV4Tests(WorkflowStateMachineV4Tests):
    def setUp(self):
        super().setUp()
        self.controller = BudgetedWorkflowStateMachineV4Controller(self.orchestrator)

    def test_parent_step_cap_is_shared_across_both_parallel_children(self):
        prepared = self._prepare()
        parent_budget = TaskExecutionBudgetState.from_bound_contract(
            self.store,
            prepared["task_id"],
        )
        parent_budget.reserve(steps=4)

        result = self._start(prepared)

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["terminal_reason"], "validation_failed")
        self.assertEqual(result["parallel_region"]["outcome"], "failed")
        parent_state = parent_budget.snapshot()
        self.assertEqual(parent_state["steps_used"], parent_state["max_steps"])

        child_steps = sorted(
            TaskExecutionBudgetState.from_bound_contract(
                self.store,
                branch["task_id"],
            ).snapshot()["steps_used"]
            for branch in result["parallel_region"]["branches"]
        )
        self.assertEqual(child_steps, [1, 2])
        self.assertEqual(sum(child_steps), 3)
        self.assertEqual(self.research.calls, 2)
        self.assertEqual(self.presentation.calls, 1)
        self.assertEqual(self.daily.calls, 0)


if __name__ == "__main__":
    import unittest

    unittest.main()
