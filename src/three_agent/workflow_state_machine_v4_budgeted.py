from __future__ import annotations

from contextvars import ContextVar
from typing import Any

from .execution_budget import TaskExecutionBudgetState
from .linked_execution_budget import LinkedTaskExecutionBudgetState
from .model_authority import TaskModelAuthority
from .workflow_state_machine import WorkflowStateError
from .workflow_state_machine_v4 import WorkflowStateMachineV4Controller


_ACTIVE_PARENT_BUDGET: ContextVar[TaskExecutionBudgetState | None] = ContextVar(
    "workspace_v4_parallel_parent_budget",
    default=None,
)


class BudgetedWorkflowStateMachineV4Controller(WorkflowStateMachineV4Controller):
    """Production V4 controller with aggregate parent budget enforcement.

    The base V4 state machine owns graph admission, child-task isolation and join
    semantics. This production controller strengthens only the execution-budget
    boundary: every child reservation is atomically charged to the child budget
    and the immutable parent workflow budget.
    """

    def _run_parallel_lane(
        self,
        *,
        parent_state: dict[str, Any],
        research_node: dict[str, Any],
        presentation_node: dict[str, Any],
        child_task_id: str,
    ) -> dict[str, Any]:
        parent_task_id = str(parent_state.get("task_id") or "").strip()
        if not parent_task_id:
            raise WorkflowStateError("parallel parent task identity is missing")
        parent_budget = TaskExecutionBudgetState.from_bound_contract(
            self.store,
            parent_task_id,
        )
        token = _ACTIVE_PARENT_BUDGET.set(parent_budget)
        try:
            return super()._run_parallel_lane(
                parent_state=parent_state,
                research_node=research_node,
                presentation_node=presentation_node,
                child_task_id=child_task_id,
            )
        finally:
            _ACTIVE_PARENT_BUDGET.reset(token)

    def _child_runtime(
        self,
        task_id: str,
    ) -> tuple[LinkedTaskExecutionBudgetState, TaskModelAuthority]:
        parent_budget = _ACTIVE_PARENT_BUDGET.get()
        if parent_budget is None:
            raise WorkflowStateError("parallel aggregate parent budget is not bound")
        child_budget, authority = super()._child_runtime(task_id)
        linked = LinkedTaskExecutionBudgetState.from_states(parent_budget, child_budget)
        return linked, authority
