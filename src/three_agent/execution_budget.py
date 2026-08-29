from __future__ import annotations

from dataclasses import dataclass

from .store import TaskStore


class ExecutionBudgetExceeded(RuntimeError):
    """A task action would exceed the immutable persistent execution budget."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


_BUDGET_EXHAUSTION_CODES = {
    "TASK_STEP_BUDGET_EXHAUSTED",
    "TASK_TOOL_CALL_BUDGET_EXHAUSTED",
    "TASK_WALL_TIME_BUDGET_EXHAUSTED",
    "MODEL_RETRY_BUDGET_EXHAUSTED",
    "MODEL_ESCALATION_BUDGET_EXHAUSTED",
}


@dataclass(frozen=True)
class TaskExecutionBudgetState:
    """Persistent task-wide execution budget backed by TaskStore/SQLite.

    All limits originate from the already-bound immutable TaskContract. Counters
    and the wall-time deadline survive stage changes and process restarts.
    Reservations are atomic so one failed dimension cannot partially consume
    another dimension.
    """

    store: TaskStore
    task_id: str
    max_steps: int
    max_tool_calls: int
    max_model_retries: int
    max_model_escalations: int
    max_wall_time_ms: int
    deadline_at: str

    @classmethod
    def from_bound_contract(
        cls,
        store: TaskStore,
        task_id: str,
    ) -> "TaskExecutionBudgetState":
        row = store.bind_task_execution_budget(task_id)
        return cls(
            store=store,
            task_id=str(task_id),
            max_steps=int(row["max_steps"]),
            max_tool_calls=int(row["max_tool_calls"]),
            max_model_retries=int(row["max_retries"]),
            max_model_escalations=int(row["max_escalations"]),
            max_wall_time_ms=int(row["max_wall_time_ms"]),
            deadline_at=str(row["deadline_at"]),
        )

    def reserve(
        self,
        *,
        steps: int = 0,
        tool_calls: int = 0,
        retries: int = 0,
        escalations: int = 0,
    ) -> None:
        try:
            self.store.reserve_task_execution_budget(
                self.task_id,
                steps=steps,
                tool_calls=tool_calls,
                retries=retries,
                escalations=escalations,
            )
        except ValueError as exc:
            code = str(exc)
            if code in _BUDGET_EXHAUSTION_CODES:
                raise ExecutionBudgetExceeded(code) from exc
            raise

    def assert_active(self) -> None:
        """Fail closed after the immutable wall-time deadline, without consuming counters."""
        self.reserve()

    def snapshot(self) -> dict[str, int | str]:
        row = self.store.task_execution_budget_for_task(self.task_id)
        return {
            "schema_version": "workspace-task-execution-budget-state/v2",
            "task_id": self.task_id,
            "max_steps": int(row["max_steps"]),
            "max_tool_calls": int(row["max_tool_calls"]),
            "max_model_retries": int(row["max_retries"]),
            "max_model_escalations": int(row["max_escalations"]),
            "max_wall_time_ms": int(row["max_wall_time_ms"]),
            "steps_used": int(row["steps_used"]),
            "tool_calls_used": int(row["tool_calls_used"]),
            "model_retries_used": int(row["retries_used"]),
            "model_escalations_used": int(row["escalations_used"]),
            "deadline_at": str(row["deadline_at"]),
        }
