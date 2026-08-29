from __future__ import annotations

from dataclasses import dataclass

from .store import TaskStore


class ExecutionBudgetExceeded(RuntimeError):
    """A model retry/escalation would exceed the immutable task budget."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class TaskExecutionBudgetState:
    """Task-wide retry/escalation budget backed by persistent TaskStore state.

    The bound TaskContract is authoritative. This wrapper carries only the store
    and task identity; every reservation is performed atomically in SQLite, so
    usage survives stage changes and process restarts and cannot be reset by a
    model/client instance.
    """

    store: TaskStore
    task_id: str
    max_model_retries: int
    max_model_escalations: int

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
            max_model_retries=int(row["max_retries"]),
            max_model_escalations=int(row["max_escalations"]),
        )

    def reserve(self, *, retries: int = 0, escalations: int = 0) -> None:
        try:
            self.store.reserve_task_execution_budget(
                self.task_id,
                retries=retries,
                escalations=escalations,
            )
        except ValueError as exc:
            code = str(exc)
            if code in {
                "MODEL_RETRY_BUDGET_EXHAUSTED",
                "MODEL_ESCALATION_BUDGET_EXHAUSTED",
            }:
                raise ExecutionBudgetExceeded(code) from exc
            raise

    def snapshot(self) -> dict[str, int | str]:
        row = self.store.task_execution_budget_for_task(self.task_id)
        return {
            "schema_version": "workspace-task-execution-budget-state/v1",
            "task_id": self.task_id,
            "max_model_retries": int(row["max_retries"]),
            "max_model_escalations": int(row["max_escalations"]),
            "model_retries_used": int(row["retries_used"]),
            "model_escalations_used": int(row["escalations_used"]),
        }
