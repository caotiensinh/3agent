from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .execution_budget import ExecutionBudgetExceeded, TaskExecutionBudgetState
from .store import TZ, TaskStore


_BUDGET_EXHAUSTION_CODES = {
    "TASK_STEP_BUDGET_EXHAUSTED",
    "TASK_TOOL_CALL_BUDGET_EXHAUSTED",
    "TASK_WALL_TIME_BUDGET_EXHAUSTED",
    "MODEL_RETRY_BUDGET_EXHAUSTED",
    "MODEL_ESCALATION_BUDGET_EXHAUSTED",
}


def _delta(value: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be an integer >= 0")
    return value


def _project(row, *, steps: int, tool_calls: int, retries: int, escalations: int, now: datetime):
    try:
        deadline = datetime.fromisoformat(str(row["deadline_at"]))
    except ValueError as exc:
        raise ValueError("TASK_EXECUTION_BUDGET_DEADLINE_INVALID") from exc
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=TZ)
    if now >= deadline:
        raise ValueError("TASK_WALL_TIME_BUDGET_EXHAUSTED")

    projected = {
        "steps_used": int(row["steps_used"]) + steps,
        "tool_calls_used": int(row["tool_calls_used"]) + tool_calls,
        "retries_used": int(row["retries_used"]) + retries,
        "escalations_used": int(row["escalations_used"]) + escalations,
    }
    if projected["steps_used"] > int(row["max_steps"]):
        raise ValueError("TASK_STEP_BUDGET_EXHAUSTED")
    if projected["tool_calls_used"] > int(row["max_tool_calls"]):
        raise ValueError("TASK_TOOL_CALL_BUDGET_EXHAUSTED")
    if projected["retries_used"] > int(row["max_retries"]):
        raise ValueError("MODEL_RETRY_BUDGET_EXHAUSTED")
    if projected["escalations_used"] > int(row["max_escalations"]):
        raise ValueError("MODEL_ESCALATION_BUDGET_EXHAUSTED")
    return projected


@dataclass(frozen=True)
class LinkedTaskExecutionBudgetState:
    """Child-local budget linked atomically to one aggregate parent budget.

    The child retains its own immutable TaskContract and counters, but every
    reservation is also charged to the parent workflow budget in the same SQLite
    transaction. This prevents parallel fan-out from multiplying steps, tool calls,
    retries, or escalations beyond the authority granted to the parent task.
    """

    store: TaskStore
    task_id: str
    parent_task_id: str
    max_steps: int
    max_tool_calls: int
    max_model_retries: int
    max_model_escalations: int
    max_wall_time_ms: int
    deadline_at: str

    @classmethod
    def from_states(
        cls,
        parent: TaskExecutionBudgetState,
        child: TaskExecutionBudgetState,
    ) -> "LinkedTaskExecutionBudgetState":
        if parent.task_id == child.task_id:
            raise ValueError("linked execution budget requires distinct parent and child tasks")
        if parent.store.db_path.resolve() != child.store.db_path.resolve():
            raise ValueError("linked execution budgets must share one authoritative TaskStore")
        return cls(
            store=child.store,
            task_id=child.task_id,
            parent_task_id=parent.task_id,
            max_steps=child.max_steps,
            max_tool_calls=child.max_tool_calls,
            max_model_retries=child.max_model_retries,
            max_model_escalations=child.max_model_escalations,
            max_wall_time_ms=child.max_wall_time_ms,
            deadline_at=child.deadline_at,
        )

    def reserve(
        self,
        *,
        steps: int = 0,
        tool_calls: int = 0,
        retries: int = 0,
        escalations: int = 0,
    ) -> None:
        step_delta = _delta(steps, "steps")
        tool_delta = _delta(tool_calls, "tool_calls")
        retry_delta = _delta(retries, "retries")
        escalation_delta = _delta(escalations, "escalations")
        now = datetime.now(TZ)
        now_text = now.isoformat()

        try:
            with self.store.connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                parent = conn.execute(
                    "SELECT * FROM task_execution_budget_usage WHERE task_id = ?",
                    (self.parent_task_id,),
                ).fetchone()
                child = conn.execute(
                    "SELECT * FROM task_execution_budget_usage WHERE task_id = ?",
                    (self.task_id,),
                ).fetchone()
                if parent is None:
                    raise ValueError("PARENT_TASK_EXECUTION_BUDGET_NOT_BOUND")
                if child is None:
                    raise ValueError("TASK_EXECUTION_BUDGET_NOT_BOUND")

                parent_next = _project(
                    parent,
                    steps=step_delta,
                    tool_calls=tool_delta,
                    retries=retry_delta,
                    escalations=escalation_delta,
                    now=now,
                )
                child_next = _project(
                    child,
                    steps=step_delta,
                    tool_calls=tool_delta,
                    retries=retry_delta,
                    escalations=escalation_delta,
                    now=now,
                )

                if step_delta or tool_delta or retry_delta or escalation_delta:
                    for task_id, projected in (
                        (self.parent_task_id, parent_next),
                        (self.task_id, child_next),
                    ):
                        conn.execute(
                            """
                            UPDATE task_execution_budget_usage
                            SET steps_used = ?, tool_calls_used = ?, retries_used = ?,
                                escalations_used = ?, updated_at = ?
                            WHERE task_id = ?
                            """,
                            (
                                projected["steps_used"],
                                projected["tool_calls_used"],
                                projected["retries_used"],
                                projected["escalations_used"],
                                now_text,
                                task_id,
                            ),
                        )
        except ValueError as exc:
            code = str(exc)
            if code in _BUDGET_EXHAUSTION_CODES:
                raise ExecutionBudgetExceeded(code) from exc
            raise

    def assert_active(self) -> None:
        self.reserve()

    def snapshot(self) -> dict[str, object]:
        child = self.store.task_execution_budget_for_task(self.task_id)
        parent = self.store.task_execution_budget_for_task(self.parent_task_id)
        return {
            "schema_version": "workspace-linked-task-execution-budget-state/v1",
            "task_id": self.task_id,
            "aggregate_parent_task_id": self.parent_task_id,
            "max_steps": int(child["max_steps"]),
            "max_tool_calls": int(child["max_tool_calls"]),
            "max_model_retries": int(child["max_retries"]),
            "max_model_escalations": int(child["max_escalations"]),
            "max_wall_time_ms": int(child["max_wall_time_ms"]),
            "steps_used": int(child["steps_used"]),
            "tool_calls_used": int(child["tool_calls_used"]),
            "model_retries_used": int(child["retries_used"]),
            "model_escalations_used": int(child["escalations_used"]),
            "deadline_at": str(child["deadline_at"]),
            "aggregate_parent": {
                "max_steps": int(parent["max_steps"]),
                "max_tool_calls": int(parent["max_tool_calls"]),
                "max_model_retries": int(parent["max_retries"]),
                "max_model_escalations": int(parent["max_escalations"]),
                "steps_used": int(parent["steps_used"]),
                "tool_calls_used": int(parent["tool_calls_used"]),
                "model_retries_used": int(parent["retries_used"]),
                "model_escalations_used": int(parent["escalations_used"]),
                "deadline_at": str(parent["deadline_at"]),
            },
        }
