from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from three_agent.execution_budget import ExecutionBudgetExceeded, TaskExecutionBudgetState
from three_agent.linked_execution_budget import LinkedTaskExecutionBudgetState
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler
from three_agent.validator_ledger import ValidatorLedger


class LinkedExecutionBudgetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TaskStore(Path(self.tmp.name) / "workspace.db")
        self.store.initialize()
        self.compiler = TaskContractCompiler()
        self.ledger = ValidatorLedger(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def _budget(self, title: str) -> TaskExecutionBudgetState:
        task = self.store.create_task(title, title)
        contract = self.compiler.compile(
            task_id=task.task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )
        self.ledger.bind_contract(contract)
        return TaskExecutionBudgetState.from_bound_contract(self.store, task.task_id)

    def test_one_reservation_charges_parent_and_child_across_all_counter_dimensions(self):
        parent = self._budget("parent")
        child = self._budget("child")
        linked = LinkedTaskExecutionBudgetState.from_states(parent, child)

        linked.reserve(steps=1, tool_calls=2, retries=1, escalations=1)

        parent_state = parent.snapshot()
        child_state = child.snapshot()
        for state in (parent_state, child_state):
            self.assertEqual(state["steps_used"], 1)
            self.assertEqual(state["tool_calls_used"], 2)
            self.assertEqual(state["model_retries_used"], 1)
            self.assertEqual(state["model_escalations_used"], 1)

    def test_parent_exhaustion_rolls_back_child_reservation(self):
        parent = self._budget("parent")
        child = self._budget("child")
        linked = LinkedTaskExecutionBudgetState.from_states(parent, child)

        linked.reserve(retries=1)
        parent.reserve(retries=1)
        before_child = child.snapshot()["model_retries_used"]

        with self.assertRaises(ExecutionBudgetExceeded) as caught:
            linked.reserve(retries=1)

        self.assertEqual(caught.exception.reason_code, "MODEL_RETRY_BUDGET_EXHAUSTED")
        self.assertEqual(parent.snapshot()["model_retries_used"], 2)
        self.assertEqual(child.snapshot()["model_retries_used"], before_child)

    def test_concurrent_children_cannot_race_past_parent_limit(self):
        parent = self._budget("parent")
        child_a = self._budget("child-a")
        child_b = self._budget("child-b")
        linked_a = LinkedTaskExecutionBudgetState.from_states(parent, child_a)
        linked_b = LinkedTaskExecutionBudgetState.from_states(parent, child_b)

        parent.reserve(steps=7)
        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        lock = threading.Lock()

        def reserve_one(linked: LinkedTaskExecutionBudgetState) -> None:
            barrier.wait(timeout=5)
            try:
                linked.reserve(steps=1)
                outcome = "pass"
            except ExecutionBudgetExceeded as exc:
                outcome = exc.reason_code
            with lock:
                outcomes.append(outcome)

        threads = [
            threading.Thread(target=reserve_one, args=(linked_a,)),
            threading.Thread(target=reserve_one, args=(linked_b,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        self.assertEqual(sorted(outcomes), ["TASK_STEP_BUDGET_EXHAUSTED", "pass"])
        self.assertEqual(parent.snapshot()["steps_used"], 8)
        self.assertEqual(
            child_a.snapshot()["steps_used"] + child_b.snapshot()["steps_used"],
            1,
        )

    def test_parent_wall_time_expiry_blocks_child_without_consuming_counters(self):
        parent = self._budget("parent")
        child = self._budget("child")
        linked = LinkedTaskExecutionBudgetState.from_states(parent, child)
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE task_execution_budget_usage SET deadline_at = ? WHERE task_id = ?",
                ("2000-01-01T00:00:00+09:00", parent.task_id),
            )

        with self.assertRaises(ExecutionBudgetExceeded) as caught:
            linked.reserve(tool_calls=1)

        self.assertEqual(caught.exception.reason_code, "TASK_WALL_TIME_BUDGET_EXHAUSTED")
        self.assertEqual(child.snapshot()["tool_calls_used"], 0)


if __name__ == "__main__":
    unittest.main()
