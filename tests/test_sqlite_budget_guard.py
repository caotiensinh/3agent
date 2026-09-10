from __future__ import annotations

import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path

from three_agent.execution_budget import TaskExecutionBudgetState
from three_agent.linked_execution_budget import LinkedTaskExecutionBudgetState
from three_agent.sqlite_budget_guard import budget_write_guard, run_budget_write
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler


class SQLiteBudgetGuardTests(unittest.TestCase):
    def _bound_state(self, store: TaskStore, title: str) -> TaskExecutionBudgetState:
        task = store.create_task(title, title)
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )
        store.bind_task_contract(task.task_id, contract.to_dict())
        return TaskExecutionBudgetState.from_bound_contract(store, task.task_id)

    def test_distinct_store_instances_share_one_process_local_budget_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "workspace.db"
            store_a = TaskStore(db)
            store_b = TaskStore(db)
            entered_a = threading.Event()
            release_a = threading.Event()
            entered_b = threading.Event()

            def holder() -> None:
                with budget_write_guard(store_a):
                    entered_a.set()
                    self.assertTrue(release_a.wait(timeout=2))

            def waiter() -> None:
                with budget_write_guard(store_b):
                    entered_b.set()

            first = threading.Thread(target=holder)
            second = threading.Thread(target=waiter)
            first.start()
            self.assertTrue(entered_a.wait(timeout=2))
            second.start()
            time.sleep(0.05)
            self.assertFalse(entered_b.is_set())
            release_a.set()
            first.join(timeout=2)
            second.join(timeout=2)
            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())
            self.assertTrue(entered_b.is_set())

    def test_locked_database_is_retried_only_within_bounded_attempts(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStore(Path(tmp) / "workspace.db")
            calls = 0

            def transient() -> str:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise sqlite3.OperationalError("database is locked")
                return "ok"

            result = run_budget_write(
                store,
                transient,
                attempts=2,
                retry_delay_seconds=0,
            )
            self.assertEqual(result, "ok")
            self.assertEqual(calls, 2)

            calls = 0

            def persistent() -> None:
                nonlocal calls
                calls += 1
                raise sqlite3.OperationalError("database is busy")

            with self.assertRaisesRegex(sqlite3.OperationalError, "database is busy"):
                run_budget_write(
                    store,
                    persistent,
                    attempts=2,
                    retry_delay_seconds=0,
                )
            self.assertEqual(calls, 2)

    def test_non_contention_operational_error_is_not_retried(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStore(Path(tmp) / "workspace.db")
            calls = 0

            def broken() -> None:
                nonlocal calls
                calls += 1
                raise sqlite3.OperationalError("no such table: broken")

            with self.assertRaisesRegex(sqlite3.OperationalError, "no such table"):
                run_budget_write(
                    store,
                    broken,
                    attempts=2,
                    retry_delay_seconds=0,
                )
            self.assertEqual(calls, 1)

    def test_parallel_linked_children_preserve_exact_parent_counter(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "workspace.db"
            store = TaskStore(db)
            store.initialize()
            parent = self._bound_state(store, "parent")
            children = [self._bound_state(TaskStore(db), f"child-{idx}") for idx in range(8)]
            linked = [LinkedTaskExecutionBudgetState.from_states(parent, child) for child in children]
            barrier = threading.Barrier(len(linked))
            failures: list[BaseException] = []
            failures_lock = threading.Lock()

            def reserve_one(state: LinkedTaskExecutionBudgetState) -> None:
                try:
                    barrier.wait(timeout=5)
                    state.reserve(steps=1)
                except BaseException as exc:  # captured for assertion in main test thread
                    with failures_lock:
                        failures.append(exc)

            threads = [threading.Thread(target=reserve_one, args=(state,)) for state in linked]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)

            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(failures, [])
            self.assertEqual(parent.snapshot()["steps_used"], 8)
            self.assertEqual(
                sum(child.snapshot()["steps_used"] for child in children),
                8,
            )


if __name__ == "__main__":
    unittest.main()
