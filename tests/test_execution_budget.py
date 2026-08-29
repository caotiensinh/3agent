import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from zoneinfo import ZoneInfo

from three_agent.artifacts import ArtifactManager
from three_agent.execution_budget import ExecutionBudgetExceeded, TaskExecutionBudgetState
from three_agent.inference_scope import current_execution_budget, inference_scope
from three_agent.llm import LocalLLMError
from three_agent.metered_runtime import MeteredAdaptiveOllamaClient, MeteredExecutionGateway
from three_agent.model_authority import TaskModelAuthority
from three_agent.resource_events import ResourceEventRecorder
from three_agent.runtime_validation import RuntimeValidatorBridge
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler

TZ = ZoneInfo("Asia/Tokyo")


class FakeModel:
    def __init__(self, model, outcomes):
        self.config = SimpleNamespace(model=model)
        self.outcomes = list(outcomes)
        self.calls = 0

    def generate(self, *args, **kwargs):
        del args, kwargs
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def generate_json(self, *args, **kwargs):
        return self.generate(*args, **kwargs)

    def unload(self):
        return None


class FakeExecution:
    def __init__(self):
        self.calls = []

    def run(self, agent_id, task_id, argv, cwd=None):
        self.calls.append((agent_id, task_id, tuple(argv), cwd))
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")


class ExecutionBudgetTests(unittest.TestCase):
    def _store_with_analysis_contract(self, root: Path):
        store = TaskStore(root / "tasks.db")
        store.initialize()
        task = store.create_task("budget", "PRIVATE_REQUEST_MARKER")
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )
        store.bind_task_contract(task.task_id, contract.to_dict())
        return store, task, contract

    def test_budget_is_derived_from_bound_contract_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TaskStore(root / "tasks.db")
            store.initialize()
            task = store.create_task("budget", "request")
            with self.assertRaisesRegex(ValueError, "TASK_CONTRACT_NOT_BOUND"):
                store.bind_task_execution_budget(task.task_id)

            contract = TaskContractCompiler().compile(
                task_id=task.task_id,
                task_type="analysis",
                sensitivity="internal",
            )
            store.bind_task_contract(task.task_id, contract.to_dict())
            row = store.bind_task_execution_budget(task.task_id)
            self.assertEqual(row["max_steps"], contract.execution_budget.max_steps)
            self.assertEqual(row["max_tool_calls"], contract.execution_budget.max_tool_calls)
            self.assertEqual(row["max_retries"], contract.execution_budget.max_retries)
            self.assertEqual(row["max_escalations"], contract.execution_budget.max_escalations)
            self.assertEqual(row["max_wall_time_ms"], contract.execution_budget.max_wall_time_ms)
            self.assertTrue(str(row["deadline_at"]))

    def test_usage_survives_wrapper_and_store_reconstruction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, task, _ = self._store_with_analysis_contract(root)
            first = TaskExecutionBudgetState.from_bound_contract(store, task.task_id)
            first.reserve(steps=1, tool_calls=1, retries=1, escalations=1)
            first_snap = first.snapshot()
            self.assertEqual(first_snap["steps_used"], 1)
            self.assertEqual(first_snap["tool_calls_used"], 1)
            self.assertEqual(first_snap["model_retries_used"], 1)

            restarted_store = TaskStore(root / "tasks.db")
            restarted_store.initialize()
            restarted = TaskExecutionBudgetState.from_bound_contract(
                restarted_store, task.task_id
            )
            snap = restarted.snapshot()
            self.assertEqual(snap["steps_used"], 1)
            self.assertEqual(snap["tool_calls_used"], 1)
            self.assertEqual(snap["model_retries_used"], 1)
            self.assertEqual(snap["model_escalations_used"], 1)
            self.assertEqual(snap["deadline_at"], first_snap["deadline_at"])
            restarted.reserve(retries=1)
            with self.assertRaisesRegex(
                ExecutionBudgetExceeded, "MODEL_RETRY_BUDGET_EXHAUSTED"
            ):
                restarted.reserve(retries=1)
            self.assertEqual(restarted.snapshot()["model_retries_used"], 2)

    def test_atomic_multi_dimension_reservation_does_not_partially_consume(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, task, _ = self._store_with_analysis_contract(Path(tmp))
            state = TaskExecutionBudgetState.from_bound_contract(store, task.task_id)
            state.reserve(steps=state.max_steps, tool_calls=1)
            before = state.snapshot()
            with self.assertRaisesRegex(
                ExecutionBudgetExceeded, "TASK_STEP_BUDGET_EXHAUSTED"
            ):
                state.reserve(steps=1, tool_calls=1)
            after = state.snapshot()
            self.assertEqual(after["steps_used"], before["steps_used"])
            self.assertEqual(after["tool_calls_used"], before["tool_calls_used"])

    def test_wall_deadline_survives_state_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, task, _ = self._store_with_analysis_contract(Path(tmp))
            state = TaskExecutionBudgetState.from_bound_contract(store, task.task_id)
            expired = (datetime.now(TZ) - timedelta(seconds=1)).isoformat()
            with store.connect() as conn:
                conn.execute(
                    "UPDATE task_execution_budget_usage SET deadline_at = ? WHERE task_id = ?",
                    (expired, task.task_id),
                )
            with self.assertRaisesRegex(
                ExecutionBudgetExceeded, "TASK_WALL_TIME_BUDGET_EXHAUSTED"
            ):
                state.assert_active()

            restarted = TaskExecutionBudgetState.from_bound_contract(
                TaskStore(store.db_path), task.task_id
            )
            with self.assertRaisesRegex(
                ExecutionBudgetExceeded, "TASK_WALL_TIME_BUDGET_EXHAUSTED"
            ):
                restarted.assert_active()

    def test_same_task_id_in_two_sandboxes_has_independent_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            store_a, task_a, _ = self._store_with_analysis_contract(base / "a")
            store_b, task_b, _ = self._store_with_analysis_contract(base / "b")
            self.assertEqual(task_a.task_id, task_b.task_id)

            state_a = TaskExecutionBudgetState.from_bound_contract(store_a, task_a.task_id)
            state_b = TaskExecutionBudgetState.from_bound_contract(store_b, task_b.task_id)
            state_a.reserve(retries=1)
            self.assertEqual(state_a.snapshot()["model_retries_used"], 1)
            self.assertEqual(state_b.snapshot()["model_retries_used"], 0)

    def test_scope_rejects_budget_from_another_task(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, task, _ = self._store_with_analysis_contract(Path(tmp))
            state = TaskExecutionBudgetState.from_bound_contract(store, task.task_id)
            with self.assertRaisesRegex(ValueError, "does not match inference scope"):
                with inference_scope(
                    "TASK-OTHER",
                    agent_id="research",
                    stage="research",
                    execution_budget=state,
                ):
                    pass

    def test_retry_and_escalation_are_reserved_before_second_model_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, task, _ = self._store_with_analysis_contract(root)
            state = TaskExecutionBudgetState.from_bound_contract(store, task.task_id)
            events_path = root / "resource.jsonl"
            recorder = ResourceEventRecorder(events_path)
            primary = FakeModel(
                "small",
                [LocalLLMError("PRIVATE_FAILURE_ONE"), LocalLLMError("PRIVATE_FAILURE_TWO")],
            )
            deep = FakeModel("deep", ["first-ok", "MUST_NOT_RUN"])
            client = MeteredAdaptiveOllamaClient(
                primary,
                deep=deep,
                deep_escalation=True,
                role="research",
                resource_events=recorder,
            )

            with inference_scope(
                task.task_id,
                agent_id="research",
                stage="research",
                execution_budget=state,
            ):
                self.assertIs(current_execution_budget(), state)
                self.assertEqual(client.generate("system", "short"), "first-ok")

            with inference_scope(
                task.task_id,
                agent_id="presentation",
                stage="presentation",
                execution_budget=state,
            ):
                with self.assertRaisesRegex(
                    ExecutionBudgetExceeded, "MODEL_ESCALATION_BUDGET_EXHAUSTED"
                ):
                    client.generate("system", "short")

            self.assertEqual(primary.calls, 2)
            self.assertEqual(deep.calls, 1)
            snap = state.snapshot()
            self.assertEqual(snap["model_retries_used"], 1)
            self.assertEqual(snap["model_escalations_used"], 1)
            raw = events_path.read_text(encoding="utf-8")
            self.assertNotIn("PRIVATE_FAILURE_ONE", raw)
            self.assertNotIn("PRIVATE_FAILURE_TWO", raw)
            rows = [json.loads(line) for line in raw.splitlines() if line]
            self.assertEqual(
                [row["event_type"] for row in rows],
                ["model_retry", "model_escalation"],
            )

    def test_expired_deadline_blocks_initial_model_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, task, contract = self._store_with_analysis_contract(root)
            state = TaskExecutionBudgetState.from_bound_contract(store, task.task_id)
            with store.connect() as conn:
                conn.execute(
                    "UPDATE task_execution_budget_usage SET deadline_at = ? WHERE task_id = ?",
                    ((datetime.now(TZ) - timedelta(seconds=1)).isoformat(), task.task_id),
                )
            primary = FakeModel("specialist", ["MUST_NOT_RUN"])
            client = MeteredAdaptiveOllamaClient(
                primary,
                deep=None,
                deep_escalation=False,
                role="research",
                resource_events=ResourceEventRecorder(root / "events.jsonl"),
            )
            authority = TaskModelAuthority.from_contract(contract)
            with inference_scope(
                task.task_id,
                agent_id="research",
                stage="research",
                execution_budget=state,
                model_authority=authority,
            ):
                with self.assertRaisesRegex(
                    ExecutionBudgetExceeded, "TASK_WALL_TIME_BUDGET_EXHAUSTED"
                ):
                    client.generate("system", "prompt")
            self.assertEqual(primary.calls, 0)

    def test_tool_budget_blocks_inner_execution_and_telemetry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TaskStore(root / "tasks.db")
            store.initialize()
            task = store.create_task("tool budget", "request")
            contract = TaskContractCompiler().compile(
                task_id=task.task_id,
                task_type="code_review",
                sensitivity="internal",
            )
            store.bind_task_contract(task.task_id, contract.to_dict())
            state = TaskExecutionBudgetState.from_bound_contract(store, task.task_id)
            state.reserve(tool_calls=state.max_tool_calls)
            inner = FakeExecution()
            events = root / "events.jsonl"
            gateway = MeteredExecutionGateway(inner, ResourceEventRecorder(events))
            authority = TaskModelAuthority.from_contract(contract)
            with inference_scope(
                task.task_id,
                agent_id="research",
                stage="research",
                execution_budget=state,
                model_authority=authority,
            ):
                with self.assertRaisesRegex(
                    ExecutionBudgetExceeded, "TASK_TOOL_CALL_BUDGET_EXHAUSTED"
                ):
                    gateway.run(
                        "research",
                        task.task_id,
                        ["pytest", "-q"],
                        capability="run_tests",
                    )
            self.assertEqual(inner.calls, [])
            self.assertFalse(events.exists())

    def test_runtime_bridge_binds_complete_persistent_budget_before_policy_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TaskStore(root / "tasks.db")
            store.initialize()
            task = store.create_task("runtime", "PRIVATE_RUNTIME_REQUEST")
            bridge = RuntimeValidatorBridge(
                store,
                ArtifactManager(root / "artifacts"),
                confidentiality_mode="development-test",
                public_web=False,
            )
            attempt = bridge.begin(task.task_id)
            self.assertIsNotNone(attempt.execution_budget)
            snap = attempt.execution_budget.snapshot()
            self.assertEqual(snap["max_steps"], 8)
            self.assertEqual(snap["max_tool_calls"], 12)
            self.assertEqual(snap["max_model_retries"], 2)
            self.assertEqual(snap["max_model_escalations"], 1)
            self.assertEqual(snap["max_wall_time_ms"], 600000)
            activities = store.activities_for_date(task.created_at[:10])
            activity_text = "\n".join(str(row["details"]) for row in activities)
            self.assertNotIn("PRIVATE_RUNTIME_REQUEST", activity_text)
            self.assertIn("max_retries=2", activity_text)
            self.assertIn("max_steps=8", activity_text)


if __name__ == "__main__":
    unittest.main()
