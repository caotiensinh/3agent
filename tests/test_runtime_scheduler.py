import json
import tempfile
import threading
import unittest
from pathlib import Path

from three_agent.capability_registry import CapabilityRegistry
from three_agent.runtime_checkpoint import RuntimeCheckpoint, RuntimeCheckpointError, RuntimeCheckpointStore
from three_agent.runtime_execution_plan import ExecutionNode
from three_agent.runtime_plan_compiler import RuntimePlanCompiler
from three_agent.runtime_scheduler import (
    CapabilityAdapterRegistry,
    NodeExecutionResult,
    RuntimeDAGScheduler,
    RuntimeSchedulerError,
)
from three_agent.task_contract import TaskContractCompiler


class FakeBudget:
    def __init__(self, task_id):
        self.task_id = task_id
        self.reservations = []
        self.active_checks = 0
        self._lock = threading.Lock()

    def assert_active(self):
        with self._lock:
            self.active_checks += 1

    def reserve(self, **kwargs):
        with self._lock:
            self.reservations.append(dict(kwargs))


class RuntimeSchedulerTests(unittest.TestCase):
    @staticmethod
    def _runtime(root=None):
        registry = CapabilityRegistry.default()
        adapters = CapabilityAdapterRegistry(registry)
        store = RuntimeCheckpointStore(Path(root)) if root else None
        scheduler = RuntimeDAGScheduler(
            registry=registry,
            adapters=adapters,
            checkpoint_store=store,
        )
        return registry, adapters, scheduler, store

    def test_parallel_reads_join_and_share_task_budget(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-SCHED-DAG",
            task_type="code_review",
            sensitivity="internal",
            risk_level="low",
        )
        registry, adapters, scheduler, _ = self._runtime()
        compiled = RuntimePlanCompiler(registry).compile(
            plan_id="sched_dag",
            task_contract=contract,
            max_parallel=4,
            nodes=(
                ExecutionNode("read_source", "read_file", "path", "src/app.py", "read"),
                ExecutionNode("search_repo", "search_repo", "repo", "workspace_repo", "read"),
                ExecutionNode(
                    "run_tests", "run_tests", "repo", "workspace_tests", "execute",
                    depends_on=("read_source", "search_repo"),
                ),
            ),
        )
        state = set()
        lock = threading.Lock()

        def read_handler(invocation):
            invocation.assert_active()
            with lock:
                state.add(invocation.node.node_id)
            node_id = invocation.node.node_id
            return NodeExecutionResult({"node": node_id}, (f"evidence/{node_id}.json",))

        def test_handler(invocation):
            with lock:
                self.assertIn("read_source", state)
                self.assertIn("search_repo", state)
            return NodeExecutionResult({"tests": "passed"}, ("evidence/tests.json",))

        adapters.register("read_file", read_handler, timeout_mode="cooperative")
        adapters.register("search_repo", read_handler, timeout_mode="cooperative")
        adapters.register("run_tests", test_handler, timeout_mode="hard")
        budget = FakeBudget(contract.task_id)
        result = scheduler.run(compiled_plan=compiled, task_contract=contract, budget=budget)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.durability, "ephemeral")
        self.assertEqual(set(result.completed_node_ids), {"read_source", "search_repo", "run_tests"})
        self.assertEqual(len(budget.reservations), 3)
        self.assertTrue(all(row == {"steps": 1, "tool_calls": 1} for row in budget.reservations))
        self.assertEqual(budget.active_checks, 3)

    def test_mutation_requires_durable_store_and_hard_timeout_adapter(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-SCHED-WRITE",
            task_type="code_fix",
            sensitivity="internal",
            risk_level="medium",
            write_scope=("src",),
        )
        registry, adapters, scheduler, _ = self._runtime()
        compiled = RuntimePlanCompiler(registry).compile(
            plan_id="sched_write",
            task_contract=contract,
            nodes=(ExecutionNode(
                "patch_a", "apply_patch", "path", "src/a.py", "write", idempotent=False
            ),),
        )
        with self.assertRaisesRegex(RuntimeSchedulerError, "MUTATING_ADAPTER_REQUIRES_HARD_TIMEOUT"):
            adapters.register(
                "apply_patch",
                lambda invocation: NodeExecutionResult({"patched": True}),
                timeout_mode="cooperative",
            )
        adapters.register(
            "apply_patch",
            lambda invocation: NodeExecutionResult({"patched": True}, ("evidence/patch.json",)),
            timeout_mode="hard",
        )
        with self.assertRaisesRegex(RuntimeSchedulerError, "DURABLE_CHECKPOINT_REQUIRED_FOR_MUTATION"):
            scheduler.run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=FakeBudget(contract.task_id),
            )

    def test_high_risk_block_then_resume_preserves_observation_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            contract = TaskContractCompiler().compile(
                task_id="TASK-SCHED-APPROVAL",
                task_type="code_fix",
                sensitivity="internal",
                risk_level="high",
                write_scope=("src",),
            )
            registry, adapters, scheduler, store = self._runtime(tmp)
            compiled = RuntimePlanCompiler(registry).compile(
                plan_id="sched_approval",
                task_contract=contract,
                nodes=(
                    ExecutionNode("read_source", "read_file", "path", "src/a.py", "read"),
                    ExecutionNode(
                        "patch_a", "apply_patch", "path", "src/a.py", "write",
                        depends_on=("read_source",), idempotent=False, approval_required=True,
                    ),
                ),
            )
            adapters.register(
                "read_file",
                lambda invocation: NodeExecutionResult({"read": True}, ("evidence/read.json",)),
                timeout_mode="cooperative",
            )
            adapters.register(
                "apply_patch",
                lambda invocation: NodeExecutionResult({"patched": True}, ("evidence/patch.json",)),
                timeout_mode="hard",
            )
            blocked = scheduler.run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=FakeBudget(contract.task_id),
            )
            self.assertEqual(blocked.status, "blocked")
            self.assertEqual(blocked.completed_node_ids, ("read_source",))
            self.assertEqual(len(blocked.checkpoint.observation_ids), 1)
            loaded = store.load(compiled_plan=compiled)
            resumed = scheduler.run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=FakeBudget(contract.task_id),
                approved_node_ids=("patch_a",),
                checkpoint=loaded,
            )
            self.assertEqual(resumed.status, "completed")
            self.assertEqual(set(resumed.completed_node_ids), {"read_source", "patch_a"})
            self.assertEqual(len(resumed.checkpoint.observation_ids), 2)

    def test_inflight_checkpoint_never_auto_replays(self):
        with tempfile.TemporaryDirectory() as tmp:
            contract = TaskContractCompiler().compile(
                task_id="TASK-SCHED-INFLIGHT",
                task_type="analysis",
                sensitivity="internal",
                risk_level="low",
            )
            registry, adapters, scheduler, store = self._runtime(tmp)
            compiled = RuntimePlanCompiler(registry).compile(
                plan_id="sched_inflight",
                task_contract=contract,
                nodes=(ExecutionNode("read_doc", "read_file", "path", "docs/a.md", "read"),),
            )
            checkpoint = RuntimeCheckpoint.capture(
                compiled_plan=compiled,
                status="running",
                running_node_ids=("read_doc",),
            )
            store.save(checkpoint)
            called = []
            adapters.register(
                "read_file",
                lambda invocation: called.append(invocation.node.node_id)
                or NodeExecutionResult({"read": True}, ("evidence/read.json",)),
                timeout_mode="cooperative",
            )
            with self.assertRaisesRegex(RuntimeSchedulerError, "INFLIGHT_CHECKPOINT_REQUIRES_RECONCILIATION"):
                scheduler.run(
                    compiled_plan=compiled,
                    task_contract=contract,
                    budget=FakeBudget(contract.task_id),
                    checkpoint=store.load(compiled_plan=compiled),
                )
            self.assertEqual(called, [])

    def test_evidence_and_timeout_fail_closed_without_raw_detail(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-SCHED-EVIDENCE",
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )
        registry, adapters, scheduler, _ = self._runtime()
        compiled = RuntimePlanCompiler(registry).compile(
            plan_id="sched_evidence",
            task_contract=contract,
            nodes=(ExecutionNode("read_doc", "read_file", "path", "docs/a.md", "read"),),
        )
        adapters.register(
            "read_file",
            lambda invocation: NodeExecutionResult({"secret": "RAW_RESULT_MUST_NOT_PERSIST"}),
            timeout_mode="cooperative",
        )
        result = scheduler.run(
            compiled_plan=compiled,
            task_contract=contract,
            budget=FakeBudget(contract.task_id),
        )
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.observations[0].reason_code, "EVIDENCE_REQUIRED_MISSING")
        self.assertNotIn("RAW_RESULT_MUST_NOT_PERSIST", json.dumps(result.metadata(), sort_keys=True))

        registry2, adapters2, scheduler2, _ = self._runtime()
        compiled2 = RuntimePlanCompiler(registry2).compile(
            plan_id="sched_timeout",
            task_contract=contract,
            nodes=(ExecutionNode("read_doc", "read_file", "path", "docs/a.md", "read"),),
        )
        def timeout_handler(invocation):
            raise TimeoutError("PRIVATE_TIMEOUT_DETAIL")
        adapters2.register("read_file", timeout_handler, timeout_mode="cooperative")
        timed = scheduler2.run(
            compiled_plan=compiled2,
            task_contract=contract,
            budget=FakeBudget(contract.task_id),
        )
        self.assertEqual(timed.observations[0].reason_code, "ADAPTER_TIMEOUT")
        self.assertNotIn("PRIVATE_TIMEOUT_DETAIL", json.dumps(timed.metadata(), sort_keys=True))

    def test_checkpoint_store_detects_corruption_and_plan_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            contract = TaskContractCompiler().compile(
                task_id="TASK-SCHED-PIN",
                task_type="analysis",
                sensitivity="internal",
                risk_level="low",
            )
            registry = CapabilityRegistry.default()
            compiler = RuntimePlanCompiler(registry)
            first = compiler.compile(
                plan_id="sched_pin",
                task_contract=contract,
                nodes=(ExecutionNode("read_doc", "read_file", "path", "docs/a.md", "read"),),
            )
            checkpoint = RuntimeCheckpoint.capture(compiled_plan=first, status="ready")
            store = RuntimeCheckpointStore(Path(tmp))
            path = store.save(checkpoint)
            raw = path.read_text(encoding="utf-8")
            path.write_text(raw.replace("ready", "block", 1), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeCheckpointError, "CHECKPOINT_FILE_INTEGRITY_MISMATCH"):
                store.load(compiled_plan=first)

            changed = compiler.compile(
                plan_id="sched_pin",
                task_contract=contract,
                nodes=(ExecutionNode("read_doc", "read_file", "path", "docs/b.md", "read"),),
            )
            with self.assertRaisesRegex(RuntimeCheckpointError, "CHECKPOINT_PLAN_CHANGED"):
                checkpoint.validate(changed)


if __name__ == "__main__":
    unittest.main()
