import tempfile
import unittest
from pathlib import Path

from three_agent.capability_registry import CapabilityRegistry
from three_agent.capability_revocation import TaskCapabilityRevocationStore
from three_agent.execution_budget import TaskExecutionBudgetState
from three_agent.runtime_checkpoint import RuntimeCheckpointStore
from three_agent.runtime_execution_plan import ExecutionNode
from three_agent.runtime_invocation import RuntimeInvocationBundle, TypedCapabilityInvocation
from three_agent.runtime_invocation_binding import RuntimeInvocationBindingStore
from three_agent.runtime_observation_ledger import RuntimeObservationLedger
from three_agent.runtime_plan_compiler import RuntimePlanCompiler
from three_agent.runtime_production_adapters import ProductionCapabilityAdapterRegistry
from three_agent.runtime_production_scheduler import ProductionAuditedRuntimeDAGScheduler
from three_agent.runtime_reviewed_calculator import (
    ReviewedCalculatorBoundary,
    ReviewedCalculatorError,
)
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler


class FakeCalculatorEvidenceSink:
    def __init__(self):
        self.calls = []

    def persist_calculation(
        self,
        *,
        task_id,
        node_id,
        expression_sha256,
        result,
        result_sha256,
    ):
        self.calls.append(
            (task_id, node_id, expression_sha256, result, result_sha256)
        )
        return ("artifact:calculator-evidence",)


class RuntimeProductionCalculatorTests(unittest.TestCase):
    @staticmethod
    def _task(tmp, *, task_type="general"):
        store = TaskStore(Path(tmp) / "tasks.db")
        store.initialize()
        task = store.create_task("production calculator", "deterministic arithmetic fixture")
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type=task_type,
            sensitivity="confidential",
            risk_level="low",
            allowed_tools=("calculator",),
            write_scope="none",
        )
        store.bind_task_contract(task.task_id, contract.to_dict())
        budget = TaskExecutionBudgetState.from_bound_contract(store, task.task_id)
        return store, contract, budget

    @staticmethod
    def _plan(contract, expression="2 + 3 * 4"):
        registry = CapabilityRegistry.default()
        compiled = RuntimePlanCompiler(registry).compile(
            plan_id="production_calculator",
            task_contract=contract,
            nodes=(
                ExecutionNode(
                    "calc",
                    "calculator",
                    "compute",
                    "deterministic_math",
                    "compute",
                ),
            ),
        )
        typed = TypedCapabilityInvocation.compile(
            compiled_plan=compiled,
            node_id="calc",
            operation="evaluate",
            arguments={"expression": expression},
        )
        bundle = RuntimeInvocationBundle.compile(
            compiled_plan=compiled,
            invocations=(typed,),
        )
        return registry, compiled, bundle

    @staticmethod
    def _adapters(*, contract, budget, registry, compiled, invocation_bundle, sink=None):
        boundary = ReviewedCalculatorBoundary(evidence_sink=sink)
        return ProductionCapabilityAdapterRegistry(
            compiled_plan=compiled,
            task_contract=contract,
            invocation_bundle=invocation_bundle,
            budget=budget,
            calculator_boundary=boundary,
            registry=registry,
        )

    @staticmethod
    def _scheduler(tmp, store, adapters):
        return ProductionAuditedRuntimeDAGScheduler(
            adapters=adapters,
            invocation_binding_store=RuntimeInvocationBindingStore(
                Path(tmp) / "invocation_bindings"
            ),
            observation_ledger=RuntimeObservationLedger(store),
            checkpoint_store=RuntimeCheckpointStore(Path(tmp) / "checkpoints"),
            registry=adapters.capability_registry,
        )

    def test_calculator_evaluates_bounded_arithmetic_without_raw_result_in_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(contract)
            adapters = self._adapters(
                contract=contract,
                budget=budget,
                registry=registry,
                compiled=compiled,
                invocation_bundle=invocation_bundle,
            )
            result = self._scheduler(tmp, store, adapters).run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "completed")
            observation = result.observations[0]
            self.assertEqual(observation.status, "succeeded")
            self.assertEqual(observation.reason_code, "CALCULATOR_OK")
            self.assertEqual(observation.evidence_refs, ())
            self.assertEqual(budget.snapshot()["steps_used"], 1)
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)
            self.assertTrue(observation.result_sha256.startswith("sha256:"))
            self.assertNotIn("14", str(observation.metadata()))
            self.assertNotIn("2 + 3 * 4", str(observation.metadata()))

    def test_evidence_required_task_uses_calculator_sink(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, contract, budget = self._task(tmp, task_type="analysis")
            registry, compiled, invocation_bundle = self._plan(contract, "(10 - 4) ** 2")
            sink = FakeCalculatorEvidenceSink()
            adapters = self._adapters(
                contract=contract,
                budget=budget,
                registry=registry,
                compiled=compiled,
                invocation_bundle=invocation_bundle,
                sink=sink,
            )
            result = self._scheduler(tmp, store, adapters).run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "completed")
            self.assertEqual(
                result.observations[0].evidence_refs,
                ("artifact:calculator-evidence",),
            )
            self.assertEqual(len(sink.calls), 1)
            self.assertEqual(sink.calls[0][3], 36)

    def test_live_revocation_denies_before_evaluation_or_tool_charge(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(contract)
            sink = FakeCalculatorEvidenceSink()
            adapters = self._adapters(
                contract=contract,
                budget=budget,
                registry=registry,
                compiled=compiled,
                invocation_bundle=invocation_bundle,
                sink=sink,
            )
            TaskCapabilityRevocationStore(store).revoke(
                contract.task_id,
                "calculator",
                reason_code="OPERATOR_REVOKED",
            )
            result = self._scheduler(tmp, store, adapters).run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.observations[0].status, "denied")
            self.assertEqual(result.observations[0].reason_code, "CAPABILITY_REVOKED")
            self.assertEqual(budget.snapshot()["tool_calls_used"], 0)
            self.assertEqual(sink.calls, [])

    def test_calculator_rejects_names_calls_bitops_and_unbounded_results(self):
        rejected = (
            "__import__('os').system('id')",
            "abs(-1)",
            "1 << 20",
            "2 ** 100",
            "1e100 * 10",
        )
        boundary = ReviewedCalculatorBoundary()
        for expression in rejected:
            with self.subTest(expression=expression):
                import ast
                from three_agent.runtime_reviewed_calculator import _evaluate, _validate_ast

                with self.assertRaises(ReviewedCalculatorError):
                    tree = ast.parse(expression, mode="eval")
                    _validate_ast(tree)
                    _evaluate(tree)

    def test_division_by_zero_fails_closed_after_single_tool_charge(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(contract, "1 / 0")
            adapters = self._adapters(
                contract=contract,
                budget=budget,
                registry=registry,
                compiled=compiled,
                invocation_bundle=invocation_bundle,
            )
            result = self._scheduler(tmp, store, adapters).run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.observations[0].reason_code, "CALCULATOR_DIVISION_BY_ZERO")
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)


if __name__ == "__main__":
    unittest.main()
