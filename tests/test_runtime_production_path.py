import tempfile
import unittest
from pathlib import Path

from three_agent.capability_registry import CapabilityRegistry
from three_agent.capability_revocation import TaskCapabilityRevocationStore
from three_agent.execution_budget import TaskExecutionBudgetState
from three_agent.metered_runtime import MeteredInternetGateway
from three_agent.resource_events import ResourceEventRecorder
from three_agent.runtime_checkpoint import RuntimeCheckpointStore
from three_agent.runtime_execution_plan import ExecutionNode
from three_agent.runtime_invocation import RuntimeInvocationBundle, TypedCapabilityInvocation
from three_agent.runtime_invocation_binding import (
    RuntimeInvocationBindingError,
    RuntimeInvocationBindingStore,
)
from three_agent.runtime_observation_ledger import RuntimeObservationLedger
from three_agent.runtime_production_adapters import ProductionCapabilityAdapterRegistry
from three_agent.runtime_production_scheduler import ProductionAuditedRuntimeDAGScheduler
from three_agent.runtime_reviewed_execution import (
    ReviewedCommandProfile,
    ReviewedExecutionBoundary,
    ReviewedExecutionError,
    SandboxCommandResult,
)
from three_agent.runtime_scheduler import CapabilityAdapterRegistry, RuntimeSchedulerError
from three_agent.runtime_plan_compiler import RuntimePlanCompiler
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler


class FakeSandboxRunner:
    def __init__(self, returncode=0):
        self.returncode = returncode
        self.calls = []

    def run(self, *, argv, cwd, timeout_seconds, constraints):
        self.calls.append((argv, cwd, timeout_seconds, constraints))
        return SandboxCommandResult.from_output_hashes(
            returncode=self.returncode,
            stdout=b"test-output",
            stderr=b"" if self.returncode == 0 else b"test-failed",
            evidence_refs=("artifact:test-evidence",),
        )


class FakeInternet:
    def __init__(self):
        self.calls = []

    def search_get(self, agent_id, task_id, endpoint, params, *, timeout=30):
        self.calls.append((agent_id, task_id, endpoint, dict(params), timeout))
        return b"public search evidence"


class FakeWebEvidenceSink:
    def __init__(self):
        self.calls = []

    def persist_search_response(
        self,
        *,
        task_id,
        node_id,
        response,
        response_sha256,
        query_sha256,
    ):
        self.calls.append(
            (task_id, node_id, response, response_sha256, query_sha256)
        )
        return ("artifact:web-evidence",)


class RuntimeProductionPathTests(unittest.TestCase):
    @staticmethod
    def _task(tmp, *, task_type, allowed_tools, public_web=False):
        store = TaskStore(Path(tmp) / "tasks.db")
        store.initialize()
        task = store.create_task("production runtime", "production runtime fixture")
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type=task_type,
            sensitivity="internal",
            risk_level="low",
            allowed_tools=allowed_tools,
            public_web=public_web,
            write_scope="none",
        )
        store.bind_task_contract(task.task_id, contract.to_dict())
        budget = TaskExecutionBudgetState.from_bound_contract(store, task.task_id)
        return store, contract, budget

    @staticmethod
    def _execution_plan(contract, *, suite="default"):
        registry = CapabilityRegistry.default()
        compiled = RuntimePlanCompiler(registry).compile(
            plan_id="production_tests",
            task_contract=contract,
            nodes=(
                ExecutionNode(
                    "tests",
                    "run_tests",
                    "repo",
                    "workspace_tests",
                    "execute",
                ),
            ),
        )
        typed = TypedCapabilityInvocation.compile(
            compiled_plan=compiled,
            node_id="tests",
            operation="run",
            arguments={"suite": suite},
        )
        bundle = RuntimeInvocationBundle.compile(
            compiled_plan=compiled,
            invocations=(typed,),
        )
        return registry, compiled, bundle

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

    def test_production_execution_charges_one_step_and_one_actual_tool_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, contract, budget = self._task(
                tmp,
                task_type="code_review",
                allowed_tools=("run_tests",),
            )
            registry, compiled, bundle = self._execution_plan(contract)
            runner = FakeSandboxRunner(returncode=0)
            boundary = ReviewedExecutionBoundary(
                workspace_root=Path(tmp),
                profiles=(
                    ReviewedCommandProfile(
                        "default",
                        "run_tests",
                        ("pytest", "-q"),
                    ),
                ),
                runner=runner,
                recorder=ResourceEventRecorder(Path(tmp) / "resource.jsonl"),
            )
            adapters = ProductionCapabilityAdapterRegistry(
                compiled_plan=compiled,
                task_contract=contract,
                invocation_bundle=bundle,
                budget=budget,
                execution_boundary=boundary,
                registry=registry,
            )
            result = self._scheduler(tmp, store, adapters).run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            snapshot = budget.snapshot()
            self.assertEqual(result.status, "completed")
            self.assertEqual(result.observations[0].status, "succeeded")
            self.assertEqual(snapshot["steps_used"], 1)
            self.assertEqual(snapshot["tool_calls_used"], 1)
            self.assertEqual(len(runner.calls), 1)
            argv, cwd, _, constraints = runner.calls[0]
            self.assertEqual(argv, ("pytest", "-q"))
            self.assertEqual(cwd, Path(tmp).resolve())
            self.assertEqual(constraints.network_scope, "deny")
            self.assertEqual(constraints.write_scope, ())

    def test_nonzero_command_is_failed_observation_with_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, contract, budget = self._task(
                tmp,
                task_type="code_review",
                allowed_tools=("run_tests",),
            )
            registry, compiled, bundle = self._execution_plan(contract)
            runner = FakeSandboxRunner(returncode=2)
            boundary = ReviewedExecutionBoundary(
                workspace_root=Path(tmp),
                profiles=(ReviewedCommandProfile("default", "run_tests", ("pytest", "-q")),),
                runner=runner,
            )
            adapters = ProductionCapabilityAdapterRegistry(
                compiled_plan=compiled,
                task_contract=contract,
                invocation_bundle=bundle,
                budget=budget,
                execution_boundary=boundary,
                registry=registry,
            )
            result = self._scheduler(tmp, store, adapters).run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.observations[0].status, "failed")
            self.assertEqual(result.observations[0].reason_code, "COMMAND_EXIT_NONZERO")
            self.assertEqual(result.observations[0].evidence_refs, ("artifact:test-evidence",))
            self.assertEqual(budget.snapshot()["steps_used"], 1)
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)

    def test_live_revocation_denies_before_tool_charge_or_sandbox_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, contract, budget = self._task(
                tmp,
                task_type="code_review",
                allowed_tools=("run_tests",),
            )
            registry, compiled, bundle = self._execution_plan(contract)
            runner = FakeSandboxRunner(returncode=0)
            boundary = ReviewedExecutionBoundary(
                workspace_root=Path(tmp),
                profiles=(ReviewedCommandProfile("default", "run_tests", ("pytest", "-q")),),
                runner=runner,
            )
            adapters = ProductionCapabilityAdapterRegistry(
                compiled_plan=compiled,
                task_contract=contract,
                invocation_bundle=bundle,
                budget=budget,
                execution_boundary=boundary,
                registry=registry,
            )
            TaskCapabilityRevocationStore(store).revoke(
                contract.task_id,
                "run_tests",
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
            self.assertEqual(budget.snapshot()["steps_used"], 1)
            self.assertEqual(budget.snapshot()["tool_calls_used"], 0)
            self.assertEqual(runner.calls, [])

    def test_web_node_is_metered_once_and_persists_evidence_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, contract, budget = self._task(
                tmp,
                task_type="analysis",
                allowed_tools=("web_gateway",),
                public_web=True,
            )
            registry = CapabilityRegistry.default()
            compiled = RuntimePlanCompiler(registry).compile(
                plan_id="production_web",
                task_contract=contract,
                nodes=(
                    ExecutionNode(
                        "web",
                        "web_gateway",
                        "network",
                        "public_search",
                        "network_read",
                    ),
                ),
            )
            typed = TypedCapabilityInvocation.compile(
                compiled_plan=compiled,
                node_id="web",
                operation="search",
                arguments={"query": "sqlite durability", "count": 3},
            )
            bundle = RuntimeInvocationBundle.compile(
                compiled_plan=compiled,
                invocations=(typed,),
            )
            inner = FakeInternet()
            metered = MeteredInternetGateway(
                inner,
                ResourceEventRecorder(Path(tmp) / "web-resource.jsonl"),
            )
            sink = FakeWebEvidenceSink()
            adapters = ProductionCapabilityAdapterRegistry(
                compiled_plan=compiled,
                task_contract=contract,
                invocation_bundle=bundle,
                budget=budget,
                internet_gateway=metered,
                web_evidence_sink=sink,
                search_endpoint="https://html.duckduckgo.com/html/",
                registry=registry,
            )
            result = self._scheduler(tmp, store, adapters).run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "completed")
            self.assertEqual(result.observations[0].reason_code, "WEB_SEARCH_OK")
            self.assertEqual(result.observations[0].evidence_refs, ("artifact:web-evidence",))
            self.assertEqual(budget.snapshot()["steps_used"], 1)
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)
            self.assertEqual(len(inner.calls), 1)
            self.assertEqual(len(sink.calls), 1)

    def test_invocation_binding_is_idempotent_and_rejects_parameter_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, contract, budget = self._task(
                tmp,
                task_type="code_review",
                allowed_tools=("run_tests",),
            )
            _, compiled, original = self._execution_plan(contract, suite="default")
            _, same_compiled, changed = self._execution_plan(contract, suite="alternate")
            self.assertEqual(compiled.fingerprint, same_compiled.fingerprint)
            self.assertNotEqual(original.fingerprint, changed.fingerprint)
            store = RuntimeInvocationBindingStore(Path(tmp) / "invocation_bindings")
            first = store.bind(compiled_plan=compiled, invocation_bundle=original)
            second = store.bind(compiled_plan=compiled, invocation_bundle=original)
            self.assertEqual(first.binding_id, second.binding_id)
            with self.assertRaisesRegex(
                RuntimeInvocationBindingError,
                "INVOCATION_BINDING_BUNDLE_CHANGED",
            ):
                store.bind(compiled_plan=compiled, invocation_bundle=changed)
            self.assertEqual(budget.snapshot()["steps_used"], 0)
            self.assertEqual(budget.snapshot()["tool_calls_used"], 0)

    def test_production_scheduler_rejects_legacy_unmetered_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStore(Path(tmp) / "tasks.db")
            store.initialize()
            with self.assertRaisesRegex(
                RuntimeSchedulerError,
                "PRODUCTION_ADAPTERS_MUST_BE_BOUNDARY_ACCOUNTED",
            ):
                ProductionAuditedRuntimeDAGScheduler(
                    adapters=CapabilityAdapterRegistry(),
                    invocation_binding_store=RuntimeInvocationBindingStore(
                        Path(tmp) / "invocation_bindings"
                    ),
                    observation_ledger=RuntimeObservationLedger(store),
                    checkpoint_store=RuntimeCheckpointStore(Path(tmp) / "checkpoints"),
                )

    def test_reviewed_profile_rejects_shell_or_inline_code_profiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeSandboxRunner()
            with self.assertRaisesRegex(
                ReviewedExecutionError,
                "REVIEWED_TEST_PROFILE_EXECUTABLE_DENIED",
            ):
                ReviewedExecutionBoundary(
                    workspace_root=Path(tmp),
                    profiles=(
                        ReviewedCommandProfile(
                            "default",
                            "run_tests",
                            ("bash", "-c", "pytest -q"),
                        ),
                    ),
                    runner=runner,
                )


if __name__ == "__main__":
    unittest.main()
