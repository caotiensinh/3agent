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
from three_agent.runtime_reviewed_read import ReviewedReadBoundary
from three_agent.runtime_scheduler import RuntimeSchedulerError
from three_agent.runtime_source_authority import (
    ReviewedSourceBinding,
    RuntimeSourceBindingBundle,
)
from three_agent.runtime_source_binding_store import RuntimeSourceBindingStore
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler


class FakeFileReadEvidenceSink:
    def __init__(self):
        self.calls = []

    def persist_file_read(
        self,
        *,
        task_id,
        node_id,
        source_class,
        resource_ref,
        content,
        content_sha256,
    ):
        self.calls.append(
            (
                task_id,
                node_id,
                source_class,
                resource_ref,
                content,
                content_sha256,
            )
        )
        return ("artifact:file-read-evidence",)


class RuntimeProductionReadTests(unittest.TestCase):
    @staticmethod
    def _task(tmp):
        store = TaskStore(Path(tmp) / "tasks.db")
        store.initialize()
        task = store.create_task("production read", "reviewed file read fixture")
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type="retrieval",
            sensitivity="internal",
            risk_level="low",
            allowed_sources=("repo",),
            allowed_tools=("read_file",),
            write_scope="none",
        )
        store.bind_task_contract(task.task_id, contract.to_dict())
        budget = TaskExecutionBudgetState.from_bound_contract(store, task.task_id)
        return store, contract, budget

    @staticmethod
    def _plan(contract, *, max_bytes=1024 * 1024):
        registry = CapabilityRegistry.default()
        compiled = RuntimePlanCompiler(registry).compile(
            plan_id="production_read",
            task_contract=contract,
            nodes=(
                ExecutionNode(
                    "read",
                    "read_file",
                    "path",
                    "README.md",
                    "read",
                ),
            ),
        )
        typed = TypedCapabilityInvocation.compile(
            compiled_plan=compiled,
            node_id="read",
            operation="read",
            arguments={"max_bytes": max_bytes},
        )
        invocation_bundle = RuntimeInvocationBundle.compile(
            compiled_plan=compiled,
            invocations=(typed,),
        )
        return registry, compiled, invocation_bundle

    @staticmethod
    def _sources(*, root, contract, registry, compiled):
        binding = ReviewedSourceBinding.bind(
            compiled_plan=compiled,
            node_id="read",
            source_class="repo",
            local_root=root,
        )
        bundle = RuntimeSourceBindingBundle.compile(
            compiled_plan=compiled,
            task_contract=contract,
            bindings=(binding,),
            registry=registry,
        )
        return binding, bundle

    @staticmethod
    def _adapters(
        *,
        contract,
        budget,
        registry,
        compiled,
        invocation_bundle,
        source_bundle,
        sink,
    ):
        read_boundary = ReviewedReadBoundary(
            compiled_plan=compiled,
            task_contract=contract,
            source_binding_bundle=source_bundle,
            evidence_sink=sink,
            registry=registry,
        )
        return ProductionCapabilityAdapterRegistry(
            compiled_plan=compiled,
            task_contract=contract,
            invocation_bundle=invocation_bundle,
            budget=budget,
            read_boundary=read_boundary,
            source_binding_bundle=source_bundle,
            registry=registry,
        )

    @staticmethod
    def _scheduler(tmp, store, adapters, *, source_store=True):
        return ProductionAuditedRuntimeDAGScheduler(
            adapters=adapters,
            invocation_binding_store=RuntimeInvocationBindingStore(
                Path(tmp) / "invocation_bindings"
            ),
            source_binding_store=(
                RuntimeSourceBindingStore(Path(tmp) / "source_bindings")
                if source_store
                else None
            ),
            observation_ledger=RuntimeObservationLedger(store),
            checkpoint_store=RuntimeCheckpointStore(Path(tmp) / "checkpoints"),
            registry=adapters.capability_registry,
        )

    def test_reviewed_file_read_is_metered_once_and_persists_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            content = b"reviewed source evidence\n"
            (root / "README.md").write_bytes(content)
            store, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(contract)
            binding, source_bundle = self._sources(
                root=root,
                contract=contract,
                registry=registry,
                compiled=compiled,
            )
            sink = FakeFileReadEvidenceSink()
            adapters = self._adapters(
                contract=contract,
                budget=budget,
                registry=registry,
                compiled=compiled,
                invocation_bundle=invocation_bundle,
                source_bundle=source_bundle,
                sink=sink,
            )
            result = self._scheduler(tmp, store, adapters).run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            snapshot = budget.snapshot()
            self.assertEqual(result.status, "completed")
            self.assertEqual(result.observations[0].status, "succeeded")
            self.assertEqual(result.observations[0].reason_code, "READ_FILE_OK")
            self.assertEqual(
                result.observations[0].evidence_refs,
                ("artifact:file-read-evidence",),
            )
            self.assertEqual(snapshot["steps_used"], 1)
            self.assertEqual(snapshot["tool_calls_used"], 1)
            self.assertEqual(len(sink.calls), 1)
            self.assertEqual(sink.calls[0][2], "repo")
            self.assertEqual(sink.calls[0][3], "README.md")
            self.assertEqual(sink.calls[0][4], content)
            self.assertTrue(sink.calls[0][5].startswith("sha256:"))
            self.assertTrue(binding.fingerprint.startswith("sha256:"))
            self.assertNotIn(str(root.resolve()), str(source_bundle.metadata()))

    def test_live_revocation_denies_before_file_io_or_tool_charge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "README.md").write_bytes(b"must not be read")
            store, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(contract)
            _, source_bundle = self._sources(
                root=root,
                contract=contract,
                registry=registry,
                compiled=compiled,
            )
            sink = FakeFileReadEvidenceSink()
            adapters = self._adapters(
                contract=contract,
                budget=budget,
                registry=registry,
                compiled=compiled,
                invocation_bundle=invocation_bundle,
                source_bundle=source_bundle,
                sink=sink,
            )
            TaskCapabilityRevocationStore(store).revoke(
                contract.task_id,
                "read_file",
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
            self.assertEqual(sink.calls, [])

    def test_source_scoped_scheduler_requires_durable_source_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "README.md").write_bytes(b"source")
            store, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(contract)
            _, source_bundle = self._sources(
                root=root,
                contract=contract,
                registry=registry,
                compiled=compiled,
            )
            adapters = self._adapters(
                contract=contract,
                budget=budget,
                registry=registry,
                compiled=compiled,
                invocation_bundle=invocation_bundle,
                source_bundle=source_bundle,
                sink=FakeFileReadEvidenceSink(),
            )
            with self.assertRaisesRegex(
                RuntimeSchedulerError,
                "DURABLE_SOURCE_BINDING_STORE_REQUIRED",
            ):
                self._scheduler(
                    tmp,
                    store,
                    adapters,
                    source_store=False,
                )
            self.assertEqual(budget.snapshot()["steps_used"], 0)
            self.assertEqual(budget.snapshot()["tool_calls_used"], 0)

    def test_restart_with_changed_trusted_root_is_denied_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root_a = Path(tmp) / "repo-a"
            root_b = Path(tmp) / "repo-b"
            root_a.mkdir()
            root_b.mkdir()
            (root_a / "README.md").write_bytes(b"approved root")
            (root_b / "README.md").write_bytes(b"changed root")
            store, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(contract)
            _, source_a = self._sources(
                root=root_a,
                contract=contract,
                registry=registry,
                compiled=compiled,
            )
            _, source_b = self._sources(
                root=root_b,
                contract=contract,
                registry=registry,
                compiled=compiled,
            )
            source_store = RuntimeSourceBindingStore(Path(tmp) / "source_bindings")
            source_store.bind(
                compiled_plan=compiled,
                task_contract=contract,
                source_binding_bundle=source_a,
                registry=registry,
            )
            sink = FakeFileReadEvidenceSink()
            adapters = self._adapters(
                contract=contract,
                budget=budget,
                registry=registry,
                compiled=compiled,
                invocation_bundle=invocation_bundle,
                source_bundle=source_b,
                sink=sink,
            )
            scheduler = ProductionAuditedRuntimeDAGScheduler(
                adapters=adapters,
                invocation_binding_store=RuntimeInvocationBindingStore(
                    Path(tmp) / "invocation_bindings"
                ),
                source_binding_store=source_store,
                observation_ledger=RuntimeObservationLedger(store),
                checkpoint_store=RuntimeCheckpointStore(Path(tmp) / "checkpoints"),
                registry=registry,
            )
            with self.assertRaisesRegex(
                RuntimeSchedulerError,
                "SOURCE_RECOVERY_BUNDLE_CHANGED",
            ):
                scheduler.run(
                    compiled_plan=compiled,
                    task_contract=contract,
                    budget=budget,
                )
            self.assertEqual(budget.snapshot()["steps_used"], 0)
            self.assertEqual(budget.snapshot()["tool_calls_used"], 0)
            self.assertEqual(sink.calls, [])


if __name__ == "__main__":
    unittest.main()
