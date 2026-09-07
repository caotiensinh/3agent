import json
import os
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
from three_agent.runtime_production_adapters import (
    ProductionCapabilityAdapterRegistry,
    RuntimeProductionAdapterError,
)
from three_agent.runtime_production_scheduler import ProductionAuditedRuntimeDAGScheduler
from three_agent.runtime_reviewed_search import ReviewedRepoSearchBoundary
from three_agent.runtime_source_authority import (
    ReviewedSourceBinding,
    RuntimeSourceBindingBundle,
)
from three_agent.runtime_source_binding_store import RuntimeSourceBindingStore
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler


class FakeRepoSearchEvidenceSink:
    def __init__(self):
        self.calls = []

    def persist_repo_search(
        self,
        *,
        task_id,
        node_id,
        source_class,
        resource_ref,
        query_sha256,
        result,
        result_sha256,
    ):
        self.calls.append(
            (
                task_id,
                node_id,
                source_class,
                resource_ref,
                query_sha256,
                result,
                result_sha256,
            )
        )
        return ("artifact:repo-search-evidence",)


class RuntimeProductionRepoSearchTests(unittest.TestCase):
    @staticmethod
    def _task(tmp):
        store = TaskStore(Path(tmp) / "tasks.db")
        store.initialize()
        task = store.create_task("production repo search", "reviewed repo search fixture")
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type="retrieval",
            sensitivity="internal",
            risk_level="low",
            allowed_sources=("repo",),
            allowed_tools=("search_repo",),
            write_scope="none",
        )
        store.bind_task_contract(task.task_id, contract.to_dict())
        budget = TaskExecutionBudgetState.from_bound_contract(store, task.task_id)
        return store, contract, budget

    @staticmethod
    def _plan(contract, *, query="needle", max_results=20):
        registry = CapabilityRegistry.default()
        compiled = RuntimePlanCompiler(registry).compile(
            plan_id="production_repo_search",
            task_contract=contract,
            nodes=(
                ExecutionNode(
                    "search",
                    "search_repo",
                    "repo",
                    "workspace_repo",
                    "read",
                ),
            ),
        )
        typed = TypedCapabilityInvocation.compile(
            compiled_plan=compiled,
            node_id="search",
            operation="search",
            arguments={"query": query, "max_results": max_results},
        )
        invocation_bundle = RuntimeInvocationBundle.compile(
            compiled_plan=compiled,
            invocations=(typed,),
        )
        return registry, compiled, invocation_bundle

    @staticmethod
    def _source(*, root, contract, registry, compiled):
        binding = ReviewedSourceBinding.bind(
            compiled_plan=compiled,
            node_id="search",
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
        boundary = ReviewedRepoSearchBoundary(
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
            repo_search_boundary=boundary,
            source_binding_bundle=source_bundle,
            registry=registry,
        )

    @staticmethod
    def _scheduler(tmp, store, adapters):
        return ProductionAuditedRuntimeDAGScheduler(
            adapters=adapters,
            invocation_binding_store=RuntimeInvocationBindingStore(
                Path(tmp) / "invocation_bindings"
            ),
            source_binding_store=RuntimeSourceBindingStore(
                Path(tmp) / "source_bindings"
            ),
            observation_ledger=RuntimeObservationLedger(store),
            checkpoint_store=RuntimeCheckpointStore(Path(tmp) / "checkpoints"),
            registry=adapters.capability_registry,
        )

    def test_repo_search_is_metered_once_bounded_and_persists_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            (root / "src").mkdir(parents=True)
            (root / "src" / "a.py").write_text("alpha\nneedle first\nomega\n", encoding="utf-8")
            (root / "src" / "b.py").write_text("needle second\n", encoding="utf-8")
            store, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(
                contract,
                max_results=1,
            )
            binding, source_bundle = self._source(
                root=root,
                contract=contract,
                registry=registry,
                compiled=compiled,
            )
            sink = FakeRepoSearchEvidenceSink()
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
            self.assertEqual(result.observations[0].reason_code, "SEARCH_REPO_OK")
            self.assertEqual(
                result.observations[0].evidence_refs,
                ("artifact:repo-search-evidence",),
            )
            self.assertEqual(snapshot["steps_used"], 1)
            self.assertEqual(snapshot["tool_calls_used"], 1)
            self.assertEqual(len(sink.calls), 1)
            payload = json.loads(sink.calls[0][5].decode("utf-8"))
            self.assertEqual(payload["match_count"], 1)
            self.assertEqual(len(payload["matches"]), 1)
            self.assertEqual(payload["matches"][0]["path"], "src/a.py")
            self.assertEqual(payload["matches"][0]["line"], 2)
            self.assertIn("needle first", payload["matches"][0]["excerpt"])
            self.assertTrue(binding.fingerprint.startswith("sha256:"))
            self.assertNotIn(str(root.resolve()), str(source_bundle.metadata()))

    def test_repo_search_does_not_follow_file_or_directory_symlinks(self):
        if os.name != "posix":
            self.skipTest("secure nofollow traversal is POSIX-only")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            outside = Path(tmp) / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "safe.txt").write_text("needle approved\n", encoding="utf-8")
            (outside / "secret.txt").write_text("needle secret\n", encoding="utf-8")
            (root / "secret-link.txt").symlink_to(outside / "secret.txt")
            (root / "outside-link").symlink_to(outside, target_is_directory=True)
            store, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(contract)
            _, source_bundle = self._source(
                root=root,
                contract=contract,
                registry=registry,
                compiled=compiled,
            )
            sink = FakeRepoSearchEvidenceSink()
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
            self.assertEqual(result.status, "completed")
            payload = json.loads(sink.calls[0][5].decode("utf-8"))
            paths = {item["path"] for item in payload["matches"]}
            excerpts = " ".join(item["excerpt"] for item in payload["matches"])
            self.assertEqual(paths, {"safe.txt"})
            self.assertNotIn("secret", excerpts)

    def test_live_revocation_denies_before_repo_io_or_tool_charge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "safe.txt").write_text("needle\n", encoding="utf-8")
            store, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(contract)
            _, source_bundle = self._source(
                root=root,
                contract=contract,
                registry=registry,
                compiled=compiled,
            )
            sink = FakeRepoSearchEvidenceSink()
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
                "search_repo",
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

    def test_search_repo_requires_reviewed_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            _, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(contract)
            _, source_bundle = self._source(
                root=root,
                contract=contract,
                registry=registry,
                compiled=compiled,
            )
            with self.assertRaisesRegex(
                RuntimeProductionAdapterError,
                "REVIEWED_REPO_SEARCH_BOUNDARY_REQUIRED",
            ):
                ProductionCapabilityAdapterRegistry(
                    compiled_plan=compiled,
                    task_contract=contract,
                    invocation_bundle=invocation_bundle,
                    budget=budget,
                    source_binding_bundle=source_bundle,
                    registry=registry,
                )


if __name__ == "__main__":
    unittest.main()
