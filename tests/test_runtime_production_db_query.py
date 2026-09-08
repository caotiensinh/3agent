import json
import sqlite3
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
from three_agent.runtime_readonly_query import (
    ReviewedQueryParameterSet,
    ReviewedReadonlyQueryProfile,
    RuntimeReadonlyQueryBundle,
)
from three_agent.runtime_readonly_query_binding_store import RuntimeQueryBindingStore
from three_agent.runtime_reviewed_db_query import (
    ReviewedDbQueryError,
    ReviewedReadonlyDatabaseQueryBoundary,
)
from three_agent.runtime_source_authority import ReviewedSourceBinding, RuntimeSourceBindingBundle
from three_agent.runtime_source_binding_store import RuntimeSourceBindingStore
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler


class FakeDatabaseEvidenceSink:
    def __init__(self):
        self.calls = []

    def persist_db_query(
        self,
        *,
        task_id,
        node_id,
        source_class,
        resource_ref,
        query_ref,
        sql_sha256,
        parameters_sha256,
        result,
        result_sha256,
    ):
        self.calls.append(
            (
                task_id,
                node_id,
                source_class,
                resource_ref,
                query_ref,
                sql_sha256,
                parameters_sha256,
                result,
                result_sha256,
            )
        )
        return ("artifact:db-query-evidence",)


class RuntimeProductionDbQueryTests(unittest.TestCase):
    @staticmethod
    def _database(tmp, *, rows=2):
        root = Path(tmp) / "database"
        root.mkdir()
        path = root / "workspace.db"
        with sqlite3.connect(path) as conn:
            conn.execute(
                "CREATE TABLE tasks(task_id TEXT PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL)"
            )
            values = [
                ("TASK-SECRET-001", "sensitive row payload", "open"),
                ("TASK-002", "ordinary row", "closed"),
            ][:rows]
            conn.executemany(
                "INSERT INTO tasks(task_id,title,status) VALUES(?,?,?)",
                values,
            )
        return root, path

    @staticmethod
    def _task(tmp):
        store = TaskStore(Path(tmp) / "runtime" / "tasks.db")
        store.initialize()
        task = store.create_task("production db query", "reviewed sqlite query fixture")
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type="sensitive_query",
            sensitivity="confidential",
            risk_level="low",
            allowed_sources=("workspace_db",),
            allowed_tools=("query_db_readonly",),
            write_scope="none",
        )
        store.bind_task_contract(task.task_id, contract.to_dict())
        budget = TaskExecutionBudgetState.from_bound_contract(store, task.task_id)
        return store, contract, budget

    @staticmethod
    def _plan(contract, *, query_ref="task_by_id", parameters_ref="params-task-1"):
        registry = CapabilityRegistry.default()
        compiled = RuntimePlanCompiler(registry).compile(
            plan_id="production_db_query",
            task_contract=contract,
            nodes=(
                ExecutionNode(
                    "db",
                    "query_db_readonly",
                    "database",
                    "workspace.db",
                    "read",
                ),
            ),
        )
        arguments = {"query_ref": query_ref}
        if parameters_ref is not None:
            arguments["parameters_ref"] = parameters_ref
        typed = TypedCapabilityInvocation.compile(
            compiled_plan=compiled,
            node_id="db",
            operation="query",
            arguments=arguments,
        )
        invocation_bundle = RuntimeInvocationBundle.compile(
            compiled_plan=compiled,
            invocations=(typed,),
        )
        return registry, compiled, invocation_bundle

    @staticmethod
    def _query_bundle(compiled, invocation_bundle, *, all_rows=False):
        if all_rows:
            profile = ReviewedReadonlyQueryProfile.compile(
                "all_tasks",
                "SELECT task_id, title, status FROM tasks ORDER BY task_id",
            )
            return RuntimeReadonlyQueryBundle.compile(
                compiled_plan=compiled,
                invocation_bundle=invocation_bundle,
                profiles=(profile,),
            )
        profile = ReviewedReadonlyQueryProfile.compile(
            "task_by_id",
            "SELECT task_id, title, status FROM tasks WHERE task_id = :task_id",
            parameter_names=("task_id",),
        )
        params = ReviewedQueryParameterSet.compile(
            "params-task-1",
            {"task_id": "TASK-SECRET-001"},
        )
        return RuntimeReadonlyQueryBundle.compile(
            compiled_plan=compiled,
            invocation_bundle=invocation_bundle,
            profiles=(profile,),
            parameter_sets=(params,),
        )

    @staticmethod
    def _source(*, root, contract, registry, compiled, with_root=True):
        binding = ReviewedSourceBinding.bind(
            compiled_plan=compiled,
            node_id="db",
            source_class="workspace_db",
            local_root=root if with_root else None,
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
        query_bundle,
        source_bundle,
        sink,
        max_rows=100,
    ):
        boundary = ReviewedReadonlyDatabaseQueryBoundary(
            compiled_plan=compiled,
            task_contract=contract,
            invocation_bundle=invocation_bundle,
            query_bundle=query_bundle,
            source_binding_bundle=source_bundle,
            evidence_sink=sink,
            registry=registry,
            max_rows=max_rows,
        )
        return ProductionCapabilityAdapterRegistry(
            compiled_plan=compiled,
            task_contract=contract,
            invocation_bundle=invocation_bundle,
            budget=budget,
            db_query_boundary=boundary,
            readonly_query_bundle=query_bundle,
            source_binding_bundle=source_bundle,
            registry=registry,
        )

    @staticmethod
    def _scheduler(tmp, store, adapters, *, with_query_store=True):
        kwargs = {}
        if with_query_store:
            kwargs["query_binding_store"] = RuntimeQueryBindingStore(
                Path(tmp) / "query_bindings"
            )
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
            **kwargs,
        )

    def test_readonly_query_executes_reviewed_profile_and_keeps_raw_rows_in_evidence_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_root, db_path = self._database(tmp)
            store, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(contract)
            query_bundle = self._query_bundle(compiled, invocation_bundle)
            binding, source_bundle = self._source(
                root=db_root,
                contract=contract,
                registry=registry,
                compiled=compiled,
            )
            sink = FakeDatabaseEvidenceSink()
            adapters = self._adapters(
                contract=contract,
                budget=budget,
                registry=registry,
                compiled=compiled,
                invocation_bundle=invocation_bundle,
                query_bundle=query_bundle,
                source_bundle=source_bundle,
                sink=sink,
            )
            before = db_path.stat()
            result = self._scheduler(tmp, store, adapters).run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            after = db_path.stat()

            self.assertEqual(result.status, "completed")
            self.assertEqual(result.observations[0].status, "succeeded")
            self.assertEqual(result.observations[0].reason_code, "DB_QUERY_READONLY_OK")
            self.assertEqual(
                result.observations[0].evidence_refs,
                ("artifact:db-query-evidence",),
            )
            self.assertEqual(budget.snapshot()["steps_used"], 1)
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)
            self.assertEqual(len(sink.calls), 1)
            payload = json.loads(sink.calls[0][7].decode("utf-8"))
            self.assertEqual(payload["row_count"], 1)
            self.assertEqual(payload["rows"][0][0], "TASK-SECRET-001")
            self.assertEqual(payload["rows"][0][1], "sensitive row payload")
            self.assertEqual(payload["sql_sha256"], query_bundle.profile("task_by_id").sql_sha256)
            self.assertEqual(before.st_size, after.st_size)
            self.assertEqual(before.st_mtime_ns, after.st_mtime_ns)
            self.assertTrue(binding.fingerprint.startswith("sha256:"))

            observation_text = json.dumps(
                result.observations[0].metadata(),
                ensure_ascii=False,
                sort_keys=True,
            )
            self.assertNotIn("sensitive row payload", observation_text)
            self.assertNotIn("TASK-SECRET-001", observation_text)
            self.assertNotIn("SELECT task_id", observation_text)

            sidecars = list((Path(tmp) / "query_bindings").rglob("*.json"))
            self.assertEqual(len(sidecars), 1)
            sidecar = sidecars[0].read_text(encoding="utf-8")
            self.assertNotIn("sensitive row payload", sidecar)
            self.assertNotIn("TASK-SECRET-001", sidecar)
            self.assertNotIn("SELECT task_id", sidecar)
            self.assertIn(query_bundle.fingerprint, sidecar)

    def test_live_revocation_denies_before_database_io_evidence_or_tool_charge(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_root, _ = self._database(tmp)
            store, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(contract)
            query_bundle = self._query_bundle(compiled, invocation_bundle)
            _, source_bundle = self._source(
                root=db_root,
                contract=contract,
                registry=registry,
                compiled=compiled,
            )
            sink = FakeDatabaseEvidenceSink()
            adapters = self._adapters(
                contract=contract,
                budget=budget,
                registry=registry,
                compiled=compiled,
                invocation_bundle=invocation_bundle,
                query_bundle=query_bundle,
                source_bundle=source_bundle,
                sink=sink,
            )
            TaskCapabilityRevocationStore(store).revoke(
                contract.task_id,
                "query_db_readonly",
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

    def test_database_symlink_escape_is_rejected_before_evidence_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / "outside.db"
            with sqlite3.connect(outside) as conn:
                conn.execute("CREATE TABLE tasks(task_id TEXT, title TEXT, status TEXT)")
                conn.execute(
                    "INSERT INTO tasks VALUES('TASK-SECRET-001','outside secret','open')"
                )
            root = Path(tmp) / "database"
            root.mkdir()
            try:
                (root / "workspace.db").symlink_to(outside)
            except OSError:
                self.skipTest("symlink creation unavailable")

            store, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(contract)
            query_bundle = self._query_bundle(compiled, invocation_bundle)
            _, source_bundle = self._source(
                root=root,
                contract=contract,
                registry=registry,
                compiled=compiled,
            )
            sink = FakeDatabaseEvidenceSink()
            adapters = self._adapters(
                contract=contract,
                budget=budget,
                registry=registry,
                compiled=compiled,
                invocation_bundle=invocation_bundle,
                query_bundle=query_bundle,
                source_bundle=source_bundle,
                sink=sink,
            )
            result = self._scheduler(tmp, store, adapters).run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.observations[0].reason_code, "DB_QUERY_REGULAR_DATABASE_REQUIRED")
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)
            self.assertEqual(sink.calls, [])

    def test_database_boundary_requires_runtime_bound_trusted_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, contract, _ = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(contract)
            query_bundle = self._query_bundle(compiled, invocation_bundle)
            _, source_bundle = self._source(
                root=Path(tmp),
                contract=contract,
                registry=registry,
                compiled=compiled,
                with_root=False,
            )
            with self.assertRaisesRegex(
                ReviewedDbQueryError,
                "DB_QUERY_TRUSTED_ROOT_REQUIRED",
            ):
                ReviewedReadonlyDatabaseQueryBoundary(
                    compiled_plan=compiled,
                    task_contract=contract,
                    invocation_bundle=invocation_bundle,
                    query_bundle=query_bundle,
                    source_binding_bundle=source_bundle,
                    evidence_sink=FakeDatabaseEvidenceSink(),
                    registry=registry,
                )

    def test_row_limit_fails_closed_without_persisting_partial_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_root, _ = self._database(tmp)
            store, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(
                contract,
                query_ref="all_tasks",
                parameters_ref=None,
            )
            query_bundle = self._query_bundle(compiled, invocation_bundle, all_rows=True)
            _, source_bundle = self._source(
                root=db_root,
                contract=contract,
                registry=registry,
                compiled=compiled,
            )
            sink = FakeDatabaseEvidenceSink()
            adapters = self._adapters(
                contract=contract,
                budget=budget,
                registry=registry,
                compiled=compiled,
                invocation_bundle=invocation_bundle,
                query_bundle=query_bundle,
                source_bundle=source_bundle,
                sink=sink,
                max_rows=1,
            )
            result = self._scheduler(tmp, store, adapters).run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.observations[0].reason_code, "DB_QUERY_ROW_LIMIT_EXCEEDED")
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)
            self.assertEqual(sink.calls, [])

    def test_query_db_requires_reviewed_query_boundary_and_durable_query_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_root, _ = self._database(tmp)
            store, contract, budget = self._task(tmp)
            registry, compiled, invocation_bundle = self._plan(contract)
            query_bundle = self._query_bundle(compiled, invocation_bundle)
            _, source_bundle = self._source(
                root=db_root,
                contract=contract,
                registry=registry,
                compiled=compiled,
            )
            with self.assertRaisesRegex(
                RuntimeProductionAdapterError,
                "REVIEWED_DB_QUERY_BOUNDARY_REQUIRED",
            ):
                ProductionCapabilityAdapterRegistry(
                    compiled_plan=compiled,
                    task_contract=contract,
                    invocation_bundle=invocation_bundle,
                    budget=budget,
                    readonly_query_bundle=query_bundle,
                    source_binding_bundle=source_bundle,
                    registry=registry,
                )

            sink = FakeDatabaseEvidenceSink()
            adapters = self._adapters(
                contract=contract,
                budget=budget,
                registry=registry,
                compiled=compiled,
                invocation_bundle=invocation_bundle,
                query_bundle=query_bundle,
                source_bundle=source_bundle,
                sink=sink,
            )
            with self.assertRaisesRegex(
                Exception,
                "DURABLE_QUERY_BINDING_STORE_REQUIRED",
            ):
                self._scheduler(
                    tmp,
                    store,
                    adapters,
                    with_query_store=False,
                )


if __name__ == "__main__":
    unittest.main()
