import json
import tempfile
import unittest
from pathlib import Path

from three_agent.capability_registry import CapabilityRegistry
from three_agent.runtime_execution_plan import ExecutionNode
from three_agent.runtime_invocation import RuntimeInvocationBundle, TypedCapabilityInvocation
from three_agent.runtime_plan_compiler import RuntimePlanCompiler
from three_agent.runtime_readonly_query import (
    ReviewedQueryParameterSet,
    ReviewedReadonlyQueryProfile,
    RuntimeReadonlyQueryBundle,
    RuntimeReadonlyQueryError,
)
from three_agent.runtime_readonly_query_binding_store import (
    RuntimeQueryBindingStore,
    RuntimeQueryBindingStoreError,
)
from three_agent.task_contract import TaskContractCompiler


class RuntimeReadonlyQueryTests(unittest.TestCase):
    @staticmethod
    def _plan(*, query_ref="task_by_id", parameters_ref="params-task-1"):
        contract = TaskContractCompiler().compile(
            task_id="readonly_query_task",
            task_type="sensitive_query",
            sensitivity="confidential",
            risk_level="low",
            allowed_sources=("workspace_db",),
            allowed_tools=("query_db_readonly",),
            write_scope="none",
        )
        registry = CapabilityRegistry.default()
        compiled = RuntimePlanCompiler(registry).compile(
            plan_id="readonly_query_plan",
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
        args = {"query_ref": query_ref}
        if parameters_ref is not None:
            args["parameters_ref"] = parameters_ref
        typed = TypedCapabilityInvocation.compile(
            compiled_plan=compiled,
            node_id="db",
            operation="query",
            arguments=args,
        )
        invocation_bundle = RuntimeInvocationBundle.compile(
            compiled_plan=compiled,
            invocations=(typed,),
        )
        return contract, registry, compiled, invocation_bundle

    @staticmethod
    def _profile(sql="SELECT task_id, status FROM tasks WHERE task_id = :task_id"):
        return ReviewedReadonlyQueryProfile.compile(
            "task_by_id",
            sql,
            parameter_names=("task_id",),
        )

    @staticmethod
    def _params(value="TASK-1"):
        return ReviewedQueryParameterSet.compile(
            "params-task-1",
            {"task_id": value},
        )

    def test_bundle_binds_query_and_parameters_without_exposing_raw_values(self):
        _, _, compiled, invocation_bundle = self._plan()
        profile = self._profile()
        params = self._params("TASK-SECRET-001")
        bundle = RuntimeReadonlyQueryBundle.compile(
            compiled_plan=compiled,
            invocation_bundle=invocation_bundle,
            profiles=(profile,),
            parameter_sets=(params,),
        )
        metadata = json.dumps(bundle.metadata(), sort_keys=True)
        self.assertTrue(bundle.fingerprint.startswith("sha256:"))
        self.assertNotIn("SELECT task_id", metadata)
        self.assertNotIn("TASK-SECRET-001", metadata)
        self.assertIn(profile.sql_sha256, metadata)
        self.assertIn(params.values_sha256, metadata)
        self.assertEqual(bundle.profile("task_by_id").sql, profile.sql)
        self.assertEqual(bundle.parameter_set("params-task-1").values["task_id"], "TASK-SECRET-001")

    def test_profile_rejects_mutation_attach_pragma_and_multiple_statements(self):
        rejected = (
            "DELETE FROM tasks",
            "SELECT 1; DELETE FROM tasks",
            "ATTACH DATABASE '/tmp/other.db' AS other",
            "PRAGMA table_info(tasks)",
            "WITH x AS (SELECT 1) DELETE FROM tasks",
        )
        for sql in rejected:
            with self.subTest(sql=sql):
                with self.assertRaises(RuntimeReadonlyQueryError):
                    ReviewedReadonlyQueryProfile.compile("bad", sql)

    def test_forged_profile_replays_sql_safety_not_only_digest(self):
        dangerous = "WITH x AS (SELECT 1) DELETE FROM tasks"
        import hashlib

        forged = ReviewedReadonlyQueryProfile(
            profile_id="task_by_id",
            sql_sha256="sha256:" + hashlib.sha256(dangerous.encode("utf-8")).hexdigest(),
            parameter_names=(),
            _sql=dangerous,
        )
        with self.assertRaisesRegex(RuntimeReadonlyQueryError, "QUERY_SQL_FORBIDDEN_TOKEN"):
            forged.validate()

    def test_bundle_requires_exact_parameter_coverage(self):
        _, _, compiled, invocation_bundle = self._plan()
        profile = self._profile()
        wrong = ReviewedQueryParameterSet.compile(
            "params-task-1",
            {"different": "TASK-1"},
        )
        with self.assertRaisesRegex(RuntimeReadonlyQueryError, "QUERY_PARAMETER_KEYS_MISMATCH"):
            RuntimeReadonlyQueryBundle.compile(
                compiled_plan=compiled,
                invocation_bundle=invocation_bundle,
                profiles=(profile,),
                parameter_sets=(wrong,),
            )

    def test_parameterized_profile_requires_opaque_parameters_ref(self):
        _, _, compiled, invocation_bundle = self._plan(parameters_ref=None)
        with self.assertRaisesRegex(RuntimeReadonlyQueryError, "QUERY_PARAMETERS_REF_REQUIRED"):
            RuntimeReadonlyQueryBundle.compile(
                compiled_plan=compiled,
                invocation_bundle=invocation_bundle,
                profiles=(self._profile(),),
                parameter_sets=(),
            )

    def test_recovery_store_rejects_same_ref_remapped_to_changed_sql(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, compiled, invocation_bundle = self._plan()
            original = RuntimeReadonlyQueryBundle.compile(
                compiled_plan=compiled,
                invocation_bundle=invocation_bundle,
                profiles=(self._profile(),),
                parameter_sets=(self._params(),),
            )
            changed = RuntimeReadonlyQueryBundle.compile(
                compiled_plan=compiled,
                invocation_bundle=invocation_bundle,
                profiles=(
                    self._profile(
                        "SELECT task_id, title FROM tasks WHERE task_id = :task_id"
                    ),
                ),
                parameter_sets=(self._params(),),
            )
            self.assertNotEqual(original.fingerprint, changed.fingerprint)
            store = RuntimeQueryBindingStore(Path(tmp) / "query_bindings")
            first = store.bind(
                compiled_plan=compiled,
                invocation_bundle=invocation_bundle,
                query_bundle=original,
            )
            second = store.bind(
                compiled_plan=compiled,
                invocation_bundle=invocation_bundle,
                query_bundle=original,
            )
            self.assertEqual(first.binding_id, second.binding_id)
            with self.assertRaisesRegex(
                RuntimeQueryBindingStoreError,
                "QUERY_RECOVERY_BUNDLE_CHANGED",
            ):
                store.bind(
                    compiled_plan=compiled,
                    invocation_bundle=invocation_bundle,
                    query_bundle=changed,
                )

    def test_recovery_sidecar_persists_only_fingerprints(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, compiled, invocation_bundle = self._plan()
            profile = self._profile()
            params = self._params("TASK-SENSITIVE-VALUE")
            bundle = RuntimeReadonlyQueryBundle.compile(
                compiled_plan=compiled,
                invocation_bundle=invocation_bundle,
                profiles=(profile,),
                parameter_sets=(params,),
            )
            root = Path(tmp) / "query_bindings"
            store = RuntimeQueryBindingStore(root)
            store.bind(
                compiled_plan=compiled,
                invocation_bundle=invocation_bundle,
                query_bundle=bundle,
            )
            paths = list(root.rglob("*.json"))
            self.assertEqual(len(paths), 1)
            raw = paths[0].read_text(encoding="utf-8")
            self.assertNotIn(profile.sql, raw)
            self.assertNotIn("TASK-SENSITIVE-VALUE", raw)
            self.assertIn(bundle.fingerprint, raw)


if __name__ == "__main__":
    unittest.main()
