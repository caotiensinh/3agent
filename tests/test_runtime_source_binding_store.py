import tempfile
import unittest
from pathlib import Path

from three_agent.capability_registry import CapabilityRegistry
from three_agent.runtime_execution_plan import ExecutionNode
from three_agent.runtime_plan_compiler import RuntimePlanCompiler
from three_agent.runtime_source_authority import (
    ReviewedSourceBinding,
    RuntimeSourceBindingBundle,
)
from three_agent.runtime_source_binding_store import (
    RuntimeSourceBindingStore,
    RuntimeSourceBindingStoreError,
)
from three_agent.task_contract import TaskContractCompiler


class RuntimeSourceBindingStoreTests(unittest.TestCase):
    @staticmethod
    def _fixture(tmp, root_name):
        root = Path(tmp) / root_name
        root.mkdir()
        contract = TaskContractCompiler().compile(
            task_id="source_recovery_task",
            task_type="retrieval",
            sensitivity="internal",
            risk_level="low",
            allowed_sources=("repo",),
            allowed_tools=("read_file",),
        )
        registry = CapabilityRegistry.default()
        compiled = RuntimePlanCompiler(registry).compile(
            plan_id="source_recovery_plan",
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
        return contract, registry, compiled, bundle

    def test_store_is_idempotent_for_same_reviewed_source_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            contract, registry, compiled, bundle = self._fixture(tmp, "repo-a")
            store = RuntimeSourceBindingStore(Path(tmp) / "bindings")
            first = store.bind(
                compiled_plan=compiled,
                task_contract=contract,
                source_binding_bundle=bundle,
                registry=registry,
            )
            second = store.bind(
                compiled_plan=compiled,
                task_contract=contract,
                source_binding_bundle=bundle,
                registry=registry,
            )
            self.assertEqual(first.binding_id, second.binding_id)
            self.assertEqual(
                first.source_binding_bundle_fingerprint,
                bundle.fingerprint,
            )

    def test_store_rejects_trusted_root_drift_for_same_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            contract, registry, compiled, original = self._fixture(tmp, "repo-a")
            _, _, same_compiled, changed = self._fixture(tmp, "repo-b")
            self.assertEqual(compiled.fingerprint, same_compiled.fingerprint)
            self.assertNotEqual(original.fingerprint, changed.fingerprint)
            store = RuntimeSourceBindingStore(Path(tmp) / "bindings")
            store.bind(
                compiled_plan=compiled,
                task_contract=contract,
                source_binding_bundle=original,
                registry=registry,
            )
            with self.assertRaisesRegex(
                RuntimeSourceBindingStoreError,
                "SOURCE_RECOVERY_BUNDLE_CHANGED",
            ):
                store.bind(
                    compiled_plan=compiled,
                    task_contract=contract,
                    source_binding_bundle=changed,
                    registry=registry,
                )


if __name__ == "__main__":
    unittest.main()
