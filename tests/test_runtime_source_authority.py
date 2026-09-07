import tempfile
import unittest
from pathlib import Path

from three_agent.capability_registry import CapabilityRegistry
from three_agent.runtime_execution_plan import ExecutionNode
from three_agent.runtime_plan_compiler import RuntimePlanCompiler
from three_agent.runtime_source_authority import (
    ReviewedSourceBinding,
    RuntimeSourceAuthorityDenied,
    RuntimeSourceBindingBundle,
)
from three_agent.task_contract import TaskContractCompiler


class RuntimeSourceAuthorityTests(unittest.TestCase):
    @staticmethod
    def _compile(*, allowed_sources, nodes):
        contract = TaskContractCompiler().compile(
            task_id="source_authority_task",
            task_type="retrieval",
            sensitivity="internal",
            risk_level="low",
            allowed_sources=allowed_sources,
            allowed_tools=tuple(node.capability for node in nodes),
        )
        registry = CapabilityRegistry.default()
        compiled = RuntimePlanCompiler(registry).compile(
            plan_id="source_authority_plan",
            task_contract=contract,
            nodes=nodes,
        )
        return contract, registry, compiled

    def test_reviewed_repo_file_binding_is_exact_and_root_confined(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node = ExecutionNode(
                "read",
                "read_file",
                "path",
                "src/app.py",
                "read",
            )
            contract, registry, compiled = self._compile(
                allowed_sources=("repo",),
                nodes=(node,),
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
            self.assertEqual(bundle.for_node("read").source_class, "repo")
            self.assertEqual(bundle.for_node("read").local_root, root.resolve())
            self.assertEqual(bundle.for_node("read").resource_ref, "src/app.py")
            self.assertTrue(bundle.fingerprint.startswith("sha256:"))

    def test_source_class_must_be_explicitly_allowed_by_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = ExecutionNode(
                "read",
                "read_file",
                "path",
                "src/app.py",
                "read",
            )
            contract, registry, compiled = self._compile(
                allowed_sources=("knowledge",),
                nodes=(node,),
            )
            binding = ReviewedSourceBinding.bind(
                compiled_plan=compiled,
                node_id="read",
                source_class="repo",
                local_root=Path(tmp),
            )
            with self.assertRaisesRegex(
                RuntimeSourceAuthorityDenied,
                "SOURCE_CLASS_NOT_ALLOWED",
            ):
                RuntimeSourceBindingBundle.compile(
                    compiled_plan=compiled,
                    task_contract=contract,
                    bindings=(binding,),
                    registry=registry,
                )

    def test_read_file_binding_rejects_path_escape_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = ExecutionNode(
                "read",
                "read_file",
                "path",
                "../secret.txt",
                "read",
            )
            _, _, compiled = self._compile(
                allowed_sources=("repo",),
                nodes=(node,),
            )
            with self.assertRaisesRegex(
                RuntimeSourceAuthorityDenied,
                "SOURCE_RESOURCE_PATH_ESCAPES_ROOT",
            ):
                ReviewedSourceBinding.bind(
                    compiled_plan=compiled,
                    node_id="read",
                    source_class="repo",
                    local_root=Path(tmp),
                )

    def test_bundle_must_cover_every_source_scoped_node_exactly_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            nodes = (
                ExecutionNode(
                    "read",
                    "read_file",
                    "path",
                    "README.md",
                    "read",
                ),
                ExecutionNode(
                    "search",
                    "search_repo",
                    "repo",
                    "workspace_repo",
                    "read",
                ),
            )
            contract, registry, compiled = self._compile(
                allowed_sources=("repo",),
                nodes=nodes,
            )
            read_binding = ReviewedSourceBinding.bind(
                compiled_plan=compiled,
                node_id="read",
                source_class="repo",
                local_root=Path(tmp),
            )
            with self.assertRaisesRegex(
                RuntimeSourceAuthorityDenied,
                "SOURCE_BINDING_BUNDLE_NODE_COVERAGE_MISMATCH",
            ):
                RuntimeSourceBindingBundle.compile(
                    compiled_plan=compiled,
                    task_contract=contract,
                    bindings=(read_binding,),
                    registry=registry,
                )

    def test_non_source_capability_cannot_be_smuggled_into_source_binding(self):
        node = ExecutionNode(
            "calc",
            "calculator",
            "compute",
            "deterministic_math",
            "compute",
        )
        contract, _, compiled = self._compile(
            allowed_sources=("repo",),
            nodes=(node,),
        )
        self.assertEqual(contract.allowed_sources, ("repo",))
        with self.assertRaisesRegex(
            RuntimeSourceAuthorityDenied,
            "SOURCE_CAPABILITY_NOT_SCOPED",
        ):
            ReviewedSourceBinding.bind(
                compiled_plan=compiled,
                node_id="calc",
                source_class="repo",
            )


if __name__ == "__main__":
    unittest.main()
