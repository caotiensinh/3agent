from dataclasses import replace
import unittest

from three_agent.runtime_execution_plan import ExecutionNode
from three_agent.runtime_invocation import (
    RuntimeInvocationBundle,
    RuntimeInvocationError,
    TypedCapabilityInvocation,
)
from three_agent.runtime_plan_compiler import RuntimePlanCompiler
from three_agent.task_contract import TaskContractCompiler


class RuntimeInvocationTests(unittest.TestCase):
    @staticmethod
    def _compiled_plan():
        contract = TaskContractCompiler().compile(
            task_id="TASK-TYPED-INVOKE",
            task_type="code_fix",
            sensitivity="internal",
            risk_level="low",
            allowed_tools=("run_tests", "apply_patch", "web_gateway"),
            write_scope=("staging",),
            public_web=True,
        )
        compiled = RuntimePlanCompiler().compile(
            plan_id="typed_invocation",
            task_contract=contract,
            nodes=(
                ExecutionNode(
                    "tests",
                    "run_tests",
                    "repo",
                    "workspace_tests",
                    "execute",
                ),
                ExecutionNode(
                    "patch",
                    "apply_patch",
                    "path",
                    "staging/a.py",
                    "write",
                    depends_on=("tests",),
                    idempotent=False,
                ),
                ExecutionNode(
                    "web",
                    "web_gateway",
                    "network",
                    "public_search",
                    "network_read",
                ),
            ),
        )
        return contract, compiled

    def test_bundle_is_plan_bound_complete_and_deterministic(self):
        _, compiled = self._compiled_plan()
        tests = TypedCapabilityInvocation.compile(
            compiled_plan=compiled,
            node_id="tests",
            operation="run",
            arguments={"suite": "unit"},
        )
        patch = TypedCapabilityInvocation.compile(
            compiled_plan=compiled,
            node_id="patch",
            operation="apply",
            arguments={
                "patch_ref": "artifact:patch-001",
                "patch_sha256": "sha256:" + "a" * 64,
            },
        )
        web = TypedCapabilityInvocation.compile(
            compiled_plan=compiled,
            node_id="web",
            operation="search",
            arguments={"query": "python sqlite atomic transaction", "count": 5},
        )
        bundle = RuntimeInvocationBundle.compile(
            compiled_plan=compiled,
            invocations=(web, patch, tests),
        )
        self.assertEqual(bundle.for_node("tests").capability, "run_tests")
        self.assertEqual(bundle.for_node("patch").resource_ref, "staging/a.py")
        self.assertEqual(len(bundle.fingerprint), 71)

        same = RuntimeInvocationBundle.compile(
            compiled_plan=compiled,
            invocations=(tests, patch, web),
        )
        self.assertEqual(bundle.fingerprint, same.fingerprint)

    def test_raw_execution_and_network_fields_are_denied(self):
        _, compiled = self._compiled_plan()
        with self.assertRaisesRegex(
            RuntimeInvocationError,
            "TYPED_INVOCATION_RAW_EXECUTION_FIELD_DENIED:argv",
        ):
            TypedCapabilityInvocation.compile(
                compiled_plan=compiled,
                node_id="tests",
                operation="run",
                arguments={"argv": "pytest -q"},
            )

        with self.assertRaisesRegex(
            RuntimeInvocationError,
            "TYPED_INVOCATION_RAW_EXECUTION_FIELD_DENIED:url",
        ):
            TypedCapabilityInvocation.compile(
                compiled_plan=compiled,
                node_id="web",
                operation="search",
                arguments={
                    "query": "release notes",
                    "url": "https://example.com/private-endpoint",
                },
            )

    def test_write_invocation_requires_artifact_ref_and_digest(self):
        _, compiled = self._compiled_plan()
        with self.assertRaisesRegex(
            RuntimeInvocationError,
            "TYPED_INVOCATION_REQUIRED_ARGUMENT_MISSING:patch_sha256",
        ):
            TypedCapabilityInvocation.compile(
                compiled_plan=compiled,
                node_id="patch",
                operation="apply",
                arguments={"patch_ref": "artifact:patch-001"},
            )

        with self.assertRaisesRegex(RuntimeInvocationError, "must be a sha256 digest"):
            TypedCapabilityInvocation.compile(
                compiled_plan=compiled,
                node_id="patch",
                operation="apply",
                arguments={
                    "patch_ref": "artifact:patch-001",
                    "patch_sha256": "not-a-digest",
                },
            )

    def test_non_string_keys_and_url_shaped_refs_are_denied(self):
        _, compiled = self._compiled_plan()
        with self.assertRaisesRegex(
            RuntimeInvocationError,
            "TYPED_INVOCATION_ARGUMENT_KEY_TYPE_INVALID",
        ):
            TypedCapabilityInvocation.compile(
                compiled_plan=compiled,
                node_id="web",
                operation="search",
                arguments={1: "not-a-string-key"},
            )

        with self.assertRaisesRegex(
            RuntimeInvocationError,
            "patch_ref must be a compact non-URL identifier",
        ):
            TypedCapabilityInvocation.compile(
                compiled_plan=compiled,
                node_id="patch",
                operation="apply",
                arguments={
                    "patch_ref": "https://example.com/patch.diff",
                    "patch_sha256": "sha256:" + "c" * 64,
                },
            )

        with self.assertRaisesRegex(
            RuntimeInvocationError,
            "TYPED_INVOCATION_ARGUMENT_KEY_COLLISION",
        ):
            TypedCapabilityInvocation.compile(
                compiled_plan=compiled,
                node_id="web",
                operation="search",
                arguments={"query": "one", " query ": "two"},
            )

    def test_bundle_rejects_missing_duplicate_or_forged_node_binding(self):
        _, compiled = self._compiled_plan()
        tests = TypedCapabilityInvocation.compile(
            compiled_plan=compiled,
            node_id="tests",
            operation="run",
            arguments={},
        )
        patch = TypedCapabilityInvocation.compile(
            compiled_plan=compiled,
            node_id="patch",
            operation="apply",
            arguments={
                "patch_ref": "artifact:patch-001",
                "patch_sha256": "sha256:" + "b" * 64,
            },
        )
        web = TypedCapabilityInvocation.compile(
            compiled_plan=compiled,
            node_id="web",
            operation="search",
            arguments={"query": "runtime security"},
        )
        with self.assertRaisesRegex(
            RuntimeInvocationError,
            "TYPED_INVOCATION_BUNDLE_NODE_COVERAGE_MISMATCH",
        ):
            RuntimeInvocationBundle.compile(
                compiled_plan=compiled,
                invocations=(tests, patch),
            )
        with self.assertRaisesRegex(
            RuntimeInvocationError,
            "TYPED_INVOCATION_BUNDLE_DUPLICATE_NODE",
        ):
            RuntimeInvocationBundle.compile(
                compiled_plan=compiled,
                invocations=(tests, tests, web),
            )
        forged = replace(patch, resource_ref="staging/b.py")
        with self.assertRaisesRegex(
            RuntimeInvocationError,
            "TYPED_INVOCATION_NODE_BINDING_MISMATCH",
        ):
            forged.validate(compiled)

    def test_invocation_fingerprint_changes_when_typed_data_changes(self):
        _, compiled = self._compiled_plan()
        first = TypedCapabilityInvocation.compile(
            compiled_plan=compiled,
            node_id="web",
            operation="search",
            arguments={"query": "sqlite durability", "count": 3},
        )
        second = TypedCapabilityInvocation.compile(
            compiled_plan=compiled,
            node_id="web",
            operation="search",
            arguments={"query": "sqlite durability", "count": 4},
        )
        self.assertNotEqual(first.fingerprint, second.fingerprint)


if __name__ == "__main__":
    unittest.main()
