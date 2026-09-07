import json
import unittest

from three_agent.capability_authority import (
    CapabilityAuthorityDenied,
    TaskCapabilityAuthority,
)
from three_agent.runtime_execution_plan import (
    ExecutionNode,
    ExecutionObservation,
    RuntimeExecutionPlan,
    RuntimeExecutionPlanError,
)
from three_agent.task_contract import TaskContractCompiler


class RuntimeCoreV3Tests(unittest.TestCase):
    def test_sanitized_internal_allowlisted_egress_matches_task_contract(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-INTERNAL-WEB",
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
            public_web=True,
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        decision = authority.require(
            "web_gateway",
            resource_kind="network",
            resource_ref="sanitized_public_search",
            effect="network_read",
        )
        self.assertTrue(decision.allowed)

    def test_delegation_can_only_reduce_authority(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-PARENT",
            task_type="code_fix",
            sensitivity="internal",
            risk_level="medium",
            write_scope=("src", "tests"),
        )
        parent = TaskCapabilityAuthority.from_contract(contract)
        child = parent.delegate(
            task_id="TASK-PARENT-LANE-A",
            sensitivity="confidential",
            allowed_sources=(),
            allowed_tools=("read_file", "run_tests", "apply_patch"),
            write_scope=("src/three_agent",),
            network_scope="deny",
        )
        self.assertTrue(child.is_subset_of(parent))
        self.assertEqual(child.delegated_from, parent.fingerprint)
        self.assertTrue(
            child.require(
                "apply_patch",
                resource_kind="path",
                resource_ref="src/three_agent/module.py",
                effect="write",
            ).allowed
        )
        with self.assertRaises(CapabilityAuthorityDenied):
            child.require(
                "apply_patch",
                resource_kind="path",
                resource_ref="tests/outside.py",
                effect="write",
            )

    def test_delegation_rejects_tool_network_or_write_widening(self):
        parent = TaskCapabilityAuthority.from_contract(
            TaskContractCompiler().compile(
                task_id="TASK-NARROW",
                task_type="analysis",
                sensitivity="internal",
                risk_level="low",
            )
        )
        with self.assertRaisesRegex(CapabilityAuthorityDenied, "DELEGATED_AUTHORITY_WIDENED"):
            parent.delegate(allowed_tools=parent.allowed_tools + ("apply_patch",))
        with self.assertRaisesRegex(CapabilityAuthorityDenied, "DELEGATED_AUTHORITY_WIDENED"):
            parent.delegate(network_scope="allowlisted_egress")
        with self.assertRaisesRegex(CapabilityAuthorityDenied, "DELEGATED_AUTHORITY_WIDENED"):
            parent.delegate(write_scope=("src",))

    def test_execution_plan_runs_independent_reads_before_join(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-DAG",
            task_type="code_review",
            sensitivity="internal",
            risk_level="low",
        )
        plan = RuntimeExecutionPlan.compile(
            plan_id="plan_dag",
            task_contract=contract,
            max_parallel=4,
            nodes=(
                ExecutionNode("read_source", "read_file", "path", "src/app.py", "read"),
                ExecutionNode("search_tests", "search_repo", "repo", "tests_index", "read"),
                ExecutionNode(
                    "run_tests",
                    "run_tests",
                    "repo",
                    "workspace_tests",
                    "execute",
                    depends_on=("read_source", "search_tests"),
                ),
            ),
        )
        self.assertEqual(
            tuple(node.node_id for node in plan.ready_nodes()),
            ("read_source", "search_tests"),
        )
        self.assertEqual(
            tuple(
                node.node_id
                for node in plan.ready_nodes(completed=("read_source", "search_tests"))
            ),
            ("run_tests",),
        )
        self.assertEqual(plan.topological_order(), ("read_source", "search_tests", "run_tests"))

    def test_execution_plan_rejects_cycle_and_unauthorized_capability(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-BAD-PLAN",
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )
        with self.assertRaisesRegex(RuntimeExecutionPlanError, "contains a cycle"):
            RuntimeExecutionPlan.compile(
                plan_id="cycle_plan",
                task_contract=contract,
                nodes=(
                    ExecutionNode(
                        "node_a", "read_file", "path", "docs/a.md", "read", depends_on=("node_b",)
                    ),
                    ExecutionNode(
                        "node_b", "read_file", "path", "docs/b.md", "read", depends_on=("node_a",)
                    ),
                ),
            )
        with self.assertRaisesRegex(RuntimeExecutionPlanError, "NODE_AUTHORITY_DENIED"):
            RuntimeExecutionPlan.compile(
                plan_id="widened_plan",
                task_contract=contract,
                nodes=(
                    ExecutionNode("patch", "apply_patch", "path", "src/app.py", "write"),
                ),
            )

    def test_high_risk_mutation_requires_approval_and_is_serialized(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-HIGH-WRITE",
            task_type="code_fix",
            sensitivity="internal",
            risk_level="high",
            write_scope=("src",),
        )
        with self.assertRaisesRegex(RuntimeExecutionPlanError, "HIGH_RISK_MUTATION_REQUIRES_APPROVAL"):
            RuntimeExecutionPlan.compile(
                plan_id="unsafe_write",
                task_contract=contract,
                nodes=(ExecutionNode("patch_a", "apply_patch", "path", "src/a.py", "write"),),
            )

        plan = RuntimeExecutionPlan.compile(
            plan_id="safe_writes",
            task_contract=contract,
            max_parallel=4,
            nodes=(
                ExecutionNode(
                    "patch_a",
                    "apply_patch",
                    "path",
                    "src/a.py",
                    "write",
                    approval_required=True,
                    idempotent=False,
                ),
                ExecutionNode(
                    "patch_b",
                    "apply_patch",
                    "path",
                    "src/b.py",
                    "write",
                    approval_required=True,
                    idempotent=False,
                ),
            ),
        )
        self.assertEqual(plan.ready_nodes(), ())
        self.assertEqual(
            tuple(node.node_id for node in plan.ready_nodes(approved=("patch_a", "patch_b"))),
            ("patch_a",),
        )
        self.assertEqual(
            tuple(
                node.node_id
                for node in plan.ready_nodes(
                    completed=("patch_a",), approved=("patch_a", "patch_b")
                )
            ),
            ("patch_b",),
        )

    def test_observation_is_metadata_only_and_stably_binds_result(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-OBS",
            task_type="retrieval",
            sensitivity="internal",
            risk_level="low",
        )
        plan = RuntimeExecutionPlan.compile(
            plan_id="obs_plan",
            task_contract=contract,
            nodes=(ExecutionNode("read_doc", "read_file", "path", "docs/runbook.md", "read"),),
        )
        payload = {"private": "RAW_RESULT_MUST_NOT_APPEAR", "count": 3}
        first = ExecutionObservation.capture(
            plan=plan,
            node_id="read_doc",
            status="succeeded",
            reason_code="READ_OK",
            result=payload,
            evidence_refs=("evidence/task-obs/read-doc.json",),
        )
        second = ExecutionObservation.capture(
            plan=plan,
            node_id="read_doc",
            status="succeeded",
            reason_code="READ_OK",
            result=payload,
            evidence_refs=("evidence/task-obs/read-doc.json",),
        )
        self.assertEqual(first.observation_id, second.observation_id)
        self.assertEqual(first.result_sha256, second.result_sha256)
        encoded = json.dumps(first.metadata(), sort_keys=True)
        self.assertNotIn("RAW_RESULT_MUST_NOT_APPEAR", encoded)
        self.assertNotIn('"private"', encoded)
        self.assertIn("result_sha256", first.metadata())


if __name__ == "__main__":
    unittest.main()
