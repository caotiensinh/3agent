import json
import unittest
from dataclasses import replace

from three_agent.capability_registry import CapabilityDescriptor, CapabilityRegistry
from three_agent.runtime_execution_plan import ExecutionNode
from three_agent.runtime_plan_compiler import RuntimePlanCompiler, RuntimePlanCompilerError
from three_agent.task_contract import TOOLS, TaskContractCompiler


class RuntimePlanCompilerTests(unittest.TestCase):
    def test_planner_context_contains_only_authority_filtered_capabilities_and_budget(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-PLAN-CONTEXT",
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )
        context = RuntimePlanCompiler().planner_context(contract)
        self.assertEqual(
            {row["capability_id"] for row in context["capabilities"]},
            {"read_file", "search_docs"},
        )
        self.assertEqual(context["execution_budget"]["max_steps"], contract.execution_budget.max_steps)
        encoded = json.dumps(context, sort_keys=True).lower()
        self.assertNotIn("write_scope", encoded)
        self.assertNotIn("allowed_sources", encoded)
        self.assertNotIn("http://", encoded)
        self.assertNotIn("https://", encoded)

    def test_compile_binds_registry_authority_and_plan(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-PLAN-COMPILE",
            task_type="code_review",
            sensitivity="internal",
            risk_level="low",
        )
        compiler = RuntimePlanCompiler()
        compiled = compiler.compile(
            plan_id="plan_compile",
            task_contract=contract,
            nodes=(
                ExecutionNode("read_source", "read_file", "path", "src/app.py", "read"),
                ExecutionNode("search_repo", "search_repo", "repo", "workspace_repo", "read"),
                ExecutionNode(
                    "run_tests",
                    "run_tests",
                    "repo",
                    "workspace_tests",
                    "execute",
                    depends_on=("read_source", "search_repo"),
                ),
            ),
        )
        metadata = compiled.metadata()
        self.assertEqual(metadata["task_id"], contract.task_id)
        self.assertEqual(metadata["registry_fingerprint"], compiler.registry.fingerprint)
        self.assertEqual(metadata["authority_fingerprint"], compiled.plan.authority_fingerprint)
        self.assertTrue(compiled.fingerprint.startswith("sha256:"))

    def test_compile_rejects_capability_not_disclosed_to_planner(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-PLAN-HIDDEN",
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )
        with self.assertRaisesRegex(RuntimePlanCompilerError, "PLAN_CAPABILITY_NOT_DISCOVERED"):
            RuntimePlanCompiler().compile(
                plan_id="hidden_cap",
                task_contract=contract,
                nodes=(ExecutionNode("patch", "apply_patch", "path", "src/app.py", "write"),),
            )

    def test_compile_rejects_effect_or_resource_kind_drift(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-PLAN-SEMANTICS",
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )
        compiler = RuntimePlanCompiler()
        with self.assertRaisesRegex(RuntimePlanCompilerError, "PLAN_CAPABILITY_EFFECT_MISMATCH"):
            compiler.compile(
                plan_id="effect_drift",
                task_contract=contract,
                nodes=(ExecutionNode("read_doc", "read_file", "path", "docs/a.md", "compute"),),
            )
        with self.assertRaisesRegex(RuntimePlanCompilerError, "PLAN_RESOURCE_KIND_MISMATCH"):
            compiler.compile(
                plan_id="kind_drift",
                task_contract=contract,
                nodes=(ExecutionNode("read_doc", "read_file", "repo", "docs_repo", "read"),),
            )

    def test_compile_enforces_task_step_budget_before_graph_execution(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-PLAN-BUDGET",
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )
        nodes = tuple(
            ExecutionNode(f"read_{index}", "read_file", "path", f"docs/{index}.md", "read")
            for index in range(contract.execution_budget.max_steps + 1)
        )
        with self.assertRaisesRegex(RuntimePlanCompilerError, "PLAN_EXCEEDS_MAX_STEPS"):
            RuntimePlanCompiler().compile(
                plan_id="budget_overflow",
                task_contract=contract,
                nodes=nodes,
            )

    def test_compiled_plan_detects_registry_change_before_execution(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-PLAN-REGISTRY-PIN",
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )
        compiler = RuntimePlanCompiler()
        compiled = compiler.compile(
            plan_id="registry_pin",
            task_contract=contract,
            nodes=(ExecutionNode("read_doc", "read_file", "path", "docs/a.md", "read"),),
        )
        descriptors = [compiler.registry.descriptor(tool) for tool in sorted(TOOLS)]
        index = next(i for i, item in enumerate(descriptors) if item.capability_id == "calculator")
        original = descriptors[index]
        descriptors[index] = CapabilityDescriptor(
            capability_id=original.capability_id,
            effect=original.effect,
            resource_kind=original.resource_kind,
            side_effect_class=original.side_effect_class,
            trust_tier=original.trust_tier,
            concurrency_mode=original.concurrency_mode,
            cost_class=original.cost_class,
            evidence_default=original.evidence_default,
            description="Updated reviewed calculator description.",
        )
        changed_registry = CapabilityRegistry(descriptors)
        self.assertNotEqual(changed_registry.fingerprint, compiler.registry.fingerprint)
        with self.assertRaisesRegex(RuntimePlanCompilerError, "COMPILED_PLAN_REGISTRY_CHANGED"):
            compiled.validate_current(task_contract=contract, registry=changed_registry)

    def test_compiled_plan_detects_authority_change(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-PLAN-AUTH-PIN",
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )
        compiler = RuntimePlanCompiler()
        compiled = compiler.compile(
            plan_id="authority_pin",
            task_contract=contract,
            nodes=(ExecutionNode("read_doc", "read_file", "path", "docs/a.md", "read"),),
        )
        changed = replace(contract, allowed_sources=("new_source",)).validate()
        with self.assertRaisesRegex(RuntimePlanCompilerError, "COMPILED_PLAN_AUTHORITY_CHANGED"):
            compiled.validate_current(task_contract=changed, registry=compiler.registry)


if __name__ == "__main__":
    unittest.main()
