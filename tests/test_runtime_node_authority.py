import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from three_agent.capability_authority import CapabilityAuthorityDenied
from three_agent.capability_registry import CapabilityRegistry
from three_agent.capability_revocation import TaskCapabilityRevocationStore
from three_agent.execution_budget import TaskExecutionBudgetState
from three_agent.inference_scope import (
    current_capability_authority,
    current_execution_budget,
    current_model_authority,
)
from three_agent.metered_runtime import MeteredExecutionGateway, MeteredInternetGateway
from three_agent.model_authority import ModelAuthorityDenied
from three_agent.resource_events import ResourceEventRecorder
from three_agent.runtime_execution_plan import ExecutionNode
from three_agent.runtime_node_authority import (
    RuntimeBudgetOwnership,
    RuntimeNodeAuthority,
)
from three_agent.runtime_plan_compiler import RuntimePlanCompiler
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler


class FakeExecution:
    def __init__(self):
        self.calls = []

    def run(self, agent_id, task_id, argv, cwd=None):
        self.calls.append((agent_id, task_id, tuple(argv), cwd))
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")


class FakeInternet:
    def __init__(self):
        self.calls = []

    def get(self, agent_id, task_id, url, timeout=30):
        self.calls.append((agent_id, task_id, url, timeout))
        return b"ok"


class RuntimeNodeAuthorityTests(unittest.TestCase):
    @staticmethod
    def _store_contract(tmp, *, task_type="code_review", public_web=False, write_scope="none"):
        store = TaskStore(Path(tmp) / "tasks.db")
        store.initialize()
        task = store.create_task("node authority", "bounded node authority fixture")
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type=task_type,
            sensitivity="internal",
            risk_level="low",
            public_web=public_web,
            write_scope=write_scope,
        )
        store.bind_task_contract(task.task_id, contract.to_dict())
        budget = TaskExecutionBudgetState.from_bound_contract(store, task.task_id)
        return store, contract, budget

    def test_node_scope_is_single_capability_no_llm_no_write_no_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, contract, budget = self._store_contract(tmp)
            registry = CapabilityRegistry.default()
            compiled = RuntimePlanCompiler(registry).compile(
                plan_id="node_scope",
                task_contract=contract,
                nodes=(
                    ExecutionNode(
                        "tests", "run_tests", "repo", "workspace_tests", "execute"
                    ),
                ),
            )
            node = RuntimeNodeAuthority.compile(
                task_contract=contract,
                compiled_plan=compiled,
                node_id="tests",
                registry=registry,
            )
            self.assertEqual(node.capability_authority.allowed_tools, ("run_tests",))
            self.assertEqual(node.capability_authority.write_scope, "none")
            self.assertEqual(node.capability_authority.network_scope, "deny")
            self.assertEqual(node.model_authority.initial_model_tier, "none")
            self.assertEqual(node.model_authority.max_model_tier, "none")
            self.assertFalse(node.model_authority.escalation_allowed)
            with self.assertRaisesRegex(ModelAuthorityDenied, "MODEL_TIER_EXCEEDS_CONTRACT_MAX"):
                node.model_authority.require_tier("small")

            with node.scope(budget):
                self.assertIs(current_execution_budget(), budget)
                self.assertEqual(current_model_authority().fingerprint, node.model_authority.fingerprint)
                self.assertEqual(
                    current_capability_authority().fingerprint,
                    node.capability_authority.fingerprint,
                )
            self.assertIsNone(current_execution_budget())

    def test_scheduler_step_and_gateway_tool_call_have_single_owners(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, contract, budget = self._store_contract(tmp)
            registry = CapabilityRegistry.default()
            compiled = RuntimePlanCompiler(registry).compile(
                plan_id="budget_owner",
                task_contract=contract,
                nodes=(
                    ExecutionNode(
                        "tests", "run_tests", "repo", "workspace_tests", "execute"
                    ),
                ),
            )
            node = RuntimeNodeAuthority.compile(
                task_contract=contract,
                compiled_plan=compiled,
                node_id="tests",
                registry=registry,
            )
            inner = FakeExecution()
            gateway = MeteredExecutionGateway(
                inner,
                ResourceEventRecorder(Path(tmp) / "resource.jsonl"),
            )
            ownership = RuntimeBudgetOwnership().validate()
            self.assertEqual(ownership.step_owner, "scheduler")
            self.assertEqual(ownership.tool_call_owner, "capability_boundary")

            # Scheduler owns only the step counter on the production path.
            budget.reserve(steps=1)
            with node.scope(budget):
                gateway.run(
                    "runtime_node",
                    contract.task_id,
                    ["pytest", "-q"],
                    capability="run_tests",
                )
                with self.assertRaisesRegex(
                    CapabilityAuthorityDenied, "CAPABILITY_NOT_ALLOWED"
                ):
                    gateway.run(
                        "runtime_node",
                        contract.task_id,
                        ["ruff", "check", "."],
                        capability="run_linter",
                    )
            snapshot = budget.snapshot()
            self.assertEqual(snapshot["steps_used"], 1)
            self.assertEqual(snapshot["tool_calls_used"], 1)
            self.assertEqual(len(inner.calls), 1)

            TaskCapabilityRevocationStore(store).revoke(
                contract.task_id,
                "run_tests",
                reason_code="OPERATOR_REVOKED",
            )
            with node.scope(budget):
                with self.assertRaisesRegex(
                    CapabilityAuthorityDenied, "CAPABILITY_REVOKED"
                ):
                    gateway.run(
                        "runtime_node",
                        contract.task_id,
                        ["pytest", "-q"],
                        capability="run_tests",
                    )
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)
            self.assertEqual(len(inner.calls), 1)

    def test_write_node_scope_is_narrowed_to_exact_plan_resource(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, contract, budget = self._store_contract(
                tmp,
                task_type="code_fix",
                write_scope=("src",),
            )
            registry = CapabilityRegistry.default()
            compiled = RuntimePlanCompiler(registry).compile(
                plan_id="write_scope",
                task_contract=contract,
                nodes=(
                    ExecutionNode(
                        "patch", "apply_patch", "path", "src/a.py", "write",
                        idempotent=False,
                    ),
                ),
            )
            node = RuntimeNodeAuthority.compile(
                task_contract=contract,
                compiled_plan=compiled,
                node_id="patch",
                registry=registry,
            )
            self.assertEqual(node.capability_authority.write_scope, ("src/a.py",))
            self.assertEqual(node.capability_authority.network_scope, "deny")
            inner = FakeExecution()
            gateway = MeteredExecutionGateway(
                inner,
                ResourceEventRecorder(Path(tmp) / "write-resource.jsonl"),
            )
            budget.reserve(steps=1)
            with node.scope(budget):
                gateway.run(
                    "runtime_node",
                    contract.task_id,
                    ["apply-patch"],
                    capability="apply_patch",
                    resource_ref="src/a.py",
                )
                with self.assertRaisesRegex(
                    CapabilityAuthorityDenied, "WRITE_SCOPE_NOT_AUTHORIZED"
                ):
                    gateway.run(
                        "runtime_node",
                        contract.task_id,
                        ["apply-patch"],
                        capability="apply_patch",
                        resource_ref="src/b.py",
                    )
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)
            self.assertEqual(len(inner.calls), 1)

    def test_network_node_preserves_only_allowlisted_read_egress(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, contract, budget = self._store_contract(
                tmp,
                task_type="analysis",
                public_web=True,
            )
            registry = CapabilityRegistry.default()
            compiled = RuntimePlanCompiler(registry).compile(
                plan_id="web_scope",
                task_contract=contract,
                nodes=(
                    ExecutionNode(
                        "web", "web_gateway", "network", "public_search", "network_read"
                    ),
                ),
            )
            node = RuntimeNodeAuthority.compile(
                task_contract=contract,
                compiled_plan=compiled,
                node_id="web",
                registry=registry,
            )
            self.assertEqual(node.capability_authority.allowed_tools, ("web_gateway",))
            self.assertEqual(node.capability_authority.network_scope, "allowlisted_egress")
            self.assertEqual(node.capability_authority.write_scope, "none")
            inner = FakeInternet()
            gateway = MeteredInternetGateway(
                inner,
                ResourceEventRecorder(Path(tmp) / "web-resource.jsonl"),
            )
            budget.reserve(steps=1)
            with node.scope(budget):
                self.assertEqual(
                    gateway.get(
                        "runtime_node",
                        contract.task_id,
                        "https://example.com",
                    ),
                    b"ok",
                )
                with self.assertRaisesRegex(
                    CapabilityAuthorityDenied, "CAPABILITY_EFFECT_NOT_ALLOWED"
                ):
                    gateway.post_json(
                        "runtime_node",
                        contract.task_id,
                        "https://example.com/upload",
                        {"data": "blocked"},
                    )
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)
            self.assertEqual(len(inner.calls), 1)


if __name__ == "__main__":
    unittest.main()
