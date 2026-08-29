import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from three_agent.capability_authority import CapabilityAuthorityDenied
from three_agent.capability_revocation import TaskCapabilityRevocationStore
from three_agent.execution_budget import TaskExecutionBudgetState
from three_agent.inference_scope import inference_scope
from three_agent.metered_runtime import MeteredExecutionGateway
from three_agent.model_authority import TaskModelAuthority
from three_agent.resource_events import ResourceEventRecorder
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler


class FakeExecution:
    def __init__(self):
        self.calls = []

    def run(self, agent_id, task_id, argv, cwd=None):
        self.calls.append((agent_id, task_id, tuple(argv), cwd))
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")


class CapabilityRevocationTests(unittest.TestCase):
    @staticmethod
    def _bound_code_review(root: Path, title: str = "revocation"):
        store = TaskStore(root / "tasks.db")
        store.initialize()
        task = store.create_task(title, "PRIVATE_REQUEST_BODY")
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type="code_review",
            sensitivity="internal",
        )
        store.bind_task_contract(task.task_id, contract.to_dict())
        budget = TaskExecutionBudgetState.from_bound_contract(store, task.task_id)
        authority = TaskModelAuthority.from_contract(contract)
        return store, task, contract, budget, authority

    def test_revoke_requires_bound_contract_and_existing_contract_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TaskStore(root / "tasks.db")
            store.initialize()
            task = store.create_task("unbound", "request")
            revocations = TaskCapabilityRevocationStore(store)
            with self.assertRaisesRegex(ValueError, "TASK_CONTRACT_NOT_BOUND"):
                revocations.revoke(task.task_id, "run_tests")

            contract = TaskContractCompiler().compile(
                task_id=task.task_id,
                task_type="code_review",
                sensitivity="internal",
            )
            store.bind_task_contract(task.task_id, contract.to_dict())
            with self.assertRaisesRegex(
                ValueError, "CAPABILITY_NOT_IN_BOUND_TASK_CONTRACT"
            ):
                revocations.revoke(task.task_id, "web_gateway")

    def test_revocation_is_idempotent_persistent_and_has_no_restore_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, task, _, _, _ = self._bound_code_review(root)
            first_store = TaskCapabilityRevocationStore(store)
            first = first_store.revoke(task.task_id, "run_tests")
            second = first_store.revoke(task.task_id, "run_tests")
            self.assertEqual(first.revoked_at, second.revoked_at)
            self.assertEqual(len(first_store.list_for_task(task.task_id)), 1)
            self.assertFalse(hasattr(first_store, "restore"))
            self.assertFalse(hasattr(first_store, "unrevoke"))

            restarted = TaskStore(root / "tasks.db")
            restarted.initialize()
            after_restart = TaskCapabilityRevocationStore(restarted)
            self.assertTrue(after_restart.is_revoked(task.task_id, "run_tests"))
            rows = after_restart.list_for_task(task.task_id)
            self.assertEqual(rows[0].reason_code, "OPERATOR_REVOKED")

    def test_revocation_becomes_effective_inside_already_active_scope_before_side_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, task, _, budget, authority = self._bound_code_review(root)
            events = root / "resource.jsonl"
            inner = FakeExecution()
            gateway = MeteredExecutionGateway(inner, ResourceEventRecorder(events))
            revocations = TaskCapabilityRevocationStore(store)

            with inference_scope(
                task.task_id,
                agent_id="research",
                stage="research",
                execution_budget=budget,
                model_authority=authority,
            ):
                # Revoke after entering the scope. The next gateway call must read
                # persistent state live instead of relying on a stale scope snapshot.
                revocations.revoke(task.task_id, "run_tests")
                with self.assertRaisesRegex(
                    CapabilityAuthorityDenied, "CAPABILITY_REVOKED"
                ):
                    gateway.run(
                        "research",
                        task.task_id,
                        ["pytest", "-q"],
                        capability="run_tests",
                    )

            self.assertEqual(inner.calls, [])
            self.assertFalse(events.exists())
            self.assertEqual(budget.snapshot()["tool_calls_used"], 0)

    def test_revocation_is_task_scoped_and_does_not_affect_peer_task(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TaskStore(root / "tasks.db")
            store.initialize()
            compiler = TaskContractCompiler()

            task_a = store.create_task("A", "request A")
            contract_a = compiler.compile(
                task_id=task_a.task_id, task_type="code_review", sensitivity="internal"
            )
            store.bind_task_contract(task_a.task_id, contract_a.to_dict())
            budget_a = TaskExecutionBudgetState.from_bound_contract(store, task_a.task_id)

            task_b = store.create_task("B", "request B")
            contract_b = compiler.compile(
                task_id=task_b.task_id, task_type="code_review", sensitivity="internal"
            )
            store.bind_task_contract(task_b.task_id, contract_b.to_dict())
            budget_b = TaskExecutionBudgetState.from_bound_contract(store, task_b.task_id)

            revocations = TaskCapabilityRevocationStore(store)
            revocations.revoke(task_a.task_id, "run_tests")
            self.assertTrue(revocations.is_revoked(task_a.task_id, "run_tests"))
            self.assertFalse(revocations.is_revoked(task_b.task_id, "run_tests"))

            inner = FakeExecution()
            events = root / "peer.jsonl"
            gateway = MeteredExecutionGateway(inner, ResourceEventRecorder(events))
            with inference_scope(
                task_b.task_id,
                agent_id="research",
                stage="research",
                execution_budget=budget_b,
                model_authority=TaskModelAuthority.from_contract(contract_b),
            ):
                result = gateway.run(
                    "research",
                    task_b.task_id,
                    ["pytest", "-q"],
                    capability="run_tests",
                )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(len(inner.calls), 1)
            self.assertEqual(budget_a.snapshot()["tool_calls_used"], 0)
            self.assertEqual(budget_b.snapshot()["tool_calls_used"], 1)
            rows = [json.loads(line) for line in events.read_text().splitlines() if line]
            self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()
