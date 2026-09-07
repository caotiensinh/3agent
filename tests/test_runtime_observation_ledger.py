import json
import tempfile
import threading
import unittest
from pathlib import Path

from three_agent.capability_registry import CapabilityRegistry
from three_agent.runtime_audited_scheduler import AuditedRuntimeDAGScheduler
from three_agent.runtime_checkpoint import RuntimeCheckpoint, RuntimeCheckpointStore
from three_agent.runtime_execution_plan import ExecutionNode, ExecutionObservation
from three_agent.runtime_observation_ledger import (
    RuntimeObservationLedger,
    RuntimeObservationLedgerError,
)
from three_agent.runtime_plan_compiler import RuntimePlanCompiler
from three_agent.runtime_scheduler import (
    CapabilityAdapterRegistry,
    NodeExecutionResult,
    RuntimeSchedulerError,
)
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler
from three_agent.validator_ledger import ValidatorLedger


class FakeBudget:
    def __init__(self, task_id):
        self.task_id = task_id
        self.reservations = []
        self.active_checks = 0
        self._lock = threading.Lock()

    def assert_active(self):
        with self._lock:
            self.active_checks += 1

    def reserve(self, **kwargs):
        with self._lock:
            self.reservations.append(dict(kwargs))


class RecordingCheckpointStore(RuntimeCheckpointStore):
    def __init__(self, root, events):
        super().__init__(root)
        self.events = events

    def save(self, checkpoint):
        self.events.append(f"checkpoint:{checkpoint.status}")
        return super().save(checkpoint)


class RecordingObservationLedger(RuntimeObservationLedger):
    def __init__(self, store, events):
        self.events = events
        super().__init__(store)

    def record_many(self, *, compiled_plan, observations):
        self.events.append("observation:commit")
        return super().record_many(
            compiled_plan=compiled_plan,
            observations=observations,
        )


class FailingObservationLedger:
    durable = True

    def record_many(self, *, compiled_plan, observations):
        del compiled_plan, observations
        raise OSError("PRIVATE_STORAGE_FAILURE")


class RuntimeObservationLedgerTests(unittest.TestCase):
    @staticmethod
    def _fixture(tmp, *, task_type="analysis", risk_level="low", write_scope="none"):
        root = Path(tmp)
        store = TaskStore(root / "tasks.db")
        store.initialize()
        task = store.create_task("runtime audit", "bounded runtime audit fixture")
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type=task_type,
            sensitivity="internal",
            risk_level=risk_level,
            write_scope=write_scope,
        )
        store.bind_task_contract(task.task_id, contract.to_dict())
        registry = CapabilityRegistry.default()
        return root, store, contract, registry

    def test_ledger_is_idempotent_hash_chained_and_never_stores_raw_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, store, contract, registry = self._fixture(tmp)
            compiled = RuntimePlanCompiler(registry).compile(
                plan_id="audit_read",
                task_contract=contract,
                nodes=(
                    ExecutionNode(
                        "read_doc", "read_file", "path", "docs/a.md", "read"
                    ),
                ),
            )
            observation = ExecutionObservation.capture(
                plan=compiled.plan,
                node_id="read_doc",
                status="succeeded",
                reason_code="EXECUTION_OK",
                result={"secret": "RAW_RESULT_MUST_NOT_PERSIST"},
                evidence_refs=("evidence/read.json",),
            )
            ledger = RuntimeObservationLedger(store)
            first = ledger.record_many(
                compiled_plan=compiled, observations=(observation,)
            )
            second = ledger.record_many(
                compiled_plan=compiled, observations=(observation,)
            )
            self.assertEqual(first, second)
            verification = ledger.verify_chain(contract.task_id, compiled.plan.plan_id)
            self.assertTrue(verification["verified"])
            self.assertEqual(verification["record_count"], 1)
            self.assertEqual(
                ledger.evidence_refs_for_plan(contract.task_id, compiled.plan.plan_id),
                ("evidence/read.json",),
            )
            self.assertNotIn(
                b"RAW_RESULT_MUST_NOT_PERSIST",
                (root / "tasks.db").read_bytes(),
            )

    def test_ledger_chain_detects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, store, contract, registry = self._fixture(tmp)
            compiled = RuntimePlanCompiler(registry).compile(
                plan_id="audit_tamper",
                task_contract=contract,
                nodes=(
                    ExecutionNode(
                        "read_doc", "read_file", "path", "docs/a.md", "read"
                    ),
                ),
            )
            observation = ExecutionObservation.capture(
                plan=compiled.plan,
                node_id="read_doc",
                status="succeeded",
                reason_code="EXECUTION_OK",
                result={"ok": True},
                evidence_refs=("evidence/read.json",),
            )
            ledger = RuntimeObservationLedger(store)
            ledger.record_many(compiled_plan=compiled, observations=(observation,))
            with store.connect() as conn:
                conn.execute(
                    "UPDATE runtime_observations SET record_sha256 = ? WHERE observation_id = ?",
                    ("sha256:" + "f" * 64, observation.observation_id),
                )
            with self.assertRaisesRegex(
                RuntimeObservationLedgerError, "OBSERVATION_CHAIN_HASH_MISMATCH"
            ):
                ledger.verify_chain(contract.task_id, compiled.plan.plan_id)

    def test_observation_evidence_does_not_auto_pass_validator_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, store, contract, registry = self._fixture(tmp)
            compiled = RuntimePlanCompiler(registry).compile(
                plan_id="audit_validator_boundary",
                task_contract=contract,
                nodes=(
                    ExecutionNode(
                        "read_doc", "read_file", "path", "docs/a.md", "read"
                    ),
                ),
            )
            observation = ExecutionObservation.capture(
                plan=compiled.plan,
                node_id="read_doc",
                status="succeeded",
                reason_code="EXECUTION_OK",
                result={"ok": True},
                evidence_refs=("evidence/read.json",),
            )
            ledger = RuntimeObservationLedger(store)
            ledger.record_many(compiled_plan=compiled, observations=(observation,))
            state = ValidatorLedger(store).evaluate(contract.task_id)
            self.assertFalse(state.verified)
            self.assertIn("evidence", state.missing_validators)
            self.assertEqual(
                ledger.evidence_refs_for_plan(contract.task_id, compiled.plan.plan_id),
                ("evidence/read.json",),
            )

    def test_audited_scheduler_commits_observation_before_completed_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, store, contract, registry = self._fixture(tmp)
            compiled = RuntimePlanCompiler(registry).compile(
                plan_id="audit_order",
                task_contract=contract,
                nodes=(
                    ExecutionNode(
                        "read_doc", "read_file", "path", "docs/a.md", "read"
                    ),
                ),
            )
            events = []
            checkpoints = RecordingCheckpointStore(root / "checkpoints", events)
            ledger = RecordingObservationLedger(store, events)
            adapters = CapabilityAdapterRegistry(registry)

            def handler(invocation):
                invocation.assert_active()
                events.append("adapter:read_doc")
                return NodeExecutionResult(
                    {"ok": True}, ("evidence/read.json",)
                )

            adapters.register("read_file", handler, timeout_mode="cooperative")
            scheduler = AuditedRuntimeDAGScheduler(
                registry=registry,
                adapters=adapters,
                checkpoint_store=checkpoints,
                observation_ledger=ledger,
            )
            result = scheduler.run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=FakeBudget(contract.task_id),
            )
            self.assertEqual(result.status, "completed")
            self.assertEqual(result.durability, "durable_audited")
            self.assertEqual(
                events,
                [
                    "checkpoint:running",
                    "adapter:read_doc",
                    "observation:commit",
                    "checkpoint:completed",
                ],
            )
            self.assertTrue(
                ledger.verify_chain(contract.task_id, compiled.plan.plan_id)["verified"]
            )

    def test_observation_persistence_failure_leaves_running_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, _, contract, registry = self._fixture(tmp)
            compiled = RuntimePlanCompiler(registry).compile(
                plan_id="audit_persist_fail",
                task_contract=contract,
                nodes=(
                    ExecutionNode(
                        "read_doc", "read_file", "path", "docs/a.md", "read"
                    ),
                ),
            )
            checkpoints = RuntimeCheckpointStore(root / "checkpoints")
            adapters = CapabilityAdapterRegistry(registry)
            adapter_calls = []
            adapters.register(
                "read_file",
                lambda invocation: adapter_calls.append(invocation.node.node_id)
                or NodeExecutionResult({"ok": True}, ("evidence/read.json",)),
                timeout_mode="cooperative",
            )
            scheduler = AuditedRuntimeDAGScheduler(
                registry=registry,
                adapters=adapters,
                checkpoint_store=checkpoints,
                observation_ledger=FailingObservationLedger(),
            )
            with self.assertRaisesRegex(
                RuntimeSchedulerError,
                "OBSERVATION_PERSISTENCE_FAILED_RECONCILIATION_REQUIRED",
            ):
                scheduler.run(
                    compiled_plan=compiled,
                    task_contract=contract,
                    budget=FakeBudget(contract.task_id),
                )
            self.assertEqual(adapter_calls, ["read_doc"])
            checkpoint = checkpoints.load(compiled_plan=compiled)
            self.assertEqual(checkpoint.status, "running")
            self.assertEqual(checkpoint.running_node_ids, ("read_doc",))

    def test_reconciliation_report_never_authorizes_automatic_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, store, contract, registry = self._fixture(tmp)
            compiled = RuntimePlanCompiler(registry).compile(
                plan_id="audit_reconcile",
                task_contract=contract,
                nodes=(
                    ExecutionNode(
                        "read_doc", "read_file", "path", "docs/a.md", "read"
                    ),
                ),
            )
            checkpoints = RuntimeCheckpointStore(root / "checkpoints")
            checkpoint = RuntimeCheckpoint.capture(
                compiled_plan=compiled,
                status="running",
                running_node_ids=("read_doc",),
            )
            checkpoints.save(checkpoint)
            observation = ExecutionObservation.capture(
                plan=compiled.plan,
                node_id="read_doc",
                status="succeeded",
                reason_code="EXECUTION_OK",
                result={"ok": True},
                evidence_refs=("evidence/read.json",),
            )
            ledger = RuntimeObservationLedger(store)
            ledger.record_many(compiled_plan=compiled, observations=(observation,))
            scheduler = AuditedRuntimeDAGScheduler(
                registry=registry,
                adapters=CapabilityAdapterRegistry(registry),
                checkpoint_store=checkpoints,
                observation_ledger=ledger,
            )
            report = scheduler.reconciliation_report(
                compiled_plan=compiled,
                checkpoint=checkpoints.load(compiled_plan=compiled),
            )
            self.assertTrue(report["ledger_verified"])
            self.assertTrue(report["requires_reconciliation"])
            self.assertFalse(report["automatic_replay_authorized"])
            self.assertEqual(len(report["uncertain_node_observations"]), 1)
            serialized = json.dumps(report, sort_keys=True)
            self.assertNotIn("result", serialized.lower().replace("result_sha256", ""))


if __name__ == "__main__":
    unittest.main()
