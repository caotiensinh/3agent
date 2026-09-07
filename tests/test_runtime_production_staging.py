import hashlib
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
from three_agent.runtime_production_adapters import ProductionCapabilityAdapterRegistry
from three_agent.runtime_production_scheduler import ProductionAuditedRuntimeDAGScheduler
from three_agent.runtime_reviewed_staging import ReviewedStagingBoundary
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class FakeStagingContentSource:
    def __init__(self, content: bytes):
        self.content = content
        self.calls = []

    def resolve_content(self, *, task_id, content_ref, max_bytes):
        self.calls.append((task_id, content_ref, max_bytes))
        return self.content


class FakeStagingEvidenceSink:
    def __init__(self, *, fail=False):
        self.fail = fail
        self.calls = []

    def persist_staged_write(
        self,
        *,
        task_id,
        node_id,
        resource_sha256,
        content_ref_sha256,
        content_sha256,
        bytes_written,
        created,
    ):
        self.calls.append(
            (
                task_id,
                node_id,
                resource_sha256,
                content_ref_sha256,
                content_sha256,
                bytes_written,
                created,
            )
        )
        if self.fail:
            raise RuntimeError("evidence unavailable")
        return ("artifact:staging-evidence",)


class RuntimeProductionStagingTests(unittest.TestCase):
    @staticmethod
    def _task(tmp):
        store = TaskStore(Path(tmp) / "tasks.db")
        store.initialize()
        task = store.create_task("production staging", "bounded staging fixture")
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type="code_fix",
            sensitivity="internal",
            risk_level="low",
            allowed_tools=("write_staging",),
            write_scope=("staging/output.txt",),
        )
        store.bind_task_contract(task.task_id, contract.to_dict())
        budget = TaskExecutionBudgetState.from_bound_contract(store, task.task_id)
        return store, contract, budget

    @staticmethod
    def _plan(contract, content_sha256):
        registry = CapabilityRegistry.default()
        compiled = RuntimePlanCompiler(registry).compile(
            plan_id="production_staging",
            task_contract=contract,
            nodes=(
                ExecutionNode(
                    "stage",
                    "write_staging",
                    "path",
                    "staging/output.txt",
                    "write",
                ),
            ),
        )
        typed = TypedCapabilityInvocation.compile(
            compiled_plan=compiled,
            node_id="stage",
            operation="materialize",
            arguments={
                "content_ref": "artifact:proposed-output",
                "content_sha256": content_sha256,
            },
        )
        bundle = RuntimeInvocationBundle.compile(
            compiled_plan=compiled,
            invocations=(typed,),
        )
        return registry, compiled, bundle

    @staticmethod
    def _runtime(tmp, *, content, expected_sha=None, evidence_fail=False):
        store, contract, budget = RuntimeProductionStagingTests._task(tmp)
        digest = expected_sha or _sha256(content)
        registry, compiled, bundle = RuntimeProductionStagingTests._plan(contract, digest)
        workspace = Path(tmp) / "workspace"
        (workspace / "staging").mkdir(parents=True)
        source = FakeStagingContentSource(content)
        sink = FakeStagingEvidenceSink(fail=evidence_fail)
        boundary = ReviewedStagingBoundary(
            staging_root=workspace,
            content_source=source,
            evidence_sink=sink,
        )
        adapters = ProductionCapabilityAdapterRegistry(
            compiled_plan=compiled,
            task_contract=contract,
            invocation_bundle=bundle,
            budget=budget,
            staging_boundary=boundary,
            registry=registry,
        )
        scheduler = ProductionAuditedRuntimeDAGScheduler(
            adapters=adapters,
            invocation_binding_store=RuntimeInvocationBindingStore(
                Path(tmp) / "invocation_bindings"
            ),
            observation_ledger=RuntimeObservationLedger(store),
            checkpoint_store=RuntimeCheckpointStore(Path(tmp) / "checkpoints"),
            registry=registry,
        )
        return (
            store,
            contract,
            budget,
            compiled,
            scheduler,
            workspace,
            source,
            sink,
        )

    def test_materializes_exact_referenced_content_with_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            content = b"reviewed staged output\n"
            (
                _,
                contract,
                budget,
                compiled,
                scheduler,
                workspace,
                source,
                sink,
            ) = self._runtime(tmp, content=content)
            result = scheduler.run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            target = workspace / "staging" / "output.txt"
            self.assertEqual(result.status, "completed")
            self.assertEqual(target.read_bytes(), content)
            self.assertEqual(result.observations[0].reason_code, "STAGING_MATERIALIZE_OK")
            self.assertEqual(
                result.observations[0].evidence_refs,
                ("artifact:staging-evidence",),
            )
            self.assertEqual(budget.snapshot()["steps_used"], 1)
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)
            self.assertEqual(len(source.calls), 1)
            self.assertEqual(len(sink.calls), 1)
            metadata = result.observations[0].metadata()
            self.assertNotIn("staging/output.txt", metadata.values())
            self.assertNotIn(content.decode().strip(), metadata.values())

    def test_digest_mismatch_fails_without_creating_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            content = b"actual content"
            wrong_sha = _sha256(b"different content")
            (
                _,
                contract,
                budget,
                compiled,
                scheduler,
                workspace,
                source,
                sink,
            ) = self._runtime(tmp, content=content, expected_sha=wrong_sha)
            result = scheduler.run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "failed")
            self.assertEqual(
                result.observations[0].reason_code,
                "STAGING_CONTENT_DIGEST_MISMATCH",
            )
            self.assertFalse((workspace / "staging" / "output.txt").exists())
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)
            self.assertEqual(len(source.calls), 1)
            self.assertEqual(sink.calls, [])

    def test_live_revocation_denies_before_content_resolution_or_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            content = b"content"
            (
                store,
                contract,
                budget,
                compiled,
                scheduler,
                workspace,
                source,
                sink,
            ) = self._runtime(tmp, content=content)
            TaskCapabilityRevocationStore(store).revoke(
                contract.task_id,
                "write_staging",
                reason_code="OPERATOR_REVOKED",
            )
            result = scheduler.run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.observations[0].status, "denied")
            self.assertEqual(result.observations[0].reason_code, "CAPABILITY_REVOKED")
            self.assertEqual(budget.snapshot()["tool_calls_used"], 0)
            self.assertEqual(source.calls, [])
            self.assertEqual(sink.calls, [])
            self.assertFalse((workspace / "staging" / "output.txt").exists())

    def test_conflicting_existing_target_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            content = b"new content"
            (
                _,
                contract,
                budget,
                compiled,
                scheduler,
                workspace,
                source,
                sink,
            ) = self._runtime(tmp, content=content)
            target = workspace / "staging" / "output.txt"
            target.write_bytes(b"existing protected content")
            result = scheduler.run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.observations[0].reason_code, "STAGING_TARGET_CONFLICT")
            self.assertEqual(target.read_bytes(), b"existing protected content")
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)
            self.assertEqual(len(source.calls), 1)
            self.assertEqual(sink.calls, [])

    def test_evidence_failure_rolls_back_newly_created_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            content = b"must not escape without evidence"
            (
                _,
                contract,
                budget,
                compiled,
                scheduler,
                workspace,
                source,
                sink,
            ) = self._runtime(tmp, content=content, evidence_fail=True)
            result = scheduler.run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "failed")
            self.assertEqual(
                result.observations[0].reason_code,
                "STAGING_EVIDENCE_WRITE_FAILED",
            )
            self.assertFalse((workspace / "staging" / "output.txt").exists())
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)
            self.assertEqual(len(source.calls), 1)
            self.assertEqual(len(sink.calls), 1)


if __name__ == "__main__":
    unittest.main()
