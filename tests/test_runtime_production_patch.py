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
from three_agent.runtime_reviewed_patch import ReviewedPatchBoundary
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class FakePatchSource:
    def __init__(self, patch: bytes):
        self.patch = patch
        self.calls = []

    def resolve_patch(self, *, task_id, patch_ref, max_bytes):
        self.calls.append((task_id, patch_ref, max_bytes))
        return self.patch


class FakePatchEvidenceSink:
    def __init__(self, *, fail=False):
        self.fail = fail
        self.calls = []

    def persist_patch_application(
        self,
        *,
        task_id,
        node_id,
        resource_sha256,
        patch_ref_sha256,
        patch_sha256,
        before_sha256,
        after_sha256,
        bytes_written,
        hunk_count,
    ):
        self.calls.append(
            (
                task_id,
                node_id,
                resource_sha256,
                patch_ref_sha256,
                patch_sha256,
                before_sha256,
                after_sha256,
                bytes_written,
                hunk_count,
            )
        )
        if self.fail:
            raise RuntimeError("evidence unavailable")
        return ("artifact:patch-evidence",)


class RuntimeProductionPatchTests(unittest.TestCase):
    ORIGINAL = b'value = 1\nprint("old")\n'
    PATCH = (
        b"--- a/staging/a.py\n"
        b"+++ b/staging/a.py\n"
        b"@@ -1,2 +1,2 @@\n"
        b" value = 1\n"
        b'-print("old")\n'
        b'+print("new")\n'
    )

    @staticmethod
    def _task(tmp):
        store = TaskStore(Path(tmp) / "tasks.db")
        store.initialize()
        task = store.create_task("production patch", "bounded patch fixture")
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type="code_fix",
            sensitivity="internal",
            risk_level="low",
            allowed_tools=("apply_patch",),
            write_scope=("staging/a.py",),
        )
        store.bind_task_contract(task.task_id, contract.to_dict())
        budget = TaskExecutionBudgetState.from_bound_contract(store, task.task_id)
        return store, contract, budget

    @staticmethod
    def _plan(contract, patch_sha256):
        registry = CapabilityRegistry.default()
        compiled = RuntimePlanCompiler(registry).compile(
            plan_id="production_patch",
            task_contract=contract,
            nodes=(
                ExecutionNode(
                    "patch",
                    "apply_patch",
                    "path",
                    "staging/a.py",
                    "write",
                    idempotent=False,
                ),
            ),
        )
        typed = TypedCapabilityInvocation.compile(
            compiled_plan=compiled,
            node_id="patch",
            operation="apply",
            arguments={
                "patch_ref": "artifact:proposed-patch",
                "patch_sha256": patch_sha256,
            },
        )
        bundle = RuntimeInvocationBundle.compile(
            compiled_plan=compiled,
            invocations=(typed,),
        )
        return registry, compiled, bundle

    @classmethod
    def _runtime(cls, tmp, *, patch=None, expected_sha=None, evidence_fail=False, original=None):
        store, contract, budget = cls._task(tmp)
        patch_bytes = cls.PATCH if patch is None else patch
        digest = expected_sha or _sha256(patch_bytes)
        registry, compiled, bundle = cls._plan(contract, digest)
        workspace = Path(tmp) / "workspace"
        (workspace / "staging").mkdir(parents=True)
        target = workspace / "staging" / "a.py"
        target.write_bytes(cls.ORIGINAL if original is None else original)
        source = FakePatchSource(patch_bytes)
        sink = FakePatchEvidenceSink(fail=evidence_fail)
        boundary = ReviewedPatchBoundary(
            workspace_root=workspace,
            patch_source=source,
            evidence_sink=sink,
        )
        adapters = ProductionCapabilityAdapterRegistry(
            compiled_plan=compiled,
            task_contract=contract,
            invocation_bundle=bundle,
            budget=budget,
            patch_boundary=boundary,
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
        return store, contract, budget, compiled, scheduler, target, source, sink

    def test_applies_exact_single_file_patch_with_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            (
                _,
                contract,
                budget,
                compiled,
                scheduler,
                target,
                source,
                sink,
            ) = self._runtime(tmp)
            result = scheduler.run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "completed")
            self.assertEqual(target.read_bytes(), b'value = 1\nprint("new")\n')
            observation = result.observations[0]
            self.assertEqual(observation.reason_code, "PATCH_APPLY_OK")
            self.assertEqual(observation.evidence_refs, ("artifact:patch-evidence",))
            self.assertEqual(budget.snapshot()["steps_used"], 1)
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)
            self.assertEqual(len(source.calls), 1)
            self.assertEqual(len(sink.calls), 1)
            metadata = observation.metadata()
            self.assertNotIn("staging/a.py", metadata.values())
            self.assertNotIn(self.PATCH.decode(), metadata.values())
            self.assertNotIn('print("new")', metadata.values())

    def test_patch_digest_mismatch_fails_before_target_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            wrong_sha = _sha256(b"different patch")
            (
                _,
                contract,
                budget,
                compiled,
                scheduler,
                target,
                source,
                sink,
            ) = self._runtime(tmp, expected_sha=wrong_sha)
            result = scheduler.run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.observations[0].reason_code, "PATCH_DIGEST_MISMATCH")
            self.assertEqual(target.read_bytes(), self.ORIGINAL)
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)
            self.assertEqual(len(source.calls), 1)
            self.assertEqual(sink.calls, [])

    def test_live_revocation_denies_before_patch_resolution_or_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            (
                store,
                contract,
                budget,
                compiled,
                scheduler,
                target,
                source,
                sink,
            ) = self._runtime(tmp)
            TaskCapabilityRevocationStore(store).revoke(
                contract.task_id,
                "apply_patch",
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
            self.assertEqual(target.read_bytes(), self.ORIGINAL)
            self.assertEqual(budget.snapshot()["tool_calls_used"], 0)
            self.assertEqual(source.calls, [])
            self.assertEqual(sink.calls, [])

    def test_patch_header_cannot_redirect_write_to_another_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            patch = self.PATCH.replace(b"staging/a.py", b"staging/b.py")
            (
                _,
                contract,
                budget,
                compiled,
                scheduler,
                target,
                source,
                sink,
            ) = self._runtime(tmp, patch=patch)
            result = scheduler.run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "failed")
            self.assertEqual(
                result.observations[0].reason_code,
                "PATCH_TARGET_HEADER_MISMATCH",
            )
            self.assertEqual(target.read_bytes(), self.ORIGINAL)
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)
            self.assertEqual(len(source.calls), 1)
            self.assertEqual(sink.calls, [])

    def test_context_mismatch_preserves_original_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = b'value = 2\nprint("old")\n'
            (
                _,
                contract,
                budget,
                compiled,
                scheduler,
                target,
                source,
                sink,
            ) = self._runtime(tmp, original=original)
            result = scheduler.run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.observations[0].reason_code, "PATCH_CONTEXT_MISMATCH")
            self.assertEqual(target.read_bytes(), original)
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)
            self.assertEqual(len(source.calls), 1)
            self.assertEqual(sink.calls, [])

    def test_multifile_patch_is_denied_without_second_file_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            patch = self.PATCH + (
                b"--- a/staging/b.py\n"
                b"+++ b/staging/b.py\n"
                b"@@ -1 +1 @@\n"
                b"-old\n"
                b"+new\n"
            )
            (
                _,
                contract,
                budget,
                compiled,
                scheduler,
                target,
                _,
                sink,
            ) = self._runtime(tmp, patch=patch)
            result = scheduler.run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.observations[0].reason_code, "PATCH_MULTIFILE_DENIED")
            self.assertEqual(target.read_bytes(), self.ORIGINAL)
            self.assertEqual(sink.calls, [])

    def test_evidence_failure_rolls_back_original_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            (
                _,
                contract,
                budget,
                compiled,
                scheduler,
                target,
                source,
                sink,
            ) = self._runtime(tmp, evidence_fail=True)
            result = scheduler.run(
                compiled_plan=compiled,
                task_contract=contract,
                budget=budget,
            )
            self.assertEqual(result.status, "failed")
            self.assertEqual(
                result.observations[0].reason_code,
                "PATCH_EVIDENCE_WRITE_FAILED",
            )
            self.assertEqual(target.read_bytes(), self.ORIGINAL)
            self.assertEqual(budget.snapshot()["tool_calls_used"], 1)
            self.assertEqual(len(source.calls), 1)
            self.assertEqual(len(sink.calls), 1)


if __name__ == "__main__":
    unittest.main()
