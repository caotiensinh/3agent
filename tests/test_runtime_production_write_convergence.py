import hashlib
import tempfile
import unittest
from pathlib import Path

from three_agent.capability_registry import CapabilityRegistry
from three_agent.execution_budget import TaskExecutionBudgetState
from three_agent.runtime_checkpoint import RuntimeCheckpointStore
from three_agent.runtime_execution_plan import ExecutionNode
from three_agent.runtime_invocation import RuntimeInvocationBundle, TypedCapabilityInvocation
from three_agent.runtime_invocation_binding import RuntimeInvocationBindingStore
from three_agent.runtime_observation_ledger import RuntimeObservationLedger
from three_agent.runtime_plan_compiler import RuntimePlanCompiler
from three_agent.runtime_production_adapters import (
    ProductionCapabilityAdapterRegistry,
    _IMPLEMENTED,
)
from three_agent.runtime_production_scheduler import ProductionAuditedRuntimeDAGScheduler
from three_agent.runtime_reviewed_patch import ReviewedPatchBoundary
from three_agent.runtime_reviewed_staging import ReviewedStagingBoundary
from three_agent.store import TaskStore
from three_agent.task_contract import TOOLS, TaskContractCompiler


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class FakeStagingSource:
    def __init__(self, content: bytes):
        self.content = content
        self.calls = []

    def resolve_content(self, *, task_id, content_ref, max_bytes):
        self.calls.append((task_id, content_ref, max_bytes))
        return self.content


class FakePatchSource:
    def __init__(self, patch: bytes):
        self.patch = patch
        self.calls = []

    def resolve_patch(self, *, task_id, patch_ref, max_bytes):
        self.calls.append((task_id, patch_ref, max_bytes))
        return self.patch


class FakeStagingEvidenceSink:
    def __init__(self):
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
        return ("artifact:staging-convergence",)


class FakePatchEvidenceSink:
    def __init__(self):
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
        return ("artifact:patch-convergence",)


class RuntimeProductionWriteConvergenceTests(unittest.TestCase):
    ORIGINAL = b'value = 1\nprint("old")\n'
    PATCH = (
        b"--- a/staging/a.py\n"
        b"+++ b/staging/a.py\n"
        b"@@ -1,2 +1,2 @@\n"
        b" value = 1\n"
        b'-print("old")\n'
        b'+print("new")\n'
    )

    def test_every_canonical_tool_has_an_explicit_production_boundary(self):
        self.assertEqual(set(_IMPLEMENTED), set(TOOLS))

    @classmethod
    def _runtime(cls, tmp, *, risk_level="low", approvals_required=False):
        store = TaskStore(Path(tmp) / "tasks.db")
        store.initialize()
        task = store.create_task("write convergence", "staging to patch fixture")
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type="code_fix",
            sensitivity="internal",
            risk_level=risk_level,
            allowed_tools=("write_staging", "apply_patch"),
            write_scope=("staging/a.py",),
        )
        store.bind_task_contract(task.task_id, contract.to_dict())
        budget = TaskExecutionBudgetState.from_bound_contract(store, task.task_id)

        registry = CapabilityRegistry.default()
        compiled = RuntimePlanCompiler(registry).compile(
            plan_id="production_write_convergence",
            task_contract=contract,
            nodes=(
                ExecutionNode(
                    "stage",
                    "write_staging",
                    "path",
                    "staging/a.py",
                    "write",
                    approval_required=approvals_required,
                ),
                ExecutionNode(
                    "patch",
                    "apply_patch",
                    "path",
                    "staging/a.py",
                    "write",
                    depends_on=("stage",),
                    idempotent=False,
                    approval_required=approvals_required,
                ),
            ),
        )
        stage_invocation = TypedCapabilityInvocation.compile(
            compiled_plan=compiled,
            node_id="stage",
            operation="materialize",
            arguments={
                "content_ref": "artifact:original-file",
                "content_sha256": _sha256(cls.ORIGINAL),
            },
        )
        patch_invocation = TypedCapabilityInvocation.compile(
            compiled_plan=compiled,
            node_id="patch",
            operation="apply",
            arguments={
                "patch_ref": "artifact:reviewed-patch",
                "patch_sha256": _sha256(cls.PATCH),
            },
        )
        bundle = RuntimeInvocationBundle.compile(
            compiled_plan=compiled,
            invocations=(stage_invocation, patch_invocation),
        )

        workspace = Path(tmp) / "workspace"
        (workspace / "staging").mkdir(parents=True)
        stage_source = FakeStagingSource(cls.ORIGINAL)
        patch_source = FakePatchSource(cls.PATCH)
        stage_sink = FakeStagingEvidenceSink()
        patch_sink = FakePatchEvidenceSink()
        staging_boundary = ReviewedStagingBoundary(
            staging_root=workspace,
            content_source=stage_source,
            evidence_sink=stage_sink,
        )
        patch_boundary = ReviewedPatchBoundary(
            workspace_root=workspace,
            patch_source=patch_source,
            evidence_sink=patch_sink,
        )
        adapters = ProductionCapabilityAdapterRegistry(
            compiled_plan=compiled,
            task_contract=contract,
            invocation_bundle=bundle,
            budget=budget,
            staging_boundary=staging_boundary,
            patch_boundary=patch_boundary,
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
        return {
            "store": store,
            "contract": contract,
            "budget": budget,
            "compiled": compiled,
            "scheduler": scheduler,
            "target": workspace / "staging" / "a.py",
            "stage_source": stage_source,
            "patch_source": patch_source,
            "stage_sink": stage_sink,
            "patch_sink": patch_sink,
        }

    def test_staging_then_patch_converges_and_completed_resume_does_not_reexecute(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self._runtime(tmp)
            first = runtime["scheduler"].run(
                compiled_plan=runtime["compiled"],
                task_contract=runtime["contract"],
                budget=runtime["budget"],
            )
            self.assertEqual(first.status, "completed")
            self.assertEqual(first.completed_node_ids, ("patch", "stage"))
            self.assertEqual(
                [item.reason_code for item in first.observations],
                ["STAGING_MATERIALIZE_OK", "PATCH_APPLY_OK"],
            )
            self.assertEqual(
                runtime["target"].read_bytes(),
                b'value = 1\nprint("new")\n',
            )
            snapshot = runtime["budget"].snapshot()
            self.assertEqual(snapshot["steps_used"], 2)
            self.assertEqual(snapshot["tool_calls_used"], 2)
            self.assertEqual(len(runtime["stage_source"].calls), 1)
            self.assertEqual(len(runtime["patch_source"].calls), 1)

            resumed = runtime["scheduler"].run(
                compiled_plan=runtime["compiled"],
                task_contract=runtime["contract"],
                budget=runtime["budget"],
                checkpoint=first.checkpoint,
            )
            self.assertEqual(resumed.status, "completed")
            self.assertEqual(resumed.observations, ())
            self.assertEqual(runtime["budget"].snapshot(), snapshot)
            self.assertEqual(len(runtime["stage_source"].calls), 1)
            self.assertEqual(len(runtime["patch_source"].calls), 1)
            self.assertEqual(
                runtime["target"].read_bytes(),
                b'value = 1\nprint("new")\n',
            )

    def test_high_risk_mutations_require_separate_approval_before_each_side_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self._runtime(
                tmp,
                risk_level="high",
                approvals_required=True,
            )
            blocked = runtime["scheduler"].run(
                compiled_plan=runtime["compiled"],
                task_contract=runtime["contract"],
                budget=runtime["budget"],
            )
            self.assertEqual(blocked.status, "blocked")
            self.assertFalse(runtime["target"].exists())
            self.assertEqual(runtime["budget"].snapshot()["tool_calls_used"], 0)
            self.assertEqual(runtime["stage_source"].calls, [])
            self.assertEqual(runtime["patch_source"].calls, [])

            staged = runtime["scheduler"].run(
                compiled_plan=runtime["compiled"],
                task_contract=runtime["contract"],
                budget=runtime["budget"],
                approved_node_ids=("stage",),
                checkpoint=blocked.checkpoint,
            )
            self.assertEqual(staged.status, "blocked")
            self.assertEqual(staged.completed_node_ids, ("stage",))
            self.assertEqual(runtime["target"].read_bytes(), self.ORIGINAL)
            self.assertEqual(runtime["budget"].snapshot()["tool_calls_used"], 1)
            self.assertEqual(len(runtime["stage_source"].calls), 1)
            self.assertEqual(runtime["patch_source"].calls, [])

            patched = runtime["scheduler"].run(
                compiled_plan=runtime["compiled"],
                task_contract=runtime["contract"],
                budget=runtime["budget"],
                approved_node_ids=("patch",),
                checkpoint=staged.checkpoint,
            )
            self.assertEqual(patched.status, "completed")
            self.assertEqual(
                runtime["target"].read_bytes(),
                b'value = 1\nprint("new")\n',
            )
            self.assertEqual(runtime["budget"].snapshot()["tool_calls_used"], 2)
            self.assertEqual(len(runtime["stage_source"].calls), 1)
            self.assertEqual(len(runtime["patch_source"].calls), 1)
            self.assertEqual(len(runtime["stage_sink"].calls), 1)
            self.assertEqual(len(runtime["patch_sink"].calls), 1)


if __name__ == "__main__":
    unittest.main()
