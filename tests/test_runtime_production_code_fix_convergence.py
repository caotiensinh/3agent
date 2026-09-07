import hashlib
import json
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
from three_agent.runtime_production_adapters import ProductionCapabilityAdapterRegistry
from three_agent.runtime_production_scheduler import ProductionAuditedRuntimeDAGScheduler
from three_agent.runtime_reviewed_execution import (
    ReviewedCommandProfile,
    ReviewedExecutionBoundary,
    SandboxCommandResult,
)
from three_agent.runtime_reviewed_patch import ReviewedPatchBoundary
from three_agent.runtime_reviewed_read import ReviewedReadBoundary
from three_agent.runtime_reviewed_search import ReviewedRepoSearchBoundary
from three_agent.runtime_reviewed_staging import ReviewedStagingBoundary
from three_agent.runtime_source_authority import (
    ReviewedSourceBinding,
    RuntimeSourceBindingBundle,
)
from three_agent.runtime_source_binding_store import RuntimeSourceBindingStore
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class FakeRepoSearchEvidenceSink:
    def __init__(self):
        self.calls = []

    def persist_repo_search(
        self,
        *,
        task_id,
        node_id,
        source_class,
        resource_ref,
        query_sha256,
        result,
        result_sha256,
    ):
        self.calls.append(
            (
                task_id,
                node_id,
                source_class,
                resource_ref,
                query_sha256,
                result,
                result_sha256,
            )
        )
        return ("artifact:codefix-search",)


class FakeFileReadEvidenceSink:
    def __init__(self):
        self.calls = []

    def persist_file_read(
        self,
        *,
        task_id,
        node_id,
        source_class,
        resource_ref,
        content,
        content_sha256,
    ):
        self.calls.append(
            (
                task_id,
                node_id,
                source_class,
                resource_ref,
                content,
                content_sha256,
            )
        )
        return ("artifact:codefix-read",)


class FakeStagingSource:
    def __init__(self, content: bytes):
        self.content = content
        self.calls = []

    def resolve_content(self, *, task_id, content_ref, max_bytes):
        self.calls.append((task_id, content_ref, max_bytes))
        return self.content


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
        return ("artifact:codefix-stage",)


class FakePatchSource:
    def __init__(self, patch: bytes):
        self.patch = patch
        self.calls = []

    def resolve_patch(self, *, task_id, patch_ref, max_bytes):
        self.calls.append((task_id, patch_ref, max_bytes))
        return self.patch


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
        return ("artifact:codefix-patch",)


class InspectingSandboxRunner:
    def __init__(self, *, target: Path, fail_linter=False):
        self.target = target
        self.fail_linter = fail_linter
        self.calls = []

    def run(self, *, argv, cwd, timeout_seconds, constraints):
        observed = self.target.read_bytes()
        self.calls.append((argv, cwd, timeout_seconds, constraints, observed))
        executable = Path(argv[0]).name.casefold()
        returncode = 2 if self.fail_linter and executable.startswith("ruff") else 0
        return SandboxCommandResult.from_output_hashes(
            returncode=returncode,
            stdout=b"reviewed command output",
            stderr=b"lint failed" if returncode else b"",
            evidence_refs=(
                "artifact:codefix-lint"
                if executable.startswith("ruff")
                else "artifact:codefix-tests",
            ),
        )


class RuntimeProductionCodeFixConvergenceTests(unittest.TestCase):
    ORIGINAL = b'value = 1\nprint("old")\n'
    PATCHED = b'value = 1\nprint("new")\n'
    PATCH = (
        b"--- a/staging/a.py\n"
        b"+++ b/staging/a.py\n"
        b"@@ -1,2 +1,2 @@\n"
        b" value = 1\n"
        b'-print("old")\n'
        b'+print("new")\n'
    )

    @classmethod
    def _runtime(cls, tmp, *, fail_linter=False):
        root = Path(tmp) / "workspace"
        (root / "src").mkdir(parents=True)
        (root / "staging").mkdir()
        (root / "src" / "a.py").write_bytes(cls.ORIGINAL)

        store = TaskStore(Path(tmp) / "tasks.db")
        store.initialize()
        task = store.create_task("production code fix", "full code-fix convergence fixture")
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type="code_fix",
            sensitivity="internal",
            risk_level="low",
            allowed_sources=("repo",),
            allowed_tools=(
                "search_repo",
                "read_file",
                "write_staging",
                "apply_patch",
                "run_linter",
                "run_tests",
            ),
            write_scope=("staging/a.py",),
        )
        store.bind_task_contract(task.task_id, contract.to_dict())
        budget = TaskExecutionBudgetState.from_bound_contract(store, task.task_id)

        registry = CapabilityRegistry.default()
        compiled = RuntimePlanCompiler(registry).compile(
            plan_id="production_code_fix_convergence",
            task_contract=contract,
            nodes=(
                ExecutionNode(
                    "search",
                    "search_repo",
                    "repo",
                    "workspace_repo",
                    "read",
                ),
                ExecutionNode(
                    "read",
                    "read_file",
                    "path",
                    "src/a.py",
                    "read",
                    depends_on=("search",),
                ),
                ExecutionNode(
                    "stage",
                    "write_staging",
                    "path",
                    "staging/a.py",
                    "write",
                    depends_on=("read",),
                ),
                ExecutionNode(
                    "patch",
                    "apply_patch",
                    "path",
                    "staging/a.py",
                    "write",
                    depends_on=("stage",),
                    idempotent=False,
                ),
                ExecutionNode(
                    "lint",
                    "run_linter",
                    "repo",
                    "workspace_repo",
                    "execute",
                    depends_on=("patch",),
                ),
                ExecutionNode(
                    "tests",
                    "run_tests",
                    "repo",
                    "workspace_repo",
                    "execute",
                    depends_on=("lint",),
                ),
            ),
        )

        invocations = (
            TypedCapabilityInvocation.compile(
                compiled_plan=compiled,
                node_id="search",
                operation="search",
                arguments={"query": "print", "max_results": 5},
            ),
            TypedCapabilityInvocation.compile(
                compiled_plan=compiled,
                node_id="read",
                operation="read",
                arguments={"max_bytes": 1024},
            ),
            TypedCapabilityInvocation.compile(
                compiled_plan=compiled,
                node_id="stage",
                operation="materialize",
                arguments={
                    "content_ref": "artifact:codefix-original",
                    "content_sha256": _sha256(cls.ORIGINAL),
                },
            ),
            TypedCapabilityInvocation.compile(
                compiled_plan=compiled,
                node_id="patch",
                operation="apply",
                arguments={
                    "patch_ref": "artifact:codefix-patch",
                    "patch_sha256": _sha256(cls.PATCH),
                },
            ),
            TypedCapabilityInvocation.compile(
                compiled_plan=compiled,
                node_id="lint",
                operation="run",
                arguments={"profile": "default"},
            ),
            TypedCapabilityInvocation.compile(
                compiled_plan=compiled,
                node_id="tests",
                operation="run",
                arguments={"suite": "default"},
            ),
        )
        invocation_bundle = RuntimeInvocationBundle.compile(
            compiled_plan=compiled,
            invocations=invocations,
        )

        source_bindings = (
            ReviewedSourceBinding.bind(
                compiled_plan=compiled,
                node_id="search",
                source_class="repo",
                local_root=root,
            ),
            ReviewedSourceBinding.bind(
                compiled_plan=compiled,
                node_id="read",
                source_class="repo",
                local_root=root,
            ),
        )
        source_bundle = RuntimeSourceBindingBundle.compile(
            compiled_plan=compiled,
            task_contract=contract,
            bindings=source_bindings,
            registry=registry,
        )

        search_sink = FakeRepoSearchEvidenceSink()
        read_sink = FakeFileReadEvidenceSink()
        stage_source = FakeStagingSource(cls.ORIGINAL)
        stage_sink = FakeStagingEvidenceSink()
        patch_source = FakePatchSource(cls.PATCH)
        patch_sink = FakePatchEvidenceSink()
        target = root / "staging" / "a.py"
        runner = InspectingSandboxRunner(
            target=target,
            fail_linter=fail_linter,
        )

        search_boundary = ReviewedRepoSearchBoundary(
            compiled_plan=compiled,
            task_contract=contract,
            source_binding_bundle=source_bundle,
            evidence_sink=search_sink,
            registry=registry,
        )
        read_boundary = ReviewedReadBoundary(
            compiled_plan=compiled,
            task_contract=contract,
            source_binding_bundle=source_bundle,
            evidence_sink=read_sink,
            registry=registry,
        )
        staging_boundary = ReviewedStagingBoundary(
            staging_root=root,
            content_source=stage_source,
            evidence_sink=stage_sink,
        )
        patch_boundary = ReviewedPatchBoundary(
            workspace_root=root,
            patch_source=patch_source,
            evidence_sink=patch_sink,
        )
        execution_boundary = ReviewedExecutionBoundary(
            workspace_root=root,
            profiles=(
                ReviewedCommandProfile(
                    "default",
                    "run_linter",
                    ("ruff", "check", "."),
                ),
                ReviewedCommandProfile(
                    "default",
                    "run_tests",
                    ("pytest", "-q"),
                ),
            ),
            runner=runner,
        )

        adapters = ProductionCapabilityAdapterRegistry(
            compiled_plan=compiled,
            task_contract=contract,
            invocation_bundle=invocation_bundle,
            budget=budget,
            execution_boundary=execution_boundary,
            read_boundary=read_boundary,
            repo_search_boundary=search_boundary,
            staging_boundary=staging_boundary,
            patch_boundary=patch_boundary,
            source_binding_bundle=source_bundle,
            registry=registry,
        )
        scheduler = ProductionAuditedRuntimeDAGScheduler(
            adapters=adapters,
            invocation_binding_store=RuntimeInvocationBindingStore(
                Path(tmp) / "invocation_bindings"
            ),
            source_binding_store=RuntimeSourceBindingStore(
                Path(tmp) / "source_bindings"
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
            "root": root,
            "target": target,
            "source_bundle": source_bundle,
            "search_sink": search_sink,
            "read_sink": read_sink,
            "stage_source": stage_source,
            "stage_sink": stage_sink,
            "patch_source": patch_source,
            "patch_sink": patch_sink,
            "runner": runner,
        }

    def test_full_code_fix_dag_converges_under_one_governed_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self._runtime(tmp)
            result = runtime["scheduler"].run(
                compiled_plan=runtime["compiled"],
                task_contract=runtime["contract"],
                budget=runtime["budget"],
            )
            self.assertEqual(result.status, "completed")
            self.assertEqual(
                [item.reason_code for item in result.observations],
                [
                    "SEARCH_REPO_OK",
                    "READ_FILE_OK",
                    "STAGING_MATERIALIZE_OK",
                    "PATCH_APPLY_OK",
                    "EXECUTION_OK",
                    "EXECUTION_OK",
                ],
            )
            self.assertEqual(runtime["target"].read_bytes(), self.PATCHED)
            snapshot = runtime["budget"].snapshot()
            self.assertEqual(snapshot["steps_used"], 6)
            self.assertEqual(snapshot["tool_calls_used"], 6)

            self.assertEqual(len(runtime["search_sink"].calls), 1)
            search_payload = json.loads(runtime["search_sink"].calls[0][5].decode("utf-8"))
            self.assertGreaterEqual(search_payload["match_count"], 1)
            self.assertEqual(len(runtime["read_sink"].calls), 1)
            self.assertEqual(runtime["read_sink"].calls[0][4], self.ORIGINAL)
            self.assertEqual(len(runtime["stage_source"].calls), 1)
            self.assertEqual(len(runtime["patch_source"].calls), 1)
            self.assertEqual(len(runtime["runner"].calls), 2)
            for argv, cwd, _, constraints, observed in runtime["runner"].calls:
                self.assertEqual(cwd, runtime["root"].resolve())
                self.assertEqual(observed, self.PATCHED)
                self.assertEqual(constraints.network_scope, "deny")
                self.assertEqual(constraints.write_scope, ())
                self.assertIn(Path(argv[0]).name, {"ruff", "pytest"})
            self.assertNotIn(
                str(runtime["root"].resolve()),
                str(runtime["source_bundle"].metadata()),
            )

            resumed = runtime["scheduler"].run(
                compiled_plan=runtime["compiled"],
                task_contract=runtime["contract"],
                budget=runtime["budget"],
                checkpoint=result.checkpoint,
            )
            self.assertEqual(resumed.status, "completed")
            self.assertEqual(resumed.observations, ())
            self.assertEqual(runtime["budget"].snapshot(), snapshot)
            self.assertEqual(len(runtime["search_sink"].calls), 1)
            self.assertEqual(len(runtime["read_sink"].calls), 1)
            self.assertEqual(len(runtime["stage_source"].calls), 1)
            self.assertEqual(len(runtime["patch_source"].calls), 1)
            self.assertEqual(len(runtime["runner"].calls), 2)

    def test_linter_failure_stops_tests_after_patch_without_double_accounting(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self._runtime(tmp, fail_linter=True)
            result = runtime["scheduler"].run(
                compiled_plan=runtime["compiled"],
                task_contract=runtime["contract"],
                budget=runtime["budget"],
            )
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.failed_node_ids, ("lint",))
            self.assertEqual(
                [item.reason_code for item in result.observations],
                [
                    "SEARCH_REPO_OK",
                    "READ_FILE_OK",
                    "STAGING_MATERIALIZE_OK",
                    "PATCH_APPLY_OK",
                    "COMMAND_EXIT_NONZERO",
                ],
            )
            self.assertEqual(runtime["target"].read_bytes(), self.PATCHED)
            snapshot = runtime["budget"].snapshot()
            self.assertEqual(snapshot["steps_used"], 5)
            self.assertEqual(snapshot["tool_calls_used"], 5)
            self.assertEqual(len(runtime["runner"].calls), 1)
            self.assertEqual(Path(runtime["runner"].calls[0][0][0]).name, "ruff")


if __name__ == "__main__":
    unittest.main()
