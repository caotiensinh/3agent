import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from three_agent.artifacts import ArtifactManager
from three_agent.runtime_dispatch import RuntimeV3DispatchDescriptor
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler
from three_agent.validator_ledger import ValidatorLedger
from three_agent.workflow_dispatch import (
    RUNTIME_DISPATCH_SCHEMA_VERSION,
    RUNTIME_EXECUTION_PROFILE,
    WorkflowDispatchController,
    WorkflowDispatchError,
)


GOOD1 = "sha256:" + "1" * 64
GOOD2 = "sha256:" + "2" * 64
GOOD3 = "sha256:" + "3" * 64
GOOD4 = "sha256:" + "4" * 64


class FakeWorkflow:
    def __init__(self):
        self.calls = []

    def run_task(self, task_id, **kwargs):
        self.calls.append((task_id, kwargs))
        return {"status": "completed", "task_status": "done", "stage": "v2"}


class FakeRuntimeExecutor:
    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.describe_calls = []
        self.execute_calls = []

    def describe(self, runtime_ref):
        self.describe_calls.append(runtime_ref)
        return self.descriptor

    def execute(self, runtime_ref, **kwargs):
        self.execute_calls.append((runtime_ref, kwargs))
        return {
            "status": "completed",
            "task_status": "done",
            "stage": "runtime_v3_completed",
            "manifest_path": "/srv/private/runtime.json",
            "raw_output": "must-not-escape",
        }


class WorkflowDispatchRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = TaskStore(root / "workspace.db")
        self.store.initialize()
        self.artifacts = ArtifactManager(root / "artifacts")
        self.bridge = SimpleNamespace(
            sensitivity="internal",
            public_web=False,
            ledger=ValidatorLedger(self.store),
        )
        self.workflow = FakeWorkflow()

        task = self.store.create_task("Runtime code fix", "Apply reviewed package")
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type="code_fix",
            sensitivity="internal",
            risk_level="low",
            allowed_sources=("repo",),
            allowed_tools=("read_file", "write_staging", "apply_patch", "run_tests"),
            write_scope=("staging/a.py",),
        )
        self.store.bind_task_contract(task.task_id, contract.to_dict())
        self.task_id = task.task_id
        self.runtime_ref = "runtime:codefix-001"
        self.descriptor = RuntimeV3DispatchDescriptor(
            task_id=self.task_id,
            runtime_ref=self.runtime_ref,
            compiled_plan_fingerprint=GOOD1,
            invocation_bundle_fingerprint=GOOD2,
            authority_fingerprint=GOOD3,
            source_binding_bundle_fingerprint=GOOD4,
        ).validate()
        self.executor = FakeRuntimeExecutor(self.descriptor)
        orchestrator = SimpleNamespace(
            store=self.store,
            artifacts=self.artifacts,
            runtime_validator_bridge=self.bridge,
            workflow=self.workflow,
            runtime_dispatch_executor=self.executor,
        )
        self.controller = WorkflowDispatchController(orchestrator)

    def tearDown(self):
        self.tmp.cleanup()

    def test_prepare_runtime_is_opt_in_content_free_and_does_not_call_v2(self):
        prepared = self.controller.prepare_runtime_v3(self.runtime_ref)
        self.assertEqual(prepared["schema_version"], RUNTIME_DISPATCH_SCHEMA_VERSION)
        self.assertEqual(prepared["execution_profile"], RUNTIME_EXECUTION_PROFILE)
        self.assertEqual(prepared["task_id"], self.task_id)
        self.assertEqual(
            prepared["runtime_descriptor_fingerprint"],
            self.descriptor.fingerprint,
        )
        self.assertFalse(prepared["execution_authorized"])
        self.assertEqual(self.workflow.calls, [])
        self.assertEqual(self.executor.execute_calls, [])

        record = json.loads(
            (self.controller.root / f"{self.task_id}.json").read_text(encoding="utf-8")
        )
        self.assertEqual(record["runtime_ref"], self.runtime_ref)
        self.assertEqual(record["runtime_descriptor_fingerprint"], self.descriptor.fingerprint)
        for forbidden_key in (
            "invocation_bundle",
            "source_binding_bundle",
            "query_bundle",
            "compiled_plan",
            "raw_package",
        ):
            self.assertNotIn(forbidden_key, record)
        encoded = repr(record)
        self.assertNotIn("SELECT ", encoded)
        self.assertNotIn("diff --git", encoded)
        self.assertNotIn("/srv/private", encoded)

    def test_missing_executor_fails_closed_without_writing_dispatch_record(self):
        controller = WorkflowDispatchController(
            SimpleNamespace(
                store=self.store,
                artifacts=self.artifacts,
                runtime_validator_bridge=self.bridge,
                workflow=self.workflow,
            )
        )
        with self.assertRaisesRegex(WorkflowDispatchError, "RUNTIME_V3_EXECUTOR_REQUIRED"):
            controller.prepare_runtime_v3(self.runtime_ref)
        self.assertFalse((controller.root / f"{self.task_id}.json").exists())

    def test_active_sensitivity_mismatch_is_rejected_before_preparation(self):
        self.bridge.sensitivity = "confidential"
        with self.assertRaisesRegex(WorkflowDispatchError, "confidentiality zone"):
            self.controller.prepare_runtime_v3(self.runtime_ref)
        self.assertEqual(self.executor.execute_calls, [])
        self.assertFalse((self.controller.root / f"{self.task_id}.json").exists())

    def test_descriptor_drift_blocks_execution_before_executor_call(self):
        prepared = self.controller.prepare_runtime_v3(self.runtime_ref)
        self.executor.descriptor = RuntimeV3DispatchDescriptor(
            task_id=self.task_id,
            runtime_ref=self.runtime_ref,
            compiled_plan_fingerprint="sha256:" + "9" * 64,
            invocation_bundle_fingerprint=GOOD2,
            authority_fingerprint=GOOD3,
            source_binding_bundle_fingerprint=GOOD4,
        ).validate()
        with self.assertRaisesRegex(WorkflowDispatchError, "descriptor drift"):
            self.controller.execute_runtime_v3(
                self.task_id,
                approval_fingerprint=prepared["approval_fingerprint"],
                confirmation="AUTHORIZE",
                approver_id="admin-1",
            )
        self.assertEqual(self.executor.execute_calls, [])
        record = json.loads(
            (self.controller.root / f"{self.task_id}.json").read_text(encoding="utf-8")
        )
        self.assertEqual(record["status"], "prepared")

    def test_exact_authorization_executes_once_and_replay_is_denied(self):
        prepared = self.controller.prepare_runtime_v3(self.runtime_ref)
        result = self.controller.execute_runtime_v3(
            self.task_id,
            approval_fingerprint=prepared["approval_fingerprint"],
            confirmation="AUTHORIZE",
            approver_id="admin-1",
        )
        self.assertEqual(result["dispatch_status"], "completed")
        self.assertEqual(result["execution_profile"], RUNTIME_EXECUTION_PROFILE)
        self.assertEqual(len(self.executor.execute_calls), 1)
        runtime_ref, kwargs = self.executor.execute_calls[0]
        self.assertEqual(runtime_ref, self.runtime_ref)
        self.assertEqual(
            kwargs["expected_descriptor_fingerprint"], self.descriptor.fingerprint
        )
        self.assertEqual(kwargs["approval_fingerprint"], prepared["approval_fingerprint"])
        self.assertTrue(kwargs["approver_ref"].startswith("sha256:"))
        self.assertEqual(self.workflow.calls, [])
        encoded = repr(result)
        self.assertNotIn("/srv/private", encoded)
        self.assertNotIn("raw_output", encoded)
        self.assertNotIn("must-not-escape", encoded)

        with self.assertRaisesRegex(WorkflowDispatchError, "not executable"):
            self.controller.execute_runtime_v3(
                self.task_id,
                approval_fingerprint=prepared["approval_fingerprint"],
                confirmation="AUTHORIZE",
                approver_id="admin-1",
            )
        self.assertEqual(len(self.executor.execute_calls), 1)

    def test_wrong_fingerprint_and_confirmation_never_execute(self):
        prepared = self.controller.prepare_runtime_v3(self.runtime_ref)
        with self.assertRaisesRegex(WorkflowDispatchError, "fingerprint"):
            self.controller.execute_runtime_v3(
                self.task_id,
                approval_fingerprint="sha256:" + "0" * 64,
                confirmation="AUTHORIZE",
                approver_id="admin-1",
            )
        with self.assertRaisesRegex(WorkflowDispatchError, "AUTHORIZE"):
            self.controller.execute_runtime_v3(
                self.task_id,
                approval_fingerprint=prepared["approval_fingerprint"],
                confirmation="yes",
                approver_id="admin-1",
            )
        self.assertEqual(self.executor.execute_calls, [])


if __name__ == "__main__":
    unittest.main()
