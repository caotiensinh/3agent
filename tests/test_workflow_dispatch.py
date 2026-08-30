from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from three_agent.artifacts import ArtifactManager
from three_agent.store import TaskStore
from three_agent.validator_ledger import ValidatorLedger
from three_agent.workflow_dispatch import WorkflowDispatchController, WorkflowDispatchError


@dataclass
class FakeRunResult:
    task_id: str
    status: str = "completed"
    task_status: str = "done"
    stage: str = "daily_report_completed"
    manifest_path: str = "/local/workflow.json"
    error: str | None = None


class FakeWorkflow:
    def __init__(self):
        self.calls = []

    def run_task(self, task_id, **kwargs):
        self.calls.append((task_id, kwargs))
        return FakeRunResult(task_id)


def executable_contract():
    return {
        "title": "Internal weekly analysis",
        "objective": "Analyze approved internal project evidence and prepare a presentation and daily report.",
        "trigger": "manual",
        "risk_level": "low",
        "data_class": "internal",
        "nodes": [
            {"id": "start", "label": "Start", "kind": "input", "action": "input", "depends_on": [], "condition": "", "approval_required": False},
            {"id": "research", "label": "Research", "kind": "agent", "action": "research", "depends_on": ["start"], "condition": "", "approval_required": False},
            {"id": "validate", "label": "Validate", "kind": "validation", "action": "validate", "depends_on": ["research"], "condition": "", "approval_required": False},
            {"id": "presentation", "label": "Presentation", "kind": "agent", "action": "presentation", "depends_on": ["validate"], "condition": "", "approval_required": False},
            {"id": "daily", "label": "Daily report", "kind": "agent", "action": "daily_report", "depends_on": ["presentation"], "condition": "", "approval_required": False},
            {"id": "done", "label": "Done", "kind": "output", "action": "output", "depends_on": ["daily"], "condition": "", "approval_required": False},
        ],
        "outputs": ["Presentation and daily report"],
        "warnings": [],
    }


class WorkflowDispatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        store = TaskStore(root / "workspace.db")
        store.initialize()
        artifacts = ArtifactManager(root / "artifacts")
        bridge = SimpleNamespace(
            sensitivity="internal",
            public_web=False,
            ledger=ValidatorLedger(store),
        )
        workflow = FakeWorkflow()
        orchestrator = SimpleNamespace(
            store=store,
            artifacts=artifacts,
            runtime_validator_bridge=bridge,
            workflow=workflow,
        )
        self.store = store
        self.workflow = workflow
        self.controller = WorkflowDispatchController(orchestrator)

    def tearDown(self):
        self.tmp.cleanup()

    def test_prepare_binds_authoritative_contract_without_authorizing_execution(self):
        prepared = self.controller.prepare(executable_contract(), language="en")
        self.assertEqual(prepared["status"], "prepared")
        self.assertFalse(prepared["execution_authorized"])
        self.assertTrue(prepared["approval_required"])
        self.assertTrue(prepared["admin_approval_required"])
        self.assertTrue(prepared["workflow_sha256"].startswith("sha256:"))
        self.assertTrue(prepared["task_contract_sha256"].startswith("sha256:"))
        self.assertIsNotNone(self.store.task_contract_for_task(prepared["task_id"]))

        record_path = self.controller.root / f"{prepared['task_id']}.json"
        stored = record_path.read_text(encoding="utf-8")
        self.assertNotIn("Internal weekly analysis", stored)
        self.assertNotIn("Analyze approved internal project evidence", stored)
        self.assertNotIn('"contract"', stored)

    def test_wrong_fingerprint_never_calls_runtime(self):
        prepared = self.controller.prepare(executable_contract())
        with self.assertRaisesRegex(WorkflowDispatchError, "fingerprint"):
            self.controller.execute(
                prepared["task_id"],
                approval_fingerprint="sha256:" + "0" * 64,
                confirmation="AUTHORIZE",
                approver_id="admin-1",
            )
        self.assertEqual(self.workflow.calls, [])

    def test_exact_authorization_runs_once_and_replay_is_rejected(self):
        prepared = self.controller.prepare(executable_contract())
        result = self.controller.execute(
            prepared["task_id"],
            approval_fingerprint=prepared["approval_fingerprint"],
            confirmation="AUTHORIZE",
            approver_id="admin-1",
        )
        self.assertEqual(result["dispatch_status"], "completed")
        self.assertEqual(len(self.workflow.calls), 1)
        self.assertTrue(self.workflow.calls[0][1]["live"])

        with self.assertRaisesRegex(WorkflowDispatchError, "not executable"):
            self.controller.execute(
                prepared["task_id"],
                approval_fingerprint=prepared["approval_fingerprint"],
                confirmation="AUTHORIZE",
                approver_id="admin-1",
            )
        self.assertEqual(len(self.workflow.calls), 1)

    def test_confirmation_must_be_exact(self):
        prepared = self.controller.prepare(executable_contract())
        with self.assertRaisesRegex(WorkflowDispatchError, "AUTHORIZE"):
            self.controller.execute(
                prepared["task_id"],
                approval_fingerprint=prepared["approval_fingerprint"],
                confirmation="yes",
                approver_id="admin-1",
            )
        self.assertEqual(self.workflow.calls, [])

    def test_non_low_risk_and_non_manual_trigger_stay_design_only(self):
        payload = executable_contract()
        payload["risk_level"] = "medium"
        with self.assertRaisesRegex(WorkflowDispatchError, "low-risk"):
            self.controller.prepare(payload)

        payload = executable_contract()
        payload["trigger"] = "schedule"
        with self.assertRaisesRegex(WorkflowDispatchError, "design-only"):
            self.controller.prepare(payload)
        self.assertEqual(self.workflow.calls, [])

    def test_manual_approval_decision_and_branching_stay_design_only(self):
        payload = executable_contract()
        payload["nodes"][2].update(kind="manual", action="manual_step")
        with self.assertRaisesRegex(WorkflowDispatchError, "design-only"):
            self.controller.prepare(payload)

        payload = executable_contract()
        payload["nodes"][2].update(kind="approval", action="human_approval", approval_required=True)
        with self.assertRaisesRegex(WorkflowDispatchError, "design-only"):
            self.controller.prepare(payload)

        payload = executable_contract()
        payload["nodes"][2].update(kind="decision", action="validate")
        with self.assertRaisesRegex(WorkflowDispatchError, "design-only"):
            self.controller.prepare(payload)

        payload = executable_contract()
        payload["nodes"][3]["depends_on"] = ["research"]
        with self.assertRaisesRegex(WorkflowDispatchError, "branching"):
            self.controller.prepare(payload)
        self.assertEqual(self.workflow.calls, [])

    def test_data_class_must_match_active_zone(self):
        payload = executable_contract()
        payload["data_class"] = "confidential"
        with self.assertRaisesRegex(WorkflowDispatchError, "confidentiality zone"):
            self.controller.prepare(payload)

    def test_fixed_profile_without_explicit_validate_node_is_supported(self):
        payload = executable_contract()
        payload["nodes"] = [node for node in payload["nodes"] if node["id"] != "validate"]
        for node in payload["nodes"]:
            if node["id"] == "presentation":
                node["depends_on"] = ["research"]
        prepared = self.controller.prepare(payload)
        self.assertEqual(
            prepared["actions"],
            ["input", "research", "presentation", "daily_report", "output"],
        )


if __name__ == "__main__":
    unittest.main()
