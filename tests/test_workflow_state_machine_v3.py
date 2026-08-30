from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from three_agent.artifacts import ArtifactManager
from three_agent.execution_budget import TaskExecutionBudgetState
from three_agent.model_authority import TaskModelAuthority
from three_agent.models import TaskStatus
from three_agent.store import TaskStore
from three_agent.validator_ledger import ValidatorLedger
from three_agent.workflow_state_machine import (
    WORKFLOW_V3_MAX_WALL_TIME_MS,
    WorkflowStateError,
    WorkflowStateMachineController,
)


def branching_contract():
    return {
        "title": "Validated management report",
        "objective": "Research internal evidence, branch on validation, require approval, then prepare the approved report.",
        "trigger": "manual",
        "risk_level": "low",
        "data_class": "internal",
        "nodes": [
            {"id": "start", "label": "Start", "kind": "input", "action": "input", "depends_on": [], "condition": "", "approval_required": False},
            {"id": "research", "label": "Research", "kind": "agent", "action": "research", "depends_on": ["start"], "condition": "", "approval_required": False},
            {"id": "gate", "label": "Evidence valid?", "kind": "decision", "action": "validate", "depends_on": ["research"], "condition": "", "approval_required": False},
            {"id": "approve", "label": "Manager approval", "kind": "approval", "action": "human_approval", "depends_on": ["gate"], "condition": "passed", "approval_required": True},
            {"id": "bad", "label": "Validation failed", "kind": "output", "action": "output", "depends_on": ["gate"], "condition": "failed", "approval_required": False},
            {"id": "presentation", "label": "Presentation", "kind": "agent", "action": "presentation", "depends_on": ["approve"], "condition": "approved", "approval_required": False},
            {"id": "rejected", "label": "Rejected", "kind": "output", "action": "output", "depends_on": ["approve"], "condition": "rejected", "approval_required": False},
            {"id": "daily", "label": "Daily report", "kind": "agent", "action": "daily_report", "depends_on": ["presentation"], "condition": "", "approval_required": False},
            {"id": "done", "label": "Done", "kind": "output", "action": "output", "depends_on": ["daily"], "condition": "", "approval_required": False},
        ],
        "outputs": ["Approved presentation and daily report"],
        "warnings": [],
    }


class FakeResearchAgent:
    def __init__(self):
        self.calls = 0
        self.llm = SimpleNamespace()

    def run(self, task_id, store, artifacts, *, live=False):
        self.calls += 1
        store.set_status(task_id, TaskStatus.RESEARCH_COMPLETED)
        return []


class FakePresentationAgent:
    def __init__(self):
        self.calls = 0
        self.llm = SimpleNamespace()

    def run(self, task_id, store, artifacts, **kwargs):
        self.calls += 1
        store.set_status(task_id, TaskStatus.PRESENTATION_COMPLETED)
        return []


class FakeDailyAgent:
    def __init__(self):
        self.calls = 0
        self.llm = SimpleNamespace()

    def run(self, date, store, artifacts, *, live=False):
        self.calls += 1
        return []


class FakeBridge:
    def __init__(self, store, *, research_passed=True):
        self.store = store
        self.ledger = ValidatorLedger(store)
        self.sensitivity = "internal"
        self.public_web = False
        self.research_passed = research_passed
        self.begin_calls = 0

    def begin(self, task_id, *, contract=None):
        self.begin_calls += 1
        digest = self.ledger.bind_contract(contract)
        return SimpleNamespace(
            contract_sha256=digest,
            execution_budget=TaskExecutionBudgetState.from_bound_contract(self.store, task_id),
            model_authority=TaskModelAuthority.from_contract(contract),
        )

    def record_research_evidence(self, task_id, **kwargs):
        return self.research_passed

    def record_presentation_validation(self, task_id, **kwargs):
        return True

    def evaluate(self, task_id):
        return SimpleNamespace(verified=True)


class WorkflowStateMachineV3Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = TaskStore(root / "workspace.db")
        self.store.initialize()
        self.artifacts = ArtifactManager(root / "artifacts")
        self.research = FakeResearchAgent()
        self.presentation = FakePresentationAgent()
        self.daily = FakeDailyAgent()
        self.bridge = FakeBridge(self.store)
        self.orchestrator = SimpleNamespace(
            store=self.store,
            artifacts=self.artifacts,
            runtime_validator_bridge=self.bridge,
            research_agent=self.research,
            presentation_agent=self.presentation,
            daily_agent=self.daily,
        )
        self.controller = WorkflowStateMachineController(self.orchestrator)

    def tearDown(self):
        self.tmp.cleanup()

    def _prepare(self):
        return self.controller.prepare(branching_contract(), language="en")

    def _start(self, prepared):
        return self.controller.start(
            prepared["task_id"],
            approval_fingerprint=prepared["approval_fingerprint"],
            confirmation="AUTHORIZE",
            approver_id="admin-1",
        )

    def test_prepare_binds_24h_contract_without_execution_or_raw_state_copy(self):
        prepared = self._prepare()
        self.assertEqual(prepared["status"], "prepared")
        self.assertFalse(prepared["execution_authorized"])
        self.assertTrue(prepared["supports_pause_resume"])
        self.assertTrue(prepared["supports_deterministic_branching"])
        self.assertEqual(
            prepared["budget"]["max_wall_time_ms"],
            WORKFLOW_V3_MAX_WALL_TIME_MS,
        )
        self.assertEqual(self.research.calls, 0)
        state_path = self.controller._state_path(prepared["task_id"])
        state_text = state_path.read_text(encoding="utf-8")
        self.assertNotIn("Validated management report", state_text)
        self.assertNotIn('"contract"', state_text)
        self.assertTrue(self.controller._contract_path(prepared["task_id"]).is_file())

    def test_passed_validation_pauses_then_approve_resumes_exact_node_once(self):
        prepared = self._prepare()
        paused = self._start(prepared)
        self.assertEqual(paused["status"], "paused")
        self.assertEqual(paused["checkpoint"]["node_id"], "approve")
        self.assertEqual(self.research.calls, 1)
        self.assertEqual(self.presentation.calls, 0)
        self.assertEqual(
            self.store.get_task(prepared["task_id"]).status,
            TaskStatus.WAITING_HUMAN,
        )

        # Simulate browser/process recovery by creating a fresh controller over
        # the same durable store/artifact paths.
        recovered = WorkflowStateMachineController(self.orchestrator)
        loaded = recovered.status(prepared["task_id"])
        self.assertEqual(
            loaded["checkpoint"]["fingerprint"],
            paused["checkpoint"]["fingerprint"],
        )
        completed = recovered.decide_checkpoint(
            prepared["task_id"],
            checkpoint_fingerprint=loaded["checkpoint"]["fingerprint"],
            decision="APPROVE",
            confirmation="APPROVE",
            approver_id="manager-1",
        )
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["terminal_reason"], "verified")
        self.assertEqual(self.research.calls, 1)
        self.assertEqual(self.presentation.calls, 1)
        self.assertEqual(self.daily.calls, 1)
        self.assertEqual(self.store.get_task(prepared["task_id"]).status, TaskStatus.DONE)

        with self.assertRaisesRegex(WorkflowStateError, "not paused"):
            recovered.decide_checkpoint(
                prepared["task_id"],
                checkpoint_fingerprint=loaded["checkpoint"]["fingerprint"],
                decision="APPROVE",
                confirmation="APPROVE",
                approver_id="manager-1",
            )
        self.assertEqual(self.presentation.calls, 1)

    def test_reject_is_terminal_and_never_runs_presentation_or_daily_report(self):
        prepared = self._prepare()
        paused = self._start(prepared)
        rejected = self.controller.decide_checkpoint(
            prepared["task_id"],
            checkpoint_fingerprint=paused["checkpoint"]["fingerprint"],
            decision="REJECT",
            confirmation="REJECT",
            approver_id="manager-2",
        )
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(rejected["terminal_reason"], "approval_rejected")
        self.assertEqual(self.research.calls, 1)
        self.assertEqual(self.presentation.calls, 0)
        self.assertEqual(self.daily.calls, 0)
        self.assertEqual(
            self.store.get_task(prepared["task_id"]).status,
            TaskStatus.RESEARCH_COMPLETED,
        )

    def test_failed_validation_is_terminal_and_never_pauses(self):
        self.bridge.research_passed = False
        prepared = self._prepare()
        result = self._start(prepared)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["terminal_reason"], "validation_failed")
        self.assertIsNone(result["checkpoint"])
        self.assertEqual(self.research.calls, 1)
        self.assertEqual(self.presentation.calls, 0)
        self.assertEqual(self.store.get_task(prepared["task_id"]).status, TaskStatus.FAILED)

    def test_wrong_checkpoint_fingerprint_confirmation_and_replay_fail_closed(self):
        prepared = self._prepare()
        paused = self._start(prepared)
        with self.assertRaisesRegex(WorkflowStateError, "fingerprint"):
            self.controller.decide_checkpoint(
                prepared["task_id"],
                checkpoint_fingerprint="sha256:" + "0" * 64,
                decision="APPROVE",
                confirmation="APPROVE",
                approver_id="manager-1",
            )
        with self.assertRaisesRegex(WorkflowStateError, "explicit APPROVE"):
            self.controller.decide_checkpoint(
                prepared["task_id"],
                checkpoint_fingerprint=paused["checkpoint"]["fingerprint"],
                decision="APPROVE",
                confirmation="yes",
                approver_id="manager-1",
            )
        self.assertEqual(self.presentation.calls, 0)

    def test_arbitrary_conditions_joins_schedule_and_non_low_risk_are_rejected(self):
        payload = branching_contract()
        payload["nodes"][3]["condition"] = "manager says yes"
        with self.assertRaisesRegex(WorkflowStateError, "must use one of"):
            self.controller.prepare(payload)

        payload = branching_contract()
        payload["nodes"][7]["depends_on"] = ["presentation", "rejected"]
        with self.assertRaisesRegex(WorkflowStateError, "joins"):
            self.controller.prepare(payload)

        payload = branching_contract()
        payload["trigger"] = "schedule"
        with self.assertRaisesRegex(WorkflowStateError, "design-only"):
            self.controller.prepare(payload)

        payload = branching_contract()
        payload["risk_level"] = "medium"
        with self.assertRaisesRegex(WorkflowStateError, "low-risk"):
            self.controller.prepare(payload)

    def test_failed_and_rejected_branches_cannot_run_side_effect_nodes(self):
        payload = branching_contract()
        payload["nodes"][4].update(
            kind="agent", action="presentation", label="Unsafe failed presentation"
        )
        # Keep exactly one presentation by converting the normal presentation to output.
        payload["nodes"][5].update(kind="output", action="output", label="Approved output")
        with self.assertRaisesRegex(WorkflowStateError, "failed branch must terminate"):
            self.controller.prepare(payload)

        payload = branching_contract()
        payload["nodes"][6].update(
            kind="agent", action="daily_report", label="Unsafe rejected report"
        )
        # Keep exactly one daily_report by converting the normal daily node to output.
        payload["nodes"][7].update(kind="output", action="output", label="Approved terminal")
        with self.assertRaisesRegex(WorkflowStateError, "rejected branch must terminate"):
            self.controller.prepare(payload)

    def test_runtime_contract_compiler_drift_is_fail_closed(self):
        prepared = self._prepare()
        original = self.controller._task_contract

        def drifted(task_id):
            contract = original(task_id)
            return contract.__class__(
                **{
                    **contract.__dict__,
                    "policy_reason_codes": contract.policy_reason_codes + ("DRIFT",),
                }
            ).validate()

        self.controller._task_contract = drifted  # type: ignore[method-assign]
        with self.assertRaisesRegex(WorkflowStateError, "compiler drift"):
            self._start(prepared)
        self.assertEqual(self.research.calls, 0)

    def test_status_response_is_metadata_only(self):
        prepared = self._prepare()
        paused = self._start(prepared)
        result = self.controller.status(prepared["task_id"])
        encoded = repr(result)
        self.assertEqual(result["status"], "paused")
        self.assertEqual(
            result["checkpoint"]["fingerprint"],
            paused["checkpoint"]["fingerprint"],
        )
        self.assertNotIn(str(self.controller.root), encoded)
        self.assertNotIn("contract", encoded)
        self.assertNotIn("audience", encoded)
        self.assertNotIn("approver", encoded)


if __name__ == "__main__":
    unittest.main()
