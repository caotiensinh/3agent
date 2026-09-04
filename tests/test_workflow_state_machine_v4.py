from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

from three_agent.artifacts import ArtifactManager
from three_agent.execution_budget import TaskExecutionBudgetState
from three_agent.model_authority import TaskModelAuthority
from three_agent.models import TaskStatus
from three_agent.presentation_schemas import PRESENTATION_PLAN_SCHEMA_V1
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler
from three_agent.validator_ledger import ValidatorLedger
from three_agent.version import DISPLAY_VERSION
from three_agent.workflow_state_machine import WorkflowStateError
from three_agent.workflow_state_machine import (
    WORKFLOW_V4_MAX_PARALLEL_BRANCHES,
    WORKFLOW_V4_MAX_PARALLEL_WORKERS,
    WorkflowStateMachineV4Controller,
)


# Test synchronization bound only; production workflow timeouts are separate.
# Five seconds was too tight for a second clean-install test pass on slower
# Windows/Python 3.11 runners and could break an otherwise valid overlap proof.
PARALLEL_TEST_SYNC_TIMEOUT_SECONDS = 30


def node(node_id, label, kind, action, parents=(), condition="", approval=False):
    return {
        "id": node_id,
        "label": label,
        "kind": kind,
        "action": action,
        "depends_on": list(parents),
        "condition": condition,
        "approval_required": approval,
    }


def parallel_contract(*, approval=False):
    passed = (
        node("approve", "Manager approval", "approval", "human_approval", ("gate",), "passed", True)
        if approval
        else node("daily", "Daily report", "agent", "daily_report", ("gate",), "passed")
    )
    nodes = [
        node("start", "Start", "input", "input"),
        node("fork", "Split work", "parallel", "parallel_fork", ("start",)),
        node("research_a", "Research A", "agent", "research", ("fork",)),
        node("research_b", "Research B", "agent", "research", ("fork",)),
        node("presentation_a", "Presentation A", "agent", "presentation", ("research_a",)),
        node("presentation_b", "Presentation B", "agent", "presentation", ("research_b",)),
        node("join", "Verified join", "parallel", "parallel_join", ("presentation_a", "presentation_b")),
        node("gate", "All lanes verified?", "decision", "validate", ("join",)),
        passed,
        node("failed", "Validation failed", "output", "output", ("gate",), "failed"),
    ]
    if approval:
        nodes += [
            node("daily", "Daily report", "agent", "daily_report", ("approve",), "approved"),
            node("rejected", "Rejected", "output", "output", ("approve",), "rejected"),
        ]
    nodes.append(node("done", "Done", "output", "output", ("daily",)))
    return {
        "title": "Parallel evidence report",
        "objective": "Run two independently verified evidence lanes before downstream reporting.",
        "trigger": "manual",
        "risk_level": "low",
        "data_class": "internal",
        "nodes": nodes,
        "outputs": ["Verified result"],
        "warnings": [],
    }


class ConcurrentResearchAgent:
    def __init__(self):
        self.calls = self.active = self.max_active = 0
        self.lock = threading.Lock()
        self.barrier = threading.Barrier(2)
        self.llm = SimpleNamespace()

    def run(self, task_id, store, artifacts, *, live=False):
        with self.lock:
            self.calls += 1
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            self.barrier.wait(timeout=PARALLEL_TEST_SYNC_TIMEOUT_SECONDS)
            store.set_status(task_id, TaskStatus.RESEARCH_COMPLETED)
            return []
        finally:
            with self.lock:
                self.active -= 1


class FakePresentationAgent:
    def __init__(self):
        self.calls = 0
        self.lock = threading.Lock()
        self.llm = SimpleNamespace()

    def run(self, task_id, store, artifacts, **kwargs):
        with self.lock:
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
    def __init__(self, store):
        self.store = store
        self.ledger = ValidatorLedger(store)
        self.compiler = TaskContractCompiler()
        self.sensitivity = "internal"
        self.public_web = False
        self.fail_evidence_call = None
        self.evidence_calls = 0
        self.lock = threading.Lock()

    def begin(self, task_id, *, contract=None):
        if contract is None:
            contract = self.compiler.compile(
                task_id=task_id,
                task_type="analysis",
                sensitivity="internal",
                risk_level="low",
                public_web=False,
                output_schema=PRESENTATION_PLAN_SCHEMA_V1,
            )
        digest = self.ledger.bind_contract(contract)
        attempts = [
            int(row["attempt"])
            for row in self.store.validator_results_for_task(task_id)
            if str(row["validator"]) == "policy"
        ]
        self.ledger.record(
            task_id,
            "policy",
            status="passed",
            reason_code="POLICY_CONTRACT_VALIDATED",
            evidence_refs=(digest,),
            validator_version="test-policy/v1",
            attempt=max(attempts, default=0) + 1,
        )
        return SimpleNamespace(
            contract_sha256=digest,
            execution_budget=TaskExecutionBudgetState.from_bound_contract(self.store, task_id),
            model_authority=TaskModelAuthority.from_contract(contract),
        )

    def record_research_evidence(self, task_id, **kwargs):
        with self.lock:
            self.evidence_calls += 1
            passed = self.evidence_calls != self.fail_evidence_call
        self.ledger.record(
            task_id,
            "evidence",
            status="passed" if passed else "failed",
            reason_code="EVIDENCE_OK" if passed else "EVIDENCE_FAIL",
            validator_version="test-evidence/v1",
            attempt=1,
        )
        return passed

    def record_presentation_validation(self, task_id, **kwargs):
        self.ledger.record(
            task_id,
            "schema",
            status="passed",
            reason_code="SCHEMA_OK",
            validator_version="test-schema/v1",
            attempt=1,
        )
        return True

    def evaluate(self, task_id):
        return self.ledger.evaluate(task_id)


class WorkflowStateMachineV4Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = TaskStore(root / "workspace.db")
        self.store.initialize()
        self.artifacts = ArtifactManager(root / "artifacts")
        self.research = ConcurrentResearchAgent()
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
        self.controller = WorkflowStateMachineV4Controller(self.orchestrator)

    def tearDown(self):
        self.tmp.cleanup()

    def _prepare(self, *, approval=False):
        return self.controller.prepare(parallel_contract(approval=approval), language="en")

    def _start(self, prepared):
        return self.controller.start(
            prepared["task_id"],
            approval_fingerprint=prepared["approval_fingerprint"],
            confirmation="AUTHORIZE",
            approver_id="admin-1",
        )

    def test_prepare_exposes_new_release_and_bounded_parallel_caps_without_execution(self):
        prepared = self._prepare()
        self.assertEqual(prepared["release_version"], DISPLAY_VERSION)
        self.assertEqual(prepared["status"], "prepared")
        self.assertTrue(prepared["supports_bounded_parallel_dag"])
        self.assertTrue(prepared["parallel_region_present"])
        self.assertEqual(prepared["parallel_max_workers"], WORKFLOW_V4_MAX_PARALLEL_WORKERS)
        self.assertEqual(prepared["parallel_max_branches"], WORKFLOW_V4_MAX_PARALLEL_BRANCHES)
        self.assertEqual((self.research.calls, self.presentation.calls), (0, 0))

    def test_two_lanes_run_concurrently_in_isolated_child_tasks_and_complete(self):
        prepared = self._prepare()
        result = self._start(prepared)
        self.assertEqual((result["status"], result["terminal_reason"]), ("completed", "verified"))
        self.assertEqual(self.research.calls, 2)
        self.assertGreaterEqual(self.research.max_active, 2)
        self.assertEqual((self.presentation.calls, self.daily.calls), (2, 1))
        region = result["parallel_region"]
        self.assertEqual((region["outcome"], region["max_workers"]), ("passed", 2))
        child_ids = [item["task_id"] for item in region["branches"]]
        self.assertEqual(len(set(child_ids)), 2)
        self.assertNotIn(prepared["task_id"], child_ids)
        self.assertTrue(all(item["status"] == "verified" for item in region["branches"]))
        for task_id in child_ids:
            self.assertEqual(self.store.get_task(task_id).status, TaskStatus.DONE)

    def test_child_validation_failure_selects_terminal_failed_branch_without_daily(self):
        self.bridge.fail_evidence_call = 2
        prepared = self._prepare()
        result = self._start(prepared)
        self.assertEqual((result["status"], result["terminal_reason"]), ("blocked", "validation_failed"))
        self.assertEqual(result["parallel_region"]["outcome"], "failed")
        self.assertEqual((self.daily.calls, self.presentation.calls), (0, 1))
        self.assertEqual(self.store.get_task(prepared["task_id"]).status, TaskStatus.FAILED)

    def test_approval_after_verified_join_pauses_and_resumes_without_parallel_replay(self):
        prepared = self._prepare(approval=True)
        paused = self._start(prepared)
        self.assertEqual((paused["status"], paused["checkpoint"]["node_id"]), ("paused", "approve"))
        self.assertEqual((self.research.calls, self.presentation.calls, self.daily.calls), (2, 2, 0))
        recovered = WorkflowStateMachineV4Controller(self.orchestrator)
        loaded = recovered.status(prepared["task_id"])
        completed = recovered.decide_checkpoint(
            prepared["task_id"],
            checkpoint_fingerprint=loaded["checkpoint"]["fingerprint"],
            decision="APPROVE",
            confirmation="APPROVE",
            approver_id="manager-1",
        )
        self.assertEqual(completed["status"], "completed")
        self.assertEqual((self.research.calls, self.presentation.calls, self.daily.calls), (2, 2, 1))

    def test_rejected_post_join_approval_never_runs_daily(self):
        prepared = self._prepare(approval=True)
        paused = self._start(prepared)
        rejected = self.controller.decide_checkpoint(
            prepared["task_id"],
            checkpoint_fingerprint=paused["checkpoint"]["fingerprint"],
            decision="REJECT",
            confirmation="REJECT",
            approver_id="manager-2",
        )
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual((self.daily.calls, self.research.calls), (0, 2))

    def test_three_lanes_bad_join_schedule_and_non_low_risk_fail_admission(self):
        payload = parallel_contract()
        payload["nodes"].insert(4, node("research_c", "Research C", "agent", "research", ("fork",)))
        with self.assertRaisesRegex(WorkflowStateError, "exactly two parallel lanes"):
            self.controller.prepare(payload)

        payload = parallel_contract()
        next(item for item in payload["nodes"] if item["id"] == "join")["depends_on"] = ["presentation_a"]
        with self.assertRaisesRegex(
            WorkflowStateError,
            "parallel presentation must flow directly to the join|join must depend",
        ):
            self.controller.prepare(payload)

        payload = parallel_contract()
        payload["trigger"] = "schedule"
        with self.assertRaisesRegex(WorkflowStateError, "design-only"):
            self.controller.prepare(payload)

        payload = parallel_contract()
        payload["risk_level"] = "medium"
        with self.assertRaisesRegex(WorkflowStateError, "low-risk"):
            self.controller.prepare(payload)

    def test_interrupted_parallel_region_cannot_be_automatically_replayed(self):
        prepared = self._prepare()
        state = self.controller._load_state(prepared["task_id"])
        state["parallel_region"] = {"status": "running", "branches": []}
        self.controller._write_state(state)
        with self.assertRaisesRegex(WorkflowStateError, "automatic replay"):
            self._start(prepared)
        self.assertEqual(self.research.calls, 0)

    def test_status_is_metadata_only(self):
        prepared = self._prepare()
        result = self._start(prepared)
        encoded = repr(result)
        for forbidden in (str(self.controller.root), "approver", "audience", "contract", "prompt"):
            self.assertNotIn(forbidden, encoded)
        self.assertEqual(result["release_version"], DISPLAY_VERSION)


if __name__ == "__main__":
    unittest.main()
