import tempfile
import unittest
from pathlib import Path

from three_agent.inference_scope import inference_scope
from three_agent.resource_events import ResourceEventRecorder
from three_agent.resource_metrics import ResourcePerVerifiedTaskAggregator
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler
from three_agent.validator_ledger import ValidatorLedger


class ResourcePerVerifiedTaskTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = TaskStore(root / "tasks.db")
        self.store.initialize()
        self.path = root / "resource.jsonl"
        self.recorder = ResourceEventRecorder(self.path)
        self.ledger = ValidatorLedger(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def _task(self, title, *, verify=False):
        task = self.store.create_task(title, "Evidence-backed analysis")
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )
        self.ledger.bind_contract(contract)
        if verify:
            for validator in contract.validators:
                self.ledger.record(
                    task.task_id,
                    validator,
                    status="passed",
                    reason_code=f"{validator.upper()}_PASS",
                    evidence_refs=[f"validator:{validator}:ok"],
                )
        return task

    def test_failed_task_resource_spend_stays_in_numerator(self):
        good = self._task("verified", verify=True)
        bad = self._task("unverified", verify=False)
        for task_id in (good.task_id, bad.task_id):
            self.recorder.record(
                "tool_call",
                task_id=task_id,
                actor_id="research",
                action="internet_get",
                reason_code="TOOL_CALL_ATTEMPT",
            )
        with inference_scope(bad.task_id, agent_id="research", stage="research"):
            self.recorder.record(
                "model_retry",
                task_id=None,
                actor_id="model_router",
                action="primary_to_deep",
                reason_code="LOCAL_LLM_ERROR",
                model="small",
                target="deep",
            )
            self.recorder.record(
                "model_escalation",
                task_id=None,
                actor_id="model_router",
                action="primary_to_deep",
                reason_code="PRIMARY_MODEL_FAILED",
                model="small",
                target="deep",
            )

        result = ResourcePerVerifiedTaskAggregator(self.store, self.path).snapshot()
        self.assertEqual(result.attempted_tasks, 2)
        self.assertEqual(result.verified_tasks, 1)
        self.assertEqual(result.tool_calls, 2)
        self.assertEqual(result.model_retries, 1)
        self.assertEqual(result.model_escalations, 1)
        self.assertEqual(result.tool_calls_per_verified_task, 2.0)
        self.assertEqual(result.model_retries_per_verified_task, 1.0)
        self.assertEqual(result.model_escalations_per_verified_task, 1.0)

    def test_unattributed_and_out_of_scope_events_are_not_guessed(self):
        a = self._task("A", verify=True)
        b = self._task("B", verify=False)
        self.recorder.record(
            "tool_call",
            task_id=a.task_id,
            actor_id="research",
            action="internet_get",
            reason_code="TOOL_CALL_ATTEMPT",
        )
        self.recorder.record(
            "tool_call",
            task_id=b.task_id,
            actor_id="research",
            action="internet_get",
            reason_code="TOOL_CALL_ATTEMPT",
        )
        self.recorder.record(
            "tool_call",
            task_id=None,
            actor_id="system",
            action="internet_get",
            reason_code="TOOL_CALL_ATTEMPT",
        )
        result = ResourcePerVerifiedTaskAggregator(self.store, self.path).snapshot([a.task_id])
        self.assertEqual(result.tool_calls, 1)
        self.assertEqual(result.out_of_scope_events, 1)
        self.assertEqual(result.unattributed_events, 1)

    def test_zero_verified_tasks_returns_undefined_ratios(self):
        task = self._task("not verified")
        self.recorder.record(
            "tool_call",
            task_id=task.task_id,
            actor_id="research",
            action="internet_get",
            reason_code="TOOL_CALL_ATTEMPT",
        )
        result = ResourcePerVerifiedTaskAggregator(self.store, self.path).snapshot()
        self.assertIsNone(result.tool_calls_per_verified_task)
        self.assertIsNone(result.model_retries_per_verified_task)
        self.assertIsNone(result.model_escalations_per_verified_task)

    def test_malformed_resource_event_is_visible(self):
        with self.path.open("w", encoding="utf-8") as handle:
            handle.write("not-json\n")
            handle.write('{"event_type":"unknown","task_id":"TASK-X"}\n')
        result = ResourcePerVerifiedTaskAggregator(self.store, self.path).snapshot([])
        self.assertEqual(result.telemetry_events, 2)
        self.assertEqual(result.malformed_events, 2)

    def test_metric_payload_is_versioned(self):
        payload = ResourcePerVerifiedTaskAggregator(self.store, self.path).snapshot([]).to_dict()
        self.assertEqual(payload["schema_version"], "workspace-resource-per-verified-task/v1")
        self.assertIn("model_escalations_per_verified_task", payload)


if __name__ == "__main__":
    unittest.main()
