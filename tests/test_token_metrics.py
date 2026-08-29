import json
import tempfile
import unittest
from pathlib import Path

from three_agent.inference_scope import inference_scope
from three_agent.runtime_efficiency import InferenceTelemetryRecorder, build_prompt_envelope
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler
from three_agent.token_metrics import TokenPerVerifiedTaskAggregator
from three_agent.validator_ledger import ValidatorLedger


class TokenPerVerifiedTaskTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = TaskStore(root / "tasks.db")
        self.store.initialize()
        self.telemetry_path = root / "inference.jsonl"
        self.recorder = InferenceTelemetryRecorder(self.telemetry_path)
        self.ledger = ValidatorLedger(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def _bound_task(self, title):
        task = self.store.create_task(title, "Evidence-backed analysis")
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )
        self.ledger.bind_contract(contract)
        return task, contract

    def _record_tokens(self, task_id, input_tokens, output_tokens, *, scoped=True):
        envelope = build_prompt_envelope("system", "user")
        payload = {
            "prompt_eval_count": input_tokens,
            "eval_count": output_tokens,
            "response": "not persisted by telemetry",
        }
        if scoped:
            with inference_scope(task_id, agent_id="research", stage="research"):
                self.recorder.record(
                    model="qwen-test",
                    envelope=envelope,
                    structured=False,
                    schema_id=None,
                    payload=payload,
                    success=True,
                    wall_duration_ms=1.0,
                )
        else:
            self.recorder.record(
                model="qwen-test",
                envelope=envelope,
                structured=False,
                schema_id=None,
                payload=payload,
                success=True,
                wall_duration_ms=1.0,
            )

    def test_failed_work_tokens_remain_in_cost_per_verified_success(self):
        verified_task, verified_contract = self._bound_task("Verified")
        for validator in verified_contract.validators:
            self.ledger.record(
                verified_task.task_id,
                validator,
                status="passed",
                reason_code=f"{validator.upper()}_PASS",
                evidence_refs=[f"validator:{validator}:ok"],
            )

        failed_task, _ = self._bound_task("Unverified but costly")
        self.ledger.record(
            failed_task.task_id,
            "policy",
            status="passed",
            reason_code="POLICY_PASS",
            evidence_refs=["validator:policy:ok"],
        )

        self._record_tokens(verified_task.task_id, 100, 20)
        self._record_tokens(failed_task.task_id, 300, 80)

        result = TokenPerVerifiedTaskAggregator(
            self.store, self.telemetry_path
        ).snapshot([verified_task.task_id, failed_task.task_id])
        self.assertEqual(result.attempted_tasks, 2)
        self.assertEqual(result.verified_tasks, 1)
        self.assertEqual(result.attributed_input_tokens, 400)
        self.assertEqual(result.attributed_output_tokens, 100)
        self.assertEqual(result.total_tokens_per_verified_task, 500.0)

    def test_unattributed_events_are_reported_not_guessed(self):
        task, contract = self._bound_task("Verified")
        for validator in contract.validators:
            self.ledger.record(
                task.task_id,
                validator,
                status="passed",
                reason_code=f"{validator.upper()}_PASS",
                evidence_refs=[f"validator:{validator}:ok"],
            )
        self._record_tokens(task.task_id, 100, 10)
        self._record_tokens(task.task_id, 900, 90, scoped=False)

        result = TokenPerVerifiedTaskAggregator(self.store, self.telemetry_path).snapshot()
        self.assertEqual(result.attributed_total_tokens, 110)
        self.assertEqual(result.unattributed_total_tokens, 990)
        self.assertEqual(result.unattributed_events, 1)
        self.assertEqual(result.total_tokens_per_verified_task, 110.0)

    def test_unknown_task_scope_is_unattributed(self):
        task, _ = self._bound_task("Known")
        self._record_tokens("TASK-UNKNOWN-0001", 50, 5)
        result = TokenPerVerifiedTaskAggregator(self.store, self.telemetry_path).snapshot([task.task_id])
        self.assertEqual(result.attributed_events, 0)
        self.assertEqual(result.unattributed_events, 1)
        self.assertEqual(result.unattributed_total_tokens, 55)

    def test_no_verified_tasks_yields_undefined_per_verified_metric(self):
        task, _ = self._bound_task("Not verified")
        self._record_tokens(task.task_id, 100, 20)
        result = TokenPerVerifiedTaskAggregator(self.store, self.telemetry_path).snapshot()
        self.assertEqual(result.verified_tasks, 0)
        self.assertIsNone(result.input_tokens_per_verified_task)
        self.assertIsNone(result.output_tokens_per_verified_task)
        self.assertIsNone(result.total_tokens_per_verified_task)

    def test_out_of_scope_task_is_not_charged_to_filtered_snapshot(self):
        task_a, contract_a = self._bound_task("A")
        task_b, _ = self._bound_task("B")
        for validator in contract_a.validators:
            self.ledger.record(
                task_a.task_id,
                validator,
                status="passed",
                reason_code=f"{validator.upper()}_PASS",
                evidence_refs=[f"validator:{validator}:ok"],
            )
        self._record_tokens(task_a.task_id, 100, 10)
        self._record_tokens(task_b.task_id, 700, 70)
        result = TokenPerVerifiedTaskAggregator(self.store, self.telemetry_path).snapshot([task_a.task_id])
        self.assertEqual(result.attributed_total_tokens, 110)
        self.assertEqual(result.out_of_scope_events, 1)
        self.assertEqual(result.total_tokens_per_verified_task, 110.0)

    def test_malformed_and_missing_usage_are_visible(self):
        task, _ = self._bound_task("T")
        with self.telemetry_path.open("w", encoding="utf-8") as handle:
            handle.write("not-json\n")
            handle.write(json.dumps({"task_scope": {"task_id": task.task_id}, "usage": {}}) + "\n")
        result = TokenPerVerifiedTaskAggregator(self.store, self.telemetry_path).snapshot()
        self.assertEqual(result.telemetry_events, 2)
        self.assertEqual(result.malformed_events, 1)
        self.assertEqual(result.events_missing_token_usage, 1)

    def test_metric_payload_is_versioned(self):
        result = TokenPerVerifiedTaskAggregator(self.store, self.telemetry_path).snapshot([])
        payload = result.to_dict()
        self.assertEqual(payload["schema_version"], "workspace-token-per-verified-task/v1")
        self.assertIn("unattributed_events", payload)


if __name__ == "__main__":
    unittest.main()
