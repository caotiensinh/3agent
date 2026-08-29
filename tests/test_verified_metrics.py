import tempfile
import unittest
from pathlib import Path

from three_agent.models import TaskStatus
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler
from three_agent.validator_ledger import ValidatorLedger
from three_agent.verified_metrics import VerifiedWorkMetricAggregator


class VerifiedWorkMetricTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TaskStore(Path(self.tmp.name) / "tasks.db")
        self.store.initialize()
        self.ledger = ValidatorLedger(self.store)
        self.metrics = VerifiedWorkMetricAggregator(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def _bound_analysis_task(self, title):
        task = self.store.create_task(title, "Evidence-backed analysis")
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )
        self.ledger.bind_contract(contract)
        return task, contract

    def _pass(self, task_id, validator, attempt=1):
        self.ledger.record(
            task_id,
            validator,
            status="passed",
            reason_code=f"{validator.upper()}_PASS",
            evidence_refs=[f"validator:{validator}:e{attempt}"],
            attempt=attempt,
        )

    def test_verified_rates_use_attempted_tasks_as_denominator(self):
        first, first_contract = self._bound_analysis_task("First pass")
        for validator in first_contract.validators:
            self._pass(first.task_id, validator)

        retry, _ = self._bound_analysis_task("Retry success")
        self._pass(retry.task_id, "policy")
        self.ledger.record(
            retry.task_id,
            "evidence",
            status="failed",
            reason_code="EVIDENCE_GAP",
            evidence_refs=["artifact:research:v1"],
            attempt=1,
        )
        self._pass(retry.task_id, "evidence", attempt=2)

        unbound = self.store.create_task("Looks done", "But has no contract")
        self.store.set_status(unbound.task_id, TaskStatus.DONE)

        snapshot = self.metrics.snapshot()
        self.assertEqual(snapshot.attempted_tasks, 3)
        self.assertEqual(snapshot.contract_bound_tasks, 2)
        self.assertEqual(snapshot.unbound_tasks, 1)
        self.assertEqual(snapshot.verified_tasks, 2)
        self.assertEqual(snapshot.first_pass_verified_tasks, 1)
        self.assertEqual(snapshot.verified_task_success_rate, 0.666667)
        self.assertEqual(snapshot.first_pass_verified_success_rate, 0.333333)

    def test_done_status_never_substitutes_for_validator_evidence(self):
        task = self.store.create_task("Status-only", "No contract and no validators")
        self.store.set_status(task.task_id, TaskStatus.DONE)
        snapshot = self.metrics.snapshot([task.task_id])
        self.assertEqual(snapshot.attempted_tasks, 1)
        self.assertEqual(snapshot.unbound_tasks, 1)
        self.assertEqual(snapshot.verified_tasks, 0)
        self.assertEqual(snapshot.verified_task_success_rate, 0.0)

    def test_missing_and_failed_validator_counts_are_latest-state_only(self):
        missing, _ = self._bound_analysis_task("Missing evidence")
        self._pass(missing.task_id, "policy")

        failed, _ = self._bound_analysis_task("Failed evidence")
        self._pass(failed.task_id, "policy")
        self.ledger.record(
            failed.task_id,
            "evidence",
            status="failed",
            reason_code="EVIDENCE_GAP",
            evidence_refs=["artifact:research:failed"],
        )

        snapshot = self.metrics.snapshot([missing.task_id, failed.task_id])
        self.assertEqual(snapshot.missing_validator_counts, {"evidence": 1})
        self.assertEqual(snapshot.failed_validator_counts, {"evidence": 1})
        self.assertEqual(snapshot.verified_tasks, 0)

    def test_empty_snapshot_is_zero_not_nan(self):
        snapshot = self.metrics.snapshot([])
        self.assertEqual(snapshot.attempted_tasks, 0)
        self.assertEqual(snapshot.verified_task_success_rate, 0.0)
        self.assertEqual(snapshot.first_pass_verified_success_rate, 0.0)

    def test_serialized_metric_contract_is_versioned(self):
        payload = self.metrics.snapshot([]).to_dict()
        self.assertEqual(payload["schema_version"], "workspace-verified-work-metrics/v1")
        self.assertIn("unbound_tasks", payload)
        self.assertIn("missing_validator_counts", payload)


if __name__ == "__main__":
    unittest.main()
