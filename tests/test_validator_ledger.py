import tempfile
import unittest
from pathlib import Path

from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler
from three_agent.validator_ledger import ValidatorLedger, ValidatorLedgerError


class ValidatorLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TaskStore(Path(self.tmp.name) / "tasks.db")
        self.store.initialize()
        self.ledger = ValidatorLedger(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def _task_and_contract(self):
        task = self.store.create_task("Verify metrics", "Validate evidence-backed work")
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )
        return task, contract

    def test_contract_binding_is_immutable_and_idempotent(self):
        task, contract = self._task_and_contract()
        first = self.ledger.bind_contract(contract)
        second = self.ledger.bind_contract(contract)
        self.assertEqual(first, second)
        record = self.store.task_contract_record(task.task_id)
        self.assertEqual(record["contract_sha256"], first)

        changed = contract.to_dict()
        changed["validators"] = ["policy"]
        with self.assertRaisesRegex(ValueError, "immutable"):
            self.store.bind_task_contract(task.task_id, changed)

    def test_missing_or_failed_required_validator_prevents_verified_success(self):
        task, contract = self._task_and_contract()
        self.ledger.bind_contract(contract)
        state = self.ledger.evaluate(task.task_id)
        self.assertFalse(state.verified)
        self.assertIn("policy", state.missing_validators)
        self.assertIn("evidence", state.missing_validators)

        self.ledger.record(
            task.task_id,
            "policy",
            status="passed",
            reason_code="POLICY_PASS",
            evidence_refs=["policy:workspace-task-contract/v1"],
        )
        self.ledger.record(
            task.task_id,
            "evidence",
            status="failed",
            reason_code="EVIDENCE_GAP",
            evidence_refs=["artifact:research/TASK.json"],
        )
        state = self.ledger.evaluate(task.task_id)
        self.assertFalse(state.verified)
        self.assertEqual(state.failed_validators, ("evidence",))

    def test_retry_can_verify_final_result_without_rewriting_first_pass(self):
        task, contract = self._task_and_contract()
        self.ledger.bind_contract(contract)
        self.ledger.record(
            task.task_id,
            "policy",
            status="passed",
            reason_code="POLICY_PASS",
            evidence_refs=["policy:contract"],
            attempt=1,
        )
        self.ledger.record(
            task.task_id,
            "evidence",
            status="failed",
            reason_code="EVIDENCE_GAP",
            evidence_refs=["artifact:research/v1"],
            attempt=1,
        )
        self.ledger.record(
            task.task_id,
            "evidence",
            status="passed",
            reason_code="EVIDENCE_PASS",
            evidence_refs=["artifact:research/v2"],
            attempt=2,
        )
        state = self.ledger.evaluate(task.task_id)
        self.assertTrue(state.verified)
        self.assertFalse(state.first_pass_verified)
        self.assertEqual(set(state.passed_validators), {"policy", "evidence"})

    def test_all_required_validators_pass_on_first_attempt(self):
        task, contract = self._task_and_contract()
        self.ledger.bind_contract(contract)
        for validator in contract.validators:
            self.ledger.record(
                task.task_id,
                validator,
                status="passed",
                reason_code=f"{validator.upper()}_PASS",
                evidence_refs=[f"validator:{validator}:e1"],
                attempt=1,
            )
        state = self.ledger.evaluate(task.task_id)
        self.assertTrue(state.verified)
        self.assertTrue(state.first_pass_verified)

    def test_unbound_task_is_never_verified_and_cannot_accept_results(self):
        task = self.store.create_task("No contract", "No verification contract")
        state = self.ledger.evaluate(task.task_id)
        self.assertFalse(state.contract_bound)
        self.assertFalse(state.verified)
        with self.assertRaisesRegex(ValidatorLedgerError, "TASK_CONTRACT_NOT_BOUND"):
            self.ledger.record(
                task.task_id,
                "policy",
                status="passed",
                reason_code="POLICY_PASS",
            )

    def test_unknown_validator_and_raw_content_refs_fail_closed(self):
        task, contract = self._task_and_contract()
        self.ledger.bind_contract(contract)
        with self.assertRaisesRegex(ValidatorLedgerError, "UNKNOWN_VALIDATOR"):
            self.ledger.record(
                task.task_id,
                "model_says_ok",
                status="passed",
                reason_code="MODEL_PASS",
            )
        with self.assertRaisesRegex(ValidatorLedgerError, "compact identifiers"):
            self.ledger.record(
                task.task_id,
                "policy",
                status="passed",
                reason_code="POLICY_PASS",
                evidence_refs=["secret password=should-not-be-stored"],
            )

    def test_export_contains_metadata_only(self):
        task, contract = self._task_and_contract()
        self.ledger.bind_contract(contract)
        self.ledger.record(
            task.task_id,
            "policy",
            status="passed",
            reason_code="POLICY_PASS",
            evidence_refs=["sha256:abc123"],
            validator_version="policy-v2",
        )
        exported = self.ledger.export_results(task.task_id)
        self.assertEqual(len(exported), 1)
        self.assertEqual(exported[0]["validator"], "policy")
        self.assertEqual(exported[0]["evidence_refs"], ["sha256:abc123"])
        self.assertNotIn("raw_content", exported[0])
        self.assertNotIn("details", exported[0])


if __name__ == "__main__":
    unittest.main()
