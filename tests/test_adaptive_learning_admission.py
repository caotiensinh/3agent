from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from three_agent.adaptive_learning_admission import (
    DeterministicLearningAdmission,
    LearningAdmissionError,
)
from three_agent.models import TaskStatus
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler
from three_agent.validator_ledger import ValidatorLedger

H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64


class AdaptiveLearningAdmissionTests(unittest.TestCase):
    def _fixture(
        self,
        root: Path,
        *,
        final_evidence_status: str = "passed",
        include_evidence_result: bool = True,
        evidence_ref: str = H1,
        final_status: TaskStatus = TaskStatus.DONE,
    ):
        store = TaskStore(root / "tasks.db")
        store.initialize()
        task = store.create_task(
            "Sensitive network analysis",
            "raw-request-secret ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        )
        contract = TaskContractCompiler().compile(
            task_id=task.task_id,
            task_type="analysis",
            sensitivity="confidential",
            risk_level="low",
            public_web=False,
        )
        ledger = ValidatorLedger(store)
        contract_sha = ledger.bind_contract(contract)
        ledger.record(
            task.task_id,
            "policy",
            status="passed",
            reason_code="POLICY_CONTRACT_VALIDATED",
            evidence_refs=(contract_sha,),
            validator_version="runtime-policy/test",
            attempt=1,
        )
        if include_evidence_result:
            ledger.record(
                task.task_id,
                "evidence",
                status=final_evidence_status,
                reason_code=(
                    "EVIDENCE_HANDOFF_VERIFIED"
                    if final_evidence_status == "passed"
                    else "EVIDENCE_HANDOFF_INVALID"
                ),
                evidence_refs=(evidence_ref,),
                validator_version="research-evidence/test",
                attempt=1,
            )
        store.set_status(task.task_id, final_status)
        verification = ledger.evaluate(task.task_id)
        manifest = {
            "schema_version": "workflow-run/v1",
            "task_id": task.task_id,
            "status": "completed",
            "task_status": "DONE",
            "stage": "daily_report_completed",
            "business_stage": "task_completed",
            "live": False,
            "report_date": "2026-08-31",
            "options": {
                "audience": "secret-audience-value",
                "purpose": "secret-purpose-value",
                "language": "ja",
                "slide_count": 6,
                "output_format": "pptx",
            },
            "research_artifacts": ["/home/private/secret-research-artifact.json"],
            "presentation_artifacts": ["/home/private/secret-presentation-artifact.json"],
            "daily_report_artifacts": ["/home/private/secret-daily-artifact.json"],
            "verification": verification.to_dict(),
            "execution_budget": {"secret-budget-detail": "must-not-transfer"},
            "model_authority": {"secret-model-detail": "must-not-transfer"},
            "error": None,
            "started_at": "2026-08-31T07:00:00+09:00",
            "completed_at": "2026-08-31T07:05:00+09:00",
        }
        path = root / "workflow.json"
        self._write(path, manifest)
        return store, ledger, task, contract, path, manifest

    @staticmethod
    def _write(path: Path, payload: dict) -> None:
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_verified_done_workflow_is_admitted_idempotently(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, task, contract, path, _ = self._fixture(root)
            gate = DeterministicLearningAdmission(store)
            first = gate.admit(task.task_id, path)
            second = gate.admit(task.task_id, path)

            self.assertEqual(first, second)
            self.assertEqual(first.admission_id, second.admission_id)
            self.assertEqual(first.outcome, "verified_success")
            self.assertEqual(first.sensitivity, contract.sensitivity)
            self.assertEqual(first.required_validators, ("policy", "evidence"))
            self.assertEqual(first.capability_grants, ())
            self.assertEqual(first.evidence_hashes, (H1,))

    def test_non_done_states_cannot_become_verified_success(self):
        for status, reason in (
            (TaskStatus.FAILED, "LEARNING_SOURCE_FAILED"),
            (TaskStatus.WAITING_HUMAN, "LEARNING_SOURCE_WAITING_HUMAN"),
            (TaskStatus.PRESENTATION_COMPLETED, "LEARNING_SOURCE_NOT_DONE"),
        ):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                store, _, task, _, path, _ = self._fixture(root, final_status=status)
                with self.assertRaisesRegex(LearningAdmissionError, reason):
                    DeterministicLearningAdmission(store).admit(task.task_id, path)

    def test_missing_or_failed_required_validator_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, task, _, path, _ = self._fixture(
                root, include_evidence_result=False
            )
            with self.assertRaisesRegex(
                LearningAdmissionError, "LEARNING_REQUIRED_VALIDATOR_MISSING"
            ):
                DeterministicLearningAdmission(store).admit(task.task_id, path)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, task, _, path, _ = self._fixture(
                root, final_evidence_status="failed"
            )
            with self.assertRaisesRegex(
                LearningAdmissionError, "LEARNING_REQUIRED_VALIDATOR_FAILED"
            ):
                DeterministicLearningAdmission(store).admit(task.task_id, path)

    def test_evidence_validator_must_use_content_addressed_refs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, task, _, path, _ = self._fixture(
                root,
                evidence_ref="artifact:local",
            )
            with self.assertRaisesRegex(
                LearningAdmissionError, "LEARNING_EVIDENCE_NOT_CONTENT_ADDRESSED"
            ):
                DeterministicLearningAdmission(store).admit(task.task_id, path)

    def test_bound_contract_digest_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, task, _, path, _ = self._fixture(root)
            with store.connect() as conn:
                conn.execute(
                    "UPDATE task_contracts SET contract_sha256=? WHERE task_id=?",
                    (H2, task.task_id),
                )
            with self.assertRaisesRegex(
                LearningAdmissionError, "LEARNING_CONTRACT_DIGEST_MISMATCH"
            ):
                DeterministicLearningAdmission(store).admit(task.task_id, path)

    def test_manifest_task_or_verification_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, task, _, path, manifest = self._fixture(root)
            tampered = dict(manifest)
            tampered["task_id"] = "TASK-TAMPERED"
            self._write(path, tampered)
            with self.assertRaisesRegex(
                LearningAdmissionError, "LEARNING_MANIFEST_TASK_MISMATCH"
            ):
                DeterministicLearningAdmission(store).admit(task.task_id, path)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, task, _, path, manifest = self._fixture(root)
            tampered = json.loads(json.dumps(manifest))
            tampered["verification"]["verified"] = False
            self._write(path, tampered)
            with self.assertRaisesRegex(
                LearningAdmissionError, "LEARNING_MANIFEST_VERIFICATION_MISMATCH"
            ):
                DeterministicLearningAdmission(store).admit(task.task_id, path)

    def test_manifest_rejects_injected_raw_request_field_and_invalid_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, task, _, path, manifest = self._fixture(root)
            tampered = dict(manifest)
            tampered["raw_request"] = "secret should never enter learning envelope"
            self._write(path, tampered)
            with self.assertRaisesRegex(
                LearningAdmissionError, "LEARNING_MANIFEST_SCHEMA_INVALID"
            ):
                DeterministicLearningAdmission(store).admit(task.task_id, path)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, task, _, path, manifest = self._fixture(root)
            tampered = dict(manifest)
            tampered["completed_at"] = "secret-not-a-timestamp"
            self._write(path, tampered)
            with self.assertRaisesRegex(
                LearningAdmissionError, "LEARNING_MANIFEST_TIME_INVALID"
            ):
                DeterministicLearningAdmission(store).admit(task.task_id, path)

    def test_sensitivity_cannot_be_downgraded_or_duplicate_source_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, task, _, path, _ = self._fixture(root)
            gate = DeterministicLearningAdmission(store)
            with self.assertRaisesRegex(
                LearningAdmissionError, "LEARNING_SENSITIVITY_DOWNGRADE_DENIED"
            ):
                gate.admit(task.task_id, path, requested_sensitivity="internal")

            baseline = gate.admit(task.task_id, path)
            upgraded = gate.admit(
                task.task_id, path, requested_sensitivity="restricted"
            )
            self.assertEqual(baseline.sensitivity, "confidential")
            self.assertEqual(upgraded.sensitivity, "restricted")
            self.assertEqual(baseline.admission_id, upgraded.admission_id)
            self.assertNotEqual(
                baseline.provenance_sha256,
                upgraded.provenance_sha256,
            )
            self.assertEqual(baseline.evidence_hashes, upgraded.evidence_hashes)
            self.assertEqual(
                baseline.validator_provenance_sha256,
                upgraded.validator_provenance_sha256,
            )

    def test_envelope_contains_hashes_not_raw_request_paths_or_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _, task, _, path, _ = self._fixture(root)
            payload = DeterministicLearningAdmission(store).admit(
                task.task_id, path
            ).to_payload()
            rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True)

            for forbidden in (
                "raw-request-secret",
                "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                "secret-research-artifact",
                "secret-presentation-artifact",
                "secret-daily-artifact",
                "secret-audience-value",
                "secret-purpose-value",
                "secret-budget-detail",
                "secret-model-detail",
            ):
                self.assertNotIn(forbidden, rendered)

            for authority_field in (
                "allowed_tools",
                "write_scope",
                "network_scope",
                "model_policy",
                "model_authority",
                "execution_budget",
                "started_at",
                "completed_at",
            ):
                self.assertNotIn(authority_field, payload)
            self.assertEqual(payload["capability_grants"], [])

    def test_non_authority_manifest_change_does_not_duplicate_trusted_experience(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, ledger, task, _, path, manifest = self._fixture(root)
            gate = DeterministicLearningAdmission(store)
            original = gate.admit(task.task_id, path)

            changed_manifest = json.loads(json.dumps(manifest))
            changed_manifest["options"]["language"] = "vi"
            self._write(path, changed_manifest)
            changed = gate.admit(task.task_id, path)
            self.assertNotEqual(original.manifest_sha256, changed.manifest_sha256)
            self.assertEqual(original.provenance_sha256, changed.provenance_sha256)
            self.assertEqual(original.admission_id, changed.admission_id)

            ledger.record(
                task.task_id,
                "policy",
                status="passed",
                reason_code="POLICY_RECHECK_VALIDATED",
                evidence_refs=(original.contract_sha256,),
                validator_version="runtime-policy/recheck",
                attempt=2,
            )
            with self.assertRaisesRegex(
                LearningAdmissionError, "LEARNING_MANIFEST_VERIFICATION_MISMATCH"
            ):
                gate.admit(task.task_id, path)

            changed_manifest["verification"] = ledger.evaluate(task.task_id).to_dict()
            self._write(path, changed_manifest)
            reevaluated = gate.admit(task.task_id, path)
            self.assertNotEqual(
                original.validator_provenance_sha256,
                reevaluated.validator_provenance_sha256,
            )
            self.assertNotEqual(original.admission_id, reevaluated.admission_id)


if __name__ == "__main__":
    unittest.main()
