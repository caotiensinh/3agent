from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_execution_governance.py"
SPEC = importlib.util.spec_from_file_location("execution_governance_validator", SCRIPT)
validator = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(validator)


def evidence(label: str):
    return [f"test:{label}"]


def lane(index: int, status: str = "VERIFIED_PASS"):
    passed = status == "VERIFIED_PASS"
    return {
        "lane_id": f"L{index:02d}",
        "goal": f"goal-{index}",
        "required": True,
        "dependencies": [],
        "write_set": [f"src/three_agent/test_authority_{index}.py"],
        "functional_authority": f"test.authority.{index}",
        "acceptance_criteria": [{
            "id": f"AC-{index:02d}",
            "statement": "observable condition",
            "required": True,
            "status": "PASS" if passed else "FAIL",
            "verifier": "python -m unittest",
            "evidence": evidence(f"ac-{index}"),
        }],
        "verification_checks": [{
            "id": f"VC-{index:02d}",
            "status": "PASS" if passed else "FAIL",
            "evidence": evidence(f"vc-{index}"),
        }],
        "evidence": evidence(f"lane-{index}"),
        "attempts": [{
            "attempt_id": f"attempt-{index}-1",
            "strategy_family": "deterministic_verification",
            "outcome": "PASS" if passed else "FAIL",
            "verification_evidence": evidence(f"attempt-{index}"),
            **({
                "failure_signature": f"failure-{index}",
                "failed_check": f"VC-{index:02d}",
                "log_evidence": evidence(f"log-{index}"),
                "diagnosis": f"diagnosis-{index}",
                "next_action_reason": f"next-action-{index}",
            } if not passed else {}),
        }],
        "status": status,
    }


def receipt(count: int = 20, repository_mutation: bool = False):
    data = {
        "session_id": "S-001",
        "goal": "prove governance",
        "substantial": True,
        "repository_mutation": repository_mutation,
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "outcome": "VERIFIED_PASS",
        "lanes": [lane(i) for i in range(1, count + 1)],
        "effectiveness": {
            "goal_coverage_percent": 100,
            "verified_completion_percent": 100,
            "evidence_coverage_percent": 100,
            "first_pass_yield_percent": 100,
            "rework_ratio": 0,
            "failed_required_lanes": 0,
            "blocked_required_lanes": 0,
            "canonical_drift_count": 0,
            "new_parallel_implementation_count": 0,
            "stale_reference_count": 0,
            "transient_lane_artifact_count": 0,
        },
        "completion_percent": 100,
        "remaining_percent": 0,
        "blockers": [],
        "commits": ["c" * 40] if repository_mutation else [],
    }
    if repository_mutation:
        data["canonical_reconciliation_evidence"] = {
            "canonical_drift_count": 0,
            "new_parallel_implementation_count": 0,
            "stale_reference_count": 0,
            "transient_lane_artifact_count": 0,
        }
    return data


class ExecutionGovernanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = json.loads((ROOT / "config" / "workspace.execution-governance.json").read_text(encoding="utf-8"))

    def test_policy_is_machine_valid(self):
        validator.validate_policy(self.policy, repo_root=ROOT)

    def test_twenty_lane_verified_pass_is_accepted(self):
        validator.validate_receipt(self.policy, receipt(20))

    def test_nineteen_lanes_without_dependency_evidence_is_rejected(self):
        with self.assertRaisesRegex(validator.GovernanceError, "below 20 lanes requires dependency_limit evidence"):
            validator.validate_receipt(self.policy, receipt(19))

    def test_nineteen_lanes_with_dependency_evidence_is_accepted(self):
        data = receipt(19)
        data["dependency_limit"] = {
            "evidence": ["dependency graph proves only nineteen safe independent authorities"]
        }
        validator.validate_receipt(self.policy, data)

    def test_twenty_one_lanes_is_rejected(self):
        with self.assertRaises(validator.GovernanceError):
            validator.validate_receipt(self.policy, receipt(21))

    def test_duplicate_functional_authority_is_rejected(self):
        data = receipt()
        data["lanes"][1]["functional_authority"] = data["lanes"][0]["functional_authority"]
        with self.assertRaisesRegex(validator.GovernanceError, "functional authority"):
            validator.validate_receipt(self.policy, data)

    def test_overlapping_write_set_is_rejected(self):
        data = receipt()
        data["lanes"][1]["write_set"] = [data["lanes"][0]["write_set"][0]]
        with self.assertRaisesRegex(validator.GovernanceError, "write-set overlap"):
            validator.validate_receipt(self.policy, data)

    def test_false_pass_without_evidence_is_rejected(self):
        data = receipt()
        data["lanes"][0]["acceptance_criteria"][0]["evidence"] = []
        with self.assertRaises(validator.GovernanceError):
            validator.validate_receipt(self.policy, data)

    def test_failed_attempt_requires_log_and_diagnosis_evidence(self):
        data = receipt()
        first = data["lanes"][0]
        first["attempts"] = [{
            "attempt_id": "failed-attempt",
            "strategy_family": "targeted_test",
            "outcome": "FAIL",
            "verification_evidence": ["targeted test failed"],
        }, {
            "attempt_id": "recovery-attempt",
            "strategy_family": "root_cause_fix",
            "outcome": "PASS",
            "verification_evidence": ["targeted test passed"],
            "prior_failure_diagnosis_ref": "failed-attempt",
        }]
        with self.assertRaisesRegex(validator.GovernanceError, "missing failure fields"):
            validator.validate_receipt(self.policy, data)

    def test_rerun_after_failure_requires_prior_diagnosis_reference(self):
        data = receipt()
        first = data["lanes"][0]
        first["attempts"] = [{
            "attempt_id": "failed-attempt",
            "strategy_family": "targeted_test",
            "outcome": "FAIL",
            "verification_evidence": ["targeted test failed"],
            "failure_signature": "AssertionError:test_guard",
            "failed_check": "VC-01",
            "log_evidence": ["traceback inspected"],
            "diagnosis": "fixture violates canonical contract",
            "next_action_reason": "correct fixture then rerun",
        }, {
            "attempt_id": "recovery-attempt",
            "strategy_family": "root_cause_fix",
            "outcome": "PASS",
            "verification_evidence": ["targeted test passed"],
        }]
        with self.assertRaisesRegex(validator.GovernanceError, "must reference prior failed attempt diagnosis"):
            validator.validate_receipt(self.policy, data)

    def test_same_strategy_rerun_requires_justification(self):
        data = receipt()
        first = data["lanes"][0]
        first["attempts"] = [{
            "attempt_id": "failed-attempt",
            "strategy_family": "targeted_test",
            "outcome": "FAIL",
            "verification_evidence": ["targeted test failed"],
            "failure_signature": "Timeout:test_guard",
            "failed_check": "VC-01",
            "log_evidence": ["timeout log inspected"],
            "diagnosis": "fixture was not initialized",
            "next_action_reason": "initialize fixture then rerun",
        }, {
            "attempt_id": "recovery-attempt",
            "strategy_family": "targeted_test",
            "outcome": "PASS",
            "verification_evidence": ["targeted test passed"],
            "prior_failure_diagnosis_ref": "failed-attempt",
        }]
        with self.assertRaisesRegex(validator.GovernanceError, "rerun_justification"):
            validator.validate_receipt(self.policy, data)

    def test_failure_with_diagnosis_can_recover_using_new_strategy(self):
        data = receipt()
        first = data["lanes"][0]
        first["attempts"] = [{
            "attempt_id": "failed-attempt",
            "strategy_family": "targeted_test",
            "outcome": "FAIL",
            "verification_evidence": ["targeted test failed"],
            "failure_signature": "AssertionError:test_guard",
            "failed_check": "VC-01",
            "log_evidence": ["traceback inspected"],
            "diagnosis": "fixture violates canonical contract",
            "next_action_reason": "correct fixture using canonical schema",
        }, {
            "attempt_id": "recovery-attempt",
            "strategy_family": "root_cause_fix",
            "outcome": "PASS",
            "verification_evidence": ["targeted test passed"],
            "prior_failure_diagnosis_ref": "failed-attempt",
        }]
        validator.validate_receipt(self.policy, data)

    def test_repository_mutation_requires_canonical_reconciliation_evidence(self):
        data = receipt(repository_mutation=True)
        del data["canonical_reconciliation_evidence"]
        with self.assertRaisesRegex(validator.GovernanceError, "canonical_reconciliation_evidence"):
            validator.validate_receipt(self.policy, data)

    def test_retryable_failure_prevents_stop(self):
        data = receipt()
        data["lanes"][0] = lane(1, "FAILED_RETRYABLE")
        with self.assertRaises(validator.GovernanceError):
            validator.validate_receipt(self.policy, data)

    def test_duplicate_canonical_policy_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "config"
            config.mkdir()
            canonical = config / "workspace.execution-governance.json"
            canonical.write_text(json.dumps(self.policy), encoding="utf-8")
            (config / "workspace.execution-governance-copy.json").write_text(json.dumps(self.policy), encoding="utf-8")
            with self.assertRaises(validator.GovernanceError):
                validator.validate_policy(self.policy, repo_root=root)


if __name__ == "__main__":
    unittest.main()
