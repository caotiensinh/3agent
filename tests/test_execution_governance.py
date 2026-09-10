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
        "acceptance_criteria": [{"id": f"AC-{index:02d}", "statement": "observable condition", "required": True, "status": "PASS" if passed else "FAIL", "verifier": "python -m unittest", "evidence": evidence(f"ac-{index}")}],
        "verification_checks": [{"id": f"VC-{index:02d}", "status": "PASS" if passed else "FAIL", "evidence": evidence(f"vc-{index}")}],
        "evidence": evidence(f"lane-{index}"),
        "attempts": [{"attempt_id": f"attempt-{index}-1", "strategy_family": "deterministic_verification", "outcome": "PASS" if passed else "FAIL", "verification_evidence": evidence(f"attempt-{index}"), **({"failure_signature": f"failure-{index}", "failed_check": f"VC-{index:02d}", "log_state": "AVAILABLE", "log_evidence": evidence(f"log-{index}"), "diagnosis": f"diagnosis-{index}", "next_action_reason": f"next-action-{index}"} if not passed else {})}],
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
        "effectiveness": {"goal_coverage_percent": 100, "verified_completion_percent": 100, "evidence_coverage_percent": 100, "first_pass_yield_percent": 100, "rework_ratio": 0, "failed_required_lanes": 0, "blocked_required_lanes": 0, "canonical_drift_count": 0, "new_parallel_implementation_count": 0, "stale_reference_count": 0, "transient_lane_artifact_count": 0},
        "start_completion_percent": 60,
        "completion_percent": 100,
        "remaining_percent": 0,
        "progress_delta_percent": 40,
        "session_progress_summary": ["verified governance acceptance increased from 60% to 100%"],
        "blockers": [],
        "commits": ["c" * 40] if repository_mutation else [],
    }
    if repository_mutation:
        data["canonical_reconciliation_evidence"] = {"canonical_drift_count": 0, "new_parallel_implementation_count": 0, "stale_reference_count": 0, "transient_lane_artifact_count": 0}
    return data


def failed_attempt(attempt_id: str, strategy: str = "targeted_test", *, log_state: str = "AVAILABLE"):
    data = {"attempt_id": attempt_id, "strategy_family": strategy, "outcome": "FAIL", "verification_evidence": evidence(f"verify-{attempt_id}"), "failure_signature": f"failure-{attempt_id}", "failed_check": "VC-01", "log_state": log_state, "diagnosis": f"diagnosis-{attempt_id}", "next_action_reason": f"next-{attempt_id}"}
    if log_state == "AVAILABLE":
        data["log_evidence"] = evidence(f"log-{attempt_id}")
    else:
        data["instrumentation_target"] = "src/three_agent/runtime.py:decision-boundary"
        data["instrumentation_plan"] = "add bounded diagnostic fields around failed branch"
        data["instrumentation_safety"] = "redact secrets; temporary debug fields only"
    return data


def pass_attempt(attempt_id: str, strategy: str, prior: str | None = None):
    data = {"attempt_id": attempt_id, "strategy_family": strategy, "outcome": "PASS", "verification_evidence": evidence(f"verify-{attempt_id}")}
    if prior is not None:
        data["prior_failure_diagnosis_ref"] = prior
    return data


class ExecutionGovernanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = json.loads((ROOT / "config" / "workspace.execution-governance.json").read_text(encoding="utf-8"))

    def test_policy_is_machine_valid(self):
        validator.validate_policy(self.policy, repo_root=ROOT)

    def test_policy_is_repository_wide_and_non_exemptible(self):
        self.assertTrue(self.policy["repository_default"]["mandatory_for_all_repository_work"])
        self.assertTrue(self.policy["repository_default"]["no_actor_self_exemption"])
        validator.validate_policy(self.policy, repo_root=ROOT)

    def test_twenty_lane_verified_pass_is_accepted(self):
        validator.validate_receipt(self.policy, receipt(20))

    def test_nineteen_lanes_without_dependency_evidence_is_rejected(self):
        with self.assertRaisesRegex(validator.GovernanceError, "below 20 lanes requires dependency_limit evidence"):
            validator.validate_receipt(self.policy, receipt(19))

    def test_nineteen_lanes_with_dependency_evidence_is_accepted(self):
        data = receipt(19)
        data["dependency_limit"] = {"evidence": ["dependency graph proves only nineteen safe independent authorities"]}
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

    def test_failed_attempt_requires_failure_contract(self):
        data = receipt()
        first = data["lanes"][0]
        first["attempts"] = [{"attempt_id": "failed-attempt", "strategy_family": "targeted_test", "outcome": "FAIL", "verification_evidence": ["targeted test failed"]}, pass_attempt("recovery-attempt", "root_cause_fix", "failed-attempt")]
        with self.assertRaisesRegex(validator.GovernanceError, "missing failure fields"):
            validator.validate_receipt(self.policy, data)

    def test_available_logs_must_be_read_and_recorded(self):
        data = receipt()
        first = data["lanes"][0]
        failed = failed_attempt("failed-attempt")
        failed.pop("log_evidence")
        first["attempts"] = [failed, pass_attempt("recovery-attempt", "root_cause_fix", "failed-attempt")]
        with self.assertRaisesRegex(validator.GovernanceError, "lacks log_evidence"):
            validator.validate_receipt(self.policy, data)

    def test_missing_logs_require_instrumentation_plan(self):
        data = receipt()
        first = data["lanes"][0]
        failed = failed_attempt("failed-attempt", log_state="MISSING")
        failed.pop("instrumentation_target")
        first["attempts"] = [failed, pass_attempt("recovery-attempt", "targeted_instrumentation", "failed-attempt")]
        first["attempts"][1]["instrumentation_evidence"] = ["instrumented exact boundary"]
        first["attempts"][1]["captured_log_evidence"] = ["new diagnostic log"]
        with self.assertRaisesRegex(validator.GovernanceError, "lacks instrumentation_target"):
            validator.validate_receipt(self.policy, data)

    def test_missing_logs_force_targeted_instrumentation_next(self):
        data = receipt()
        first = data["lanes"][0]
        first["attempts"] = [failed_attempt("failed-attempt", log_state="MISSING"), pass_attempt("recovery-attempt", "root_cause_fix", "failed-attempt")]
        first["attempts"][1]["instrumentation_evidence"] = ["instrumented exact boundary"]
        first["attempts"][1]["captured_log_evidence"] = ["new diagnostic log"]
        with self.assertRaisesRegex(validator.GovernanceError, "must use targeted_instrumentation"):
            validator.validate_receipt(self.policy, data)

    def test_instrumented_recovery_must_capture_and_read_logs(self):
        data = receipt()
        first = data["lanes"][0]
        first["attempts"] = [failed_attempt("failed-attempt", log_state="MISSING"), pass_attempt("recovery-attempt", "targeted_instrumentation", "failed-attempt")]
        first["attempts"][1]["instrumentation_evidence"] = ["instrumented exact boundary"]
        with self.assertRaisesRegex(validator.GovernanceError, "lacks captured_log_evidence"):
            validator.validate_receipt(self.policy, data)

    def test_failed_instrumented_rerun_requires_logic_and_syntax_analysis(self):
        data = receipt()
        first = data["lanes"][0]
        instrumented_fail = failed_attempt("instrumented-attempt", "targeted_instrumentation", log_state="AVAILABLE")
        instrumented_fail["prior_failure_diagnosis_ref"] = "failed-attempt"
        instrumented_fail["instrumentation_evidence"] = ["instrumented exact boundary"]
        instrumented_fail["captured_log_evidence"] = ["new diagnostic log"]
        first["attempts"] = [failed_attempt("failed-attempt", log_state="MISSING"), instrumented_fail, pass_attempt("recovery-attempt", "logic_trace", "instrumented-attempt")]
        with self.assertRaisesRegex(validator.GovernanceError, "lacks logic_analysis_evidence"):
            validator.validate_receipt(self.policy, data)

    def test_failed_instrumented_rerun_with_logic_and_syntax_can_recover(self):
        data = receipt()
        first = data["lanes"][0]
        instrumented_fail = failed_attempt("instrumented-attempt", "targeted_instrumentation", log_state="AVAILABLE")
        instrumented_fail.update({"prior_failure_diagnosis_ref": "failed-attempt", "instrumentation_evidence": ["instrumented exact boundary"], "captured_log_evidence": ["new diagnostic log"], "logic_analysis_evidence": ["traced input -> branch -> state -> output"], "syntax_analysis_evidence": ["parser/static check PASS; expression precedence reviewed"]})
        first["attempts"] = [failed_attempt("failed-attempt", log_state="MISSING"), instrumented_fail, pass_attempt("recovery-attempt", "logic_trace", "instrumented-attempt")]
        validator.validate_receipt(self.policy, data)

    def test_rerun_after_failure_requires_prior_diagnosis_reference(self):
        data = receipt()
        first = data["lanes"][0]
        first["attempts"] = [failed_attempt("failed-attempt"), pass_attempt("recovery-attempt", "root_cause_fix")]
        with self.assertRaisesRegex(validator.GovernanceError, "must reference prior failed attempt diagnosis"):
            validator.validate_receipt(self.policy, data)

    def test_same_strategy_rerun_requires_justification(self):
        data = receipt()
        first = data["lanes"][0]
        first["attempts"] = [failed_attempt("failed-attempt", "targeted_test"), pass_attempt("recovery-attempt", "targeted_test", "failed-attempt")]
        with self.assertRaisesRegex(validator.GovernanceError, "rerun_justification"):
            validator.validate_receipt(self.policy, data)

    def test_strategy_must_change_after_repeated_failure_threshold(self):
        data = receipt()
        first = data["lanes"][0]
        second = failed_attempt("failed-2", "targeted_test")
        second["prior_failure_diagnosis_ref"] = "failed-1"
        second["rerun_justification"] = "fixture change produced new evidence"
        third = pass_attempt("attempt-3", "targeted_test", "failed-2")
        third["rerun_justification"] = "try same strategy again"
        first["attempts"] = [failed_attempt("failed-1", "targeted_test"), second, third]
        with self.assertRaisesRegex(validator.GovernanceError, "must change strategy after 2 consecutive failures"):
            validator.validate_receipt(self.policy, data)

    def test_failure_with_diagnosis_can_recover_using_new_strategy(self):
        data = receipt()
        first = data["lanes"][0]
        first["attempts"] = [failed_attempt("failed-attempt"), pass_attempt("recovery-attempt", "root_cause_fix", "failed-attempt")]
        validator.validate_receipt(self.policy, data)

    def test_progress_delta_is_machine_checked(self):
        data = receipt()
        data["progress_delta_percent"] = 39
        with self.assertRaisesRegex(validator.GovernanceError, "progress delta must equal"):
            validator.validate_receipt(self.policy, data)

    def test_session_progress_summary_is_required(self):
        data = receipt()
        data["session_progress_summary"] = []
        with self.assertRaisesRegex(validator.GovernanceError, "session_progress_summary"):
            validator.validate_receipt(self.policy, data)

    def test_negative_progress_requires_rebaseline_evidence(self):
        data = receipt()
        data["start_completion_percent"] = 80
        data["completion_percent"] = 70
        data["remaining_percent"] = 30
        data["progress_delta_percent"] = -10
        data["outcome"] = "BLOCKED_EXTERNAL"
        data["blockers"] = [{"external": True, "evidence": ["upstream unavailable"], "owner": "external provider", "next_action": "retry after provider recovery"}]
        data["lanes"][0]["status"] = "BLOCKED_EXTERNAL"
        with self.assertRaisesRegex(validator.GovernanceError, "negative progress delta requires"):
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
