from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "workspace.execution-governance.json"
AGENTS_PATH = ROOT / "AGENTS.md"
DOC_PATH = ROOT / "docs" / "WORKSPACE_EXECUTION_GOVERNANCE_V0_0_1.md"
COMPOSITE_DOC_PATH = ROOT / "docs" / "WORKSPACE_COMPOSITE_STRATEGY_POLICY_V0_0_1.md"


class ExecutionGovernanceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        cls.agents = AGENTS_PATH.read_text(encoding="utf-8")
        cls.doc = DOC_PATH.read_text(encoding="utf-8")
        cls.composite_doc = COMPOSITE_DOC_PATH.read_text(encoding="utf-8")

    def test_policy_is_project_wide_and_covers_all_execution_actors(self) -> None:
        self.assertEqual(self.policy["scope"], "project_wide")
        self.assertEqual(
            set(self.policy["applies_to"]),
            {"human", "agent", "sub_agent", "automation", "ci_worker"},
        )

    def test_parallel_execution_uses_twenty_lane_canonical_contract(self) -> None:
        parallel = self.policy["parallel_execution"]
        self.assertTrue(parallel["required_for_substantial_sessions"])
        self.assertEqual(parallel["preferred_active_lanes_min"], 20)
        self.assertEqual(parallel["target_active_lanes"], 20)
        self.assertEqual(parallel["maximum_active_lanes"], 20)
        self.assertTrue(parallel["lanes_must_be_independent_or_dependency_isolated"])
        self.assertTrue(parallel["shared_write_set_requires_single_owner"])
        self.assertTrue(parallel["overlapping_lane_write_sets_forbidden"])
        self.assertTrue(parallel["duplicate_functional_authority_across_lanes_forbidden"])
        self.assertTrue(parallel["canonical_target_requires_single_writer_lane"])
        self.assertTrue(parallel["do_not_invent_useless_work_to_fill_lanes"])

    def test_lane_contract_requires_authority_attempts_and_evidence(self) -> None:
        lane_contract = self.policy["lane_contract"]
        required = set(lane_contract["required_fields"])
        self.assertTrue(
            {
                "lane_id",
                "goal",
                "dependencies",
                "write_set",
                "functional_authority",
                "acceptance_criteria",
                "verification_checks",
                "evidence",
                "attempts",
                "status",
            }.issubset(required)
        )
        self.assertEqual(set(lane_contract["attempt_outcomes"]), {"PASS", "FAIL"})
        self.assertTrue(lane_contract["later_attempt_after_fail_requires_prior_failure_diagnosis_ref"])

    def test_failure_handling_is_failure_first_and_forbids_blind_retry(self) -> None:
        failure = self.policy["failure_handling"]
        self.assertTrue(failure["failed_verification_requires_log_inspection_before_edit_or_rerun"])
        self.assertEqual(
            failure["required_sequence"],
            [
                "capture_failure",
                "read_failed_logs",
                "identify_failure_signature",
                "classify_root_cause",
                "record_diagnosis",
                "choose_justified_next_action",
                "edit_if_justified",
                "rerun_targeted_verifier",
            ],
        )
        self.assertTrue(failure["blind_rerun_forbidden"])
        self.assertTrue(failure["edit_before_failure_evidence_review_forbidden"])
        self.assertTrue(failure["same_attempt_rerun_without_new_evidence_forbidden"])
        self.assertTrue(failure["rerun_same_strategy_requires_explicit_justification"])

    def test_adaptive_solver_changes_strategy_and_requires_real_blockers(self) -> None:
        solver = self.policy["adaptive_solver"]
        self.assertTrue(solver["retry_until_acceptance_or_proven_unsuccessful_terminal_state"])
        self.assertTrue(solver["identical_retry_without_new_evidence_is_forbidden"])
        self.assertTrue(solver["strategy_change_required_after_repeated_failure"])
        self.assertEqual(solver["repeated_failure_threshold"], 2)
        self.assertGreaterEqual(solver["minimum_distinct_strategy_families_before_hard_failed"], 3)
        self.assertIn("decompose", solver["allowed_strategy_changes"])
        self.assertIn("collect_new_evidence", solver["allowed_strategy_changes"])
        self.assertTrue(solver["blocker_requires_external_dependency"])
        self.assertTrue(solver["blocker_requires_evidence"])

    def test_success_is_execution_and_evidence_gated(self) -> None:
        acceptance = self.policy["acceptance"]
        self.assertTrue(acceptance["success_requires_all_mandatory_criteria_pass"])
        self.assertTrue(acceptance["mandatory_pass_requires_executed_verifier"])
        self.assertTrue(acceptance["mandatory_pass_requires_evidence"])
        self.assertTrue(acceptance["verification_checks_must_pass"])
        self.assertTrue(acceptance["optional_score_cannot_mask_hard_gate_failure"])
        self.assertTrue(acceptance["model_claim_is_not_execution_evidence"])
        self.assertTrue(acceptance["false_completion_forbidden"])
        self.assertEqual(acceptance["success_state"], "VERIFIED_PASS")

    def test_state_machine_does_not_allow_retryable_failure_to_stop(self) -> None:
        state = self.policy["state_machine"]
        self.assertEqual(state["successful_terminal_state"], "VERIFIED_PASS")
        self.assertIn("FAILED_RETRYABLE", state["non_terminal_states"])
        self.assertEqual(
            set(state["unsuccessful_terminal_states"]),
            {"BLOCKED_EXTERNAL", "HARD_FAILED", "ABORTED_BY_OPERATOR"},
        )
        self.assertTrue(state["failed_retryable_must_reenter_solver_loop"])
        self.assertTrue(state["normal_stop_requires_verified_pass"])

    def test_canonical_implementation_forbids_new_version_siblings(self) -> None:
        canonical = self.policy["canonical_implementation"]
        self.assertTrue(canonical["single_functional_authority_required"])
        self.assertTrue(canonical["new_version_sibling_files_forbidden"])
        self.assertTrue(canonical["canonical_merge_required_before_main"])
        self.assertTrue(canonical["transient_lane_artifacts_must_be_removed_before_main"])
        self.assertTrue(canonical["production_entrypoints_must_reference_canonical_files"])
        self.assertEqual(canonical["explicit_compatibility_exceptions"], [])

    def test_progress_is_verified_work_and_reports_both_percentages(self) -> None:
        progress = self.policy["progress"]
        self.assertTrue(progress["measurement_required_every_session"])
        self.assertEqual(
            progress["completed_definition"],
            "mandatory_acceptance_passed_with_executed_verifier_and_evidence",
        )
        self.assertIn("passed_verified_acceptance_weight", progress["formula"])
        self.assertEqual(progress["remaining_formula"], "100 - completion_percent")
        self.assertTrue(progress["rebaseline_when_required_scope_changes"])
        self.assertTrue(progress["silent_denominator_change_forbidden"])
        self.assertTrue(progress["report_completed_percent"])
        self.assertTrue(progress["report_remaining_percent"])

    def test_passed_task_or_module_requires_same_session_commit(self) -> None:
        commit = self.policy["commit_discipline"]
        self.assertTrue(commit["commit_after_passed_task_or_module_in_same_session"])
        self.assertTrue(commit["commit_only_coherent_acceptance_boundary"])
        self.assertTrue(commit["do_not_commit_known_failing_state_as_complete"])
        self.assertTrue(commit["repository_mutation_session_requires_commit_for_verified_pass"])
        self.assertTrue(commit["exact_head_evidence_required_before_ready_claim"])

    def test_parallelism_cannot_escalate_authority(self) -> None:
        authority = self.policy["authority"]
        self.assertTrue(authority["inherits_existing_security_policy"])
        self.assertTrue(authority["cannot_grant_runtime_capabilities"])
        self.assertTrue(authority["task_contract_remains_authoritative"])
        self.assertTrue(authority["throughput_never_overrides_security"])

    def test_agents_root_references_canonical_governance_without_redefining_lane_limits(self) -> None:
        self.assertIn("Mandatory execution governance", self.agents)
        self.assertIn("config/workspace.execution-governance.json", self.agents)
        self.assertIn("parallel-lane window defined by the canonical policy", self.agents)
        self.assertIn("retryable failure MUST return to diagnose/decompose/replan/execute/verify", self.agents)
        self.assertIn("exact-head evidence", self.agents)
        self.assertNotIn("5-10 active lanes", self.agents)

    def test_governance_guide_is_non_normative_and_does_not_redefine_lane_numbers(self) -> None:
        self.assertIn("Canonical machine policy", self.doc)
        self.assertIn("config/workspace.execution-governance.json", self.doc)
        self.assertIn("VERIFIED_PASS", self.doc)
        self.assertIn("FAILED_RETRYABLE", self.doc)
        self.assertIn("use the lane window and limits from the canonical JSON", self.doc)
        self.assertNotIn("10–20 independent or dependency-isolated lanes", self.doc)
        self.assertNotIn("typical 10-lane", self.doc.lower())

    def test_composite_strategy_document_contains_required_portfolio_contract(self) -> None:
        self.assertIn("Composite Strategy Policy", self.composite_doc)
        self.assertIn("DIRECT_DISCOVERY", self.composite_doc)
        self.assertIn("HISTORY_ARCHAEOLOGY", self.composite_doc)
        self.assertIn("PROTOCOL_FIRST", self.composite_doc)
        self.assertIn("LOCAL_EXACT_HEAD_INSPECTION", self.composite_doc)
        self.assertIn("evidence convergence", self.composite_doc)
        self.assertIn("BLOCKED", self.composite_doc)


if __name__ == "__main__":
    unittest.main()
