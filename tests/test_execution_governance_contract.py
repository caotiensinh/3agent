from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "workspace.execution-governance.json"
AGENTS_PATH = ROOT / "AGENTS.md"
DOC_PATH = ROOT / "docs" / "WORKSPACE_EXECUTION_GOVERNANCE_V0_0_1.md"


class ExecutionGovernanceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        cls.agents = AGENTS_PATH.read_text(encoding="utf-8")
        cls.doc = DOC_PATH.read_text(encoding="utf-8")

    def test_policy_is_project_wide_and_actor_neutral(self) -> None:
        self.assertEqual(self.policy["scope"], "project_wide")
        self.assertEqual(set(self.policy["applies_to"]), {"human", "agent", "automation"})

    def test_parallel_execution_requires_five_to_ten_lanes(self) -> None:
        parallel = self.policy["parallel_execution"]
        self.assertTrue(parallel["non_trivial_sessions"])
        self.assertEqual(parallel["minimum_active_lanes"], 5)
        self.assertEqual(parallel["target_active_lanes"], 10)
        self.assertEqual(parallel["maximum_active_lanes"], 10)
        self.assertTrue(parallel["lanes_must_be_independent_or_dependency_isolated"])
        self.assertTrue(parallel["do_not_invent_useless_work_to_fill_lanes"])

    def test_large_or_blocked_work_must_decompose_to_atomic_units(self) -> None:
        decomposition = self.policy["decomposition"]
        self.assertTrue(decomposition["large_or_blocked_work_must_be_split"])
        self.assertIn("one_session", decomposition["target"])
        self.assertTrue(decomposition["avoid_duplicate_existing_work"])

    def test_failure_requires_strategy_change_not_identical_retry(self) -> None:
        solver = self.policy["adaptive_solver"]
        self.assertTrue(solver["retry_until_acceptance_or_irreducible_blocker"])
        self.assertTrue(solver["identical_retry_without_new_evidence_is_forbidden"])
        self.assertTrue(solver["strategy_change_required_after_repeated_failure"])
        self.assertEqual(solver["repeated_failure_threshold"], 2)
        self.assertIn("decompose", solver["allowed_strategy_changes"])
        self.assertIn("collect_new_evidence", solver["allowed_strategy_changes"])
        self.assertTrue(solver["blocker_requires_evidence"])

    def test_success_is_evidence_gated(self) -> None:
        acceptance = self.policy["acceptance"]
        self.assertTrue(acceptance["success_requires_all_mandatory_criteria_pass"])
        self.assertTrue(acceptance["mandatory_pass_requires_evidence"])
        self.assertTrue(acceptance["optional_score_cannot_mask_hard_gate_failure"])
        self.assertTrue(acceptance["model_claim_is_not_execution_evidence"])
        self.assertTrue(acceptance["false_completion_forbidden"])

    def test_progress_is_verified_work_and_reports_both_percentages(self) -> None:
        progress = self.policy["progress"]
        self.assertTrue(progress["measurement_required_every_session"])
        self.assertEqual(progress["completed_definition"], "acceptance_passed_with_evidence")
        self.assertIn("completed_weight", progress["formula"])
        self.assertEqual(progress["remaining_formula"], "100 - completion_percent")
        self.assertTrue(progress["rebaseline_when_scope_changes"])
        self.assertTrue(progress["report_completed_percent"])
        self.assertTrue(progress["report_remaining_percent"])

    def test_passed_task_or_module_requires_same_session_commit(self) -> None:
        commit = self.policy["commit_discipline"]
        self.assertTrue(commit["commit_after_passed_task_or_module_in_same_session"])
        self.assertTrue(commit["commit_only_coherent_acceptance_boundary"])
        self.assertTrue(commit["do_not_commit_known_failing_state_as_complete"])
        self.assertTrue(commit["exact_head_evidence_required_before_ready_claim"])

    def test_parallelism_cannot_escalate_authority(self) -> None:
        authority = self.policy["authority"]
        self.assertTrue(authority["inherits_existing_security_policy"])
        self.assertTrue(authority["cannot_grant_runtime_capabilities"])
        self.assertTrue(authority["task_contract_remains_authoritative"])
        self.assertTrue(authority["throughput_never_overrides_security"])

    def test_agents_root_declares_mandatory_execution_governance(self) -> None:
        required_phrases = (
            "Mandatory execution governance",
            "5-10 active lanes",
            "failure changes strategy",
            "completion_percent",
            "commit",
            "exact-head evidence",
        )
        for phrase in required_phrases:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.agents)

    def test_governance_document_contains_ten_lane_and_no_false_completion_contract(self) -> None:
        self.assertIn("Ten-lane execution model", self.doc)
        self.assertIn("L10", self.doc)
        self.assertIn("no-false-completion", self.doc.lower())
        self.assertIn("remaining_percent", self.doc)
        self.assertIn("COMMITTED", self.doc)


if __name__ == "__main__":
    unittest.main()
