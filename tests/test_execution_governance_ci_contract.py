from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
GUIDE_PATH = ROOT / "docs" / "WORKSPACE_EXECUTION_GOVERNANCE_V0_0_1.md"


class ExecutionGovernanceCIContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ci = CI_PATH.read_text(encoding="utf-8")
        cls.guide = GUIDE_PATH.read_text(encoding="utf-8")

    def test_governance_gate_remains_blocking(self) -> None:
        start = self.ci.index("- name: Execution governance canonical gate")
        end = self.ci.index("- name: Upload execution governance evidence", start)
        gate = self.ci[start:end]
        self.assertIn("python scripts/validate_execution_governance.py", gate)
        self.assertIn('exit "$rc"', gate)
        self.assertNotIn("continue-on-error", gate)

    def test_governance_ci_emits_machine_readable_evidence(self) -> None:
        self.assertIn("execution-governance.json", self.ci)
        self.assertIn("execution-governance.log", self.ci)
        self.assertIn("Upload execution governance evidence", self.ci)
        self.assertIn("head_sha", self.ci)
        self.assertIn("rule_id", self.ci)
        self.assertIn("exit_code", self.ci)

    def test_required_failure_classifications_are_explicit(self) -> None:
        for classification in (
            "POLICY_INVALID",
            "CONFIG_ERROR",
            "VALIDATOR_ERROR",
            "TEST_FAILURE",
            "DUPLICATE_FAILURE",
            "INFRA_FAILURE",
        ):
            with self.subTest(classification=classification):
                self.assertIn(classification, self.ci)
                self.assertIn(classification, self.guide)

    def test_hosting_enforcement_boundary_is_not_overclaimed(self) -> None:
        self.assertIn("branch protection", self.guide)
        self.assertIn("repository ruleset", self.guide)
        self.assertIn("must not claim that GitHub merge enforcement is complete", self.guide)


if __name__ == "__main__":
    unittest.main()
