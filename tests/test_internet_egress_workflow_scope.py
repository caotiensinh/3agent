from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "internet-egress-security-ci.yml"

EXPECTED_TRIGGER_PATHS = (
    "src/three_agent/**",
    "config/test.example.json",
    "config/local.public-research.example.json",
    "scripts/migrate_default_web_search_config.py",
    "scripts/bootstrap.sh",
    "scripts/bootstrap.ps1",
    "scripts/update_workspace_ubuntu.sh",
    "tests/test_default_web_search_policy.py",
    "tests/test_internet_gateway_no_bypass.py",
    "tests/test_internet_gateway_ssrf.py",
    "tests/test_internet_egress_workflow_scope.py",
    ".github/workflows/internet-egress-security-ci.yml",
)

EXPECTED_TEST_COMMANDS = (
    "python -m unittest tests.test_internet_gateway_no_bypass -v",
    "python -m unittest tests.test_internet_gateway_ssrf -v",
    "python -m unittest tests.test_default_web_search_policy -v",
    "python -m unittest tests.test_internet_egress_workflow_scope -v",
)


class InternetEgressWorkflowScopeTests(unittest.TestCase):
    def test_security_relevant_paths_trigger_on_push_and_pull_request(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for path in EXPECTED_TRIGGER_PATHS:
            marker = f'- "{path}"'
            self.assertGreaterEqual(
                workflow.count(marker),
                2,
                msg=f"Internet egress security workflow must trigger on push and pull_request for {path}",
            )

    def test_dedicated_gate_runs_all_security_regressions(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for command in EXPECTED_TEST_COMMANDS:
            self.assertIn(command, workflow)

    def test_security_gate_is_not_soft_failed(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("continue-on-error: true", workflow)


if __name__ == "__main__":
    unittest.main()
