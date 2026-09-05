from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/portable-deploy-ci.yml"


class SecurityMonitoringPortableCIContractTests(unittest.TestCase):
    def test_security_monitoring_changes_trigger_portable_deploy_for_push_and_pr(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        required_paths = (
            "src/three_agent/security_monitoring/**",
            "src/three_agent/security_*.py",
            "tests/test_security_monitoring*.py",
            "docs/knowledge/NETWORK_SECURITY_INTELLIGENCE*.md",
            "config/security*.json",
        )
        for path in required_paths:
            self.assertEqual(
                text.count(f"- '{path}'"),
                2,
                msg=f"portable-deploy-ci must cover {path} for both push and pull_request",
            )

    def test_portable_gate_keeps_exact_lineage_and_idempotent_redeploy(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("EXPECTED_HEAD: ${{ github.event.pull_request.head.sha || github.sha }}", text)
        self.assertIn('git -C "${{ runner.temp }}/three-agent-install" rev-parse HEAD', text)
        self.assertIn("Re-run bootstrap idempotently and preserve config", text)
        self.assertIn('test "$before" = "$after"', text)


if __name__ == "__main__":
    unittest.main()
