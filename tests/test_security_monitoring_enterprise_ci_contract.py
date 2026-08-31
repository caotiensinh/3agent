from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class EnterpriseVerificationCIContractTests(unittest.TestCase):
    def test_harness_binds_exact_head_then_emits_bounded_ev_receipt(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("ref: ${{ github.event.pull_request.head.sha || github.sha }}", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("Enterprise verification EV-01 through EV-10", workflow)
        self.assertIn("security_enterprise_verify.py", workflow)
        self.assertIn("EXACT_SOURCE_SHA: ${{ github.event.pull_request.head.sha || github.sha }}", workflow)
        self.assertIn("actions/upload-artifact@v4", workflow)
        self.assertIn("security-enterprise-verification-py${{ matrix.python-version }}", workflow)
        self.assertIn("retention-days: 14", workflow)
        self.assertIn("timeout-minutes: 30", workflow)

    def test_verification_script_is_offline_and_does_not_claim_real_lan_evidence(self):
        script = (ROOT / "scripts/security_enterprise_verify.py").read_text(encoding="utf-8")
        self.assertIn('"EV-01"', script)
        self.assertIn('"EV-10"', script)
        self.assertNotIn("socket", script)
        self.assertNotIn("urlopen", script)
        self.assertNotIn("subprocess", script)
        self.assertNotIn("tcpdump", script)
        self.assertNotIn("192.168.", script)


if __name__ == "__main__":
    unittest.main()
