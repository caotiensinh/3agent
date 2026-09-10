import unittest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.evidence_resource_budget import EvidenceResourceBudget


class EvidenceResourceBudgetTests(unittest.TestCase):
    def test_default_budget_admits_bounded_usage(self):
        budget = EvidenceResourceBudget()
        self.assertTrue(budget.admit(evidence_items=64, total_bytes=1024 * 1024, window_seconds=3600, provenance_refs=8))

    def test_each_limit_fails_closed(self):
        budget = EvidenceResourceBudget()
        self.assertFalse(budget.admit(evidence_items=257, total_bytes=1, window_seconds=1, provenance_refs=1))
        self.assertFalse(budget.admit(evidence_items=1, total_bytes=17 * 1024 * 1024, window_seconds=1, provenance_refs=1))
        self.assertFalse(budget.admit(evidence_items=1, total_bytes=1024, window_seconds=90000, provenance_refs=1))
        self.assertFalse(budget.admit(evidence_items=1, total_bytes=1024, window_seconds=1, provenance_refs=17))

    def test_require_admitted_raises_on_overrun(self):
        with self.assertRaisesRegex(MonitoringContractError, "budget exceeded"):
            EvidenceResourceBudget().require_admitted(
                evidence_items=300, total_bytes=1024, window_seconds=60, provenance_refs=1
            )

    def test_negative_and_invalid_config_fail_closed(self):
        with self.assertRaisesRegex(MonitoringContractError, "non-negative"):
            EvidenceResourceBudget().admit(evidence_items=-1, total_bytes=0, window_seconds=0, provenance_refs=0)
        with self.assertRaisesRegex(MonitoringContractError, "max_evidence_items"):
            EvidenceResourceBudget(max_evidence_items=0).validate()


if __name__ == "__main__":
    unittest.main()
