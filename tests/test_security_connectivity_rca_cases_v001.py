import unittest

from three_agent.security_monitoring.connectivity_rca_cases import CONNECTIVITY_RCA_CASES, validate_connectivity_rca_corpus


class ConnectivityRcaCorpusTests(unittest.TestCase):
    def test_corpus_has_representative_connectivity_cases(self):
        rows = validate_connectivity_rca_corpus()
        self.assertGreaterEqual(len(rows), 5)
        ids = {row.case_id for row in rows}
        self.assertIn("endpoint_only_down", ids)
        self.assertIn("gateway_and_downstream_down", ids)
        self.assertIn("config_drift_after_change", ids)
        self.assertIn("dns_dependency_failure", ids)
        self.assertIn("insufficient_power_evidence", ids)

    def test_data_gap_case_never_claims_root_cause(self):
        case = next(row for row in CONNECTIVITY_RCA_CASES if row.case_id == "insufficient_power_evidence")
        self.assertEqual(case.expected_status, "data_gap")
        self.assertIsNone(case.expected_root_cause)
        self.assertIn("power_failure_confirmed", case.forbidden_claims)

    def test_all_cases_require_quorum_boundary(self):
        for case in validate_connectivity_rca_corpus():
            self.assertIn("confirmed_without_quorum", case.forbidden_claims)
            self.assertGreaterEqual(len(case.required_evidence_classes), 2)


if __name__ == "__main__":
    unittest.main()
