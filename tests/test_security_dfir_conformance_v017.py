from __future__ import annotations

import unittest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.dfir_conformance import (
    DFIR_CONFORMANCE_CASES,
    conformance_fingerprint,
    run_dfir_conformance,
)


class SecurityDFIRConformanceV017Tests(unittest.TestCase):
    def test_fixed_corpus_passes_expected_accept_reject_contracts(self) -> None:
        results = run_dfir_conformance()
        self.assertEqual(tuple(row.case_id for row in results), DFIR_CONFORMANCE_CASES)
        self.assertTrue(all(row.passed for row in results))
        self.assertEqual(results[0].actual, "accept")
        self.assertTrue(all(row.actual == "reject" for row in results[1:]))
        self.assertTrue(conformance_fingerprint(results).startswith("sha256:"))

    def test_corpus_is_deterministic(self) -> None:
        first = run_dfir_conformance()
        second = run_dfir_conformance()
        self.assertEqual(tuple(row.public_dict() for row in first), tuple(row.public_dict() for row in second))
        self.assertEqual(conformance_fingerprint(first), conformance_fingerprint(second))

    def test_unknown_or_duplicate_cases_fail_closed(self) -> None:
        with self.assertRaisesRegex(MonitoringContractError, "CASE_SET_INVALID"):
            run_dfir_conformance(("UNKNOWN",))
        with self.assertRaisesRegex(MonitoringContractError, "CASE_SET_INVALID"):
            run_dfir_conformance(("C1_VALID_EVIDENCE", "C1_VALID_EVIDENCE"))

    def test_rejection_reasons_cover_tamper_scope_permission_and_chain(self) -> None:
        by_id = {row.case_id: row for row in run_dfir_conformance()}
        self.assertIn("content_sha256", by_id["C2_TAMPERED_CONTENT_HASH"].reason_code)
        self.assertEqual(by_id["T1_EVIDENCE_SCOPE_ESCAPE"].reason_code, "EVIDENCE_TYPE_OUTSIDE_CASE_SCOPE")
        self.assertIn("cannot grant network", by_id["P1_PERMISSION_ESCALATION"].reason_code)
        self.assertIn("hash chain is broken", by_id["B1_BROKEN_CUSTODY_CHAIN"].reason_code)


if __name__ == "__main__":
    unittest.main()
