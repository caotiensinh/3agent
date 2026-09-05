from __future__ import annotations

import unittest

from three_agent.security_monitoring.contracts import sha256_fingerprint
from three_agent.security_monitoring.forensic_evidence import CaseRecord


class SecurityForensicCaseTimeV011Tests(unittest.TestCase):
    def test_fractional_updated_at_after_whole_second_created_at_is_valid(self) -> None:
        record = CaseRecord(
            case_id="case:fractional-time",
            status="open",
            created_at="2026-09-02T14:30:00Z",
            updated_at="2026-09-02T14:30:00.500000Z",
            authorization_fingerprint=sha256_fingerprint({"authorization": "fractional-time"}),
            evidence_refs=(),
        ).validate()
        self.assertEqual(record.updated_at, "2026-09-02T14:30:00.500000Z")


if __name__ == "__main__":
    unittest.main()
