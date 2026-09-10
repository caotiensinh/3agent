from __future__ import annotations

import hashlib
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skill_candidates" / "document-full-ingestion" / "SKILL.md"
APPROVED_SKILL = ROOT / "skills" / "document-full-ingestion" / "SKILL.md"
EXPECTED_SHA256 = "d348999cdbb42d7c51bffc98f421ad7cef2bbe8fb903d1aa6dedebfd23426d66"


class DocumentFullIngestionSkillTest(unittest.TestCase):
    def test_candidate_is_quarantined_small_named_and_integrity_pinned(self) -> None:
        raw = SKILL.read_bytes()
        text = raw.decode("utf-8")
        self.assertFalse(APPROVED_SKILL.exists())
        self.assertLessEqual(len(raw), 3072)
        self.assertIn("name: document-full-ingestion", text)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), EXPECTED_SHA256)

    def test_candidate_has_fail_closed_coverage_contract(self) -> None:
        text = SKILL.read_text(encoding="utf-8")
        for required in (
            "coverage ledger",
            "`complete`, `partial`, or `rejected`",
            "Stop safely rather than silently truncating",
            "Never execute macros, scripts, embedded binaries",
            "Do not claim “read all”, “complete”, or equivalent",
            "Keep confidential content local",
        ):
            self.assertIn(required, text)

    def test_candidate_does_not_grant_runtime_or_egress_capabilities(self) -> None:
        text = SKILL.read_text(encoding="utf-8").lower()
        for forbidden in (
            "curl ",
            "wget ",
            "pip install",
            "npm install",
            "subprocess",
            "os.system",
            "http://",
            "https://",
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
