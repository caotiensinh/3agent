from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skill_candidates" / "xlsx-understanding" / "SKILL.md"
APPROVED_SKILL = ROOT / "skills" / "xlsx-understanding" / "SKILL.md"
EXPECTED_SHA256 = "c4944f8b44cbdba5f15298640855d53c630b4eab77c03f9b8d3fc81d1628a2d5"


class XlsxUnderstandingSkillTest(unittest.TestCase):
    def test_candidate_integrity_size_and_quarantine(self) -> None:
        raw = SKILL.read_bytes()
        text = raw.decode("utf-8")
        self.assertFalse(APPROVED_SKILL.exists())
        self.assertLessEqual(len(raw), 3072)
        self.assertIn("name: xlsx-understanding", text)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), EXPECTED_SHA256)

    def test_candidate_preserves_workbook_provenance(self) -> None:
        text = SKILL.read_text(encoding="utf-8")
        for required in (
            "Require `file-xlsx-safety` and `document-full-ingestion`",
            "visible, hidden, and very-hidden sheets",
            "Never execute VBA, Office Scripts, add-ins, DDE",
            "cached value",
            "preserve sheet and cell references",
            "sheet-by-sheet coverage ledger",
        ):
            self.assertIn(required, text)

    def test_candidate_grants_no_runtime_or_egress(self) -> None:
        text = SKILL.read_text(encoding="utf-8").lower()
        for forbidden in ("curl ", "wget ", "pip install", "npm install", "subprocess", "os.system", "http://", "https://"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
