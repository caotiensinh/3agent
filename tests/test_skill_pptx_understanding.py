from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skill_candidates" / "pptx-understanding" / "SKILL.md"
APPROVED_SKILL = ROOT / "skills" / "pptx-understanding" / "SKILL.md"
EXPECTED_SHA256 = "b3a92d98d997446b3958b05d84fe6d1c31deed9f9e7739aa6e942580ec90329b"


class PptxUnderstandingSkillTest(unittest.TestCase):
    def test_candidate_integrity_size_and_quarantine(self) -> None:
        raw = SKILL.read_bytes()
        text = raw.decode("utf-8")
        self.assertFalse(APPROVED_SKILL.exists())
        self.assertLessEqual(len(raw), 3072)
        self.assertIn("name: pptx-understanding", text)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), EXPECTED_SHA256)

    def test_candidate_preserves_slide_coverage(self) -> None:
        text = SKILL.read_text(encoding="utf-8")
        for required in (
            "Require `file-pptx-safety` and `document-full-ingestion`",
            "Inventory every slide",
            "Never execute macros, OLE objects, embedded packages",
            "hidden slides",
            "keep OCR/inference separate from visible facts",
            "partial/rejected coverage",
        ):
            self.assertIn(required, text)

    def test_candidate_grants_no_runtime_or_egress(self) -> None:
        text = SKILL.read_text(encoding="utf-8").lower()
        for forbidden in ("curl ", "wget ", "pip install", "npm install", "subprocess", "os.system", "http://", "https://"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
