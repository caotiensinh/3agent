from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "pdf-understanding" / "SKILL.md"
EXPECTED_SHA256 = "599a745891477d19accb42fc2b3c8667746175692cd897e0f03a7d897a54abde"


class PdfUnderstandingSkillTest(unittest.TestCase):
    def test_candidate_integrity_and_size(self) -> None:
        raw = SKILL.read_bytes()
        text = raw.decode("utf-8")
        self.assertLessEqual(len(raw), 3072)
        self.assertIn("name: pdf-understanding", text)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), EXPECTED_SHA256)

    def test_candidate_requires_traceable_page_coverage(self) -> None:
        text = SKILL.read_text(encoding="utf-8")
        for required in (
            "Require `file-pdf-safety` and `document-full-ingestion`",
            "Inventory every page",
            "label OCR-derived text explicitly",
            "never activate or fetch them",
            "rather than silently skipping them",
            "Never claim the PDF is fully understood",
        ):
            self.assertIn(required, text)

    def test_candidate_grants_no_runtime_or_egress(self) -> None:
        text = SKILL.read_text(encoding="utf-8").lower()
        for forbidden in ("curl ", "wget ", "pip install", "npm install", "subprocess", "os.system", "http://", "https://"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
