from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "docx-understanding" / "SKILL.md"
EXPECTED_SHA256 = "00d93ecbf991283cee6c7b03223227db2c655509a7a8fbf89b2c0bc36b78fa81"


class DocxUnderstandingSkillTest(unittest.TestCase):
    def test_candidate_integrity_and_size(self) -> None:
        raw = SKILL.read_bytes()
        text = raw.decode("utf-8")
        self.assertLessEqual(len(raw), 3072)
        self.assertIn("name: docx-understanding", text)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), EXPECTED_SHA256)

    def test_candidate_keeps_ooxml_inert_and_traceable(self) -> None:
        text = SKILL.read_text(encoding="utf-8")
        for required in (
            "Require `file-docx-safety` and `document-full-ingestion`",
            "untrusted ZIP/XML",
            "never execute macros, OLE objects, scripts",
            "never dereference external URLs or network templates",
            "rather than claiming completeness",
            "trace claims back to the source",
        ):
            self.assertIn(required, text)

    def test_candidate_grants_no_runtime_or_egress(self) -> None:
        text = SKILL.read_text(encoding="utf-8").lower()
        for forbidden in ("curl ", "wget ", "pip install", "npm install", "subprocess", "os.system", "http://", "https://"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
