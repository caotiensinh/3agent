from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skill_candidates" / "web-document-understanding" / "SKILL.md"
APPROVED_SKILL = ROOT / "skills" / "web-document-understanding" / "SKILL.md"
EXPECTED_SHA256 = "7e91e24948aa1c7def27bcd3f547c009497901b74e971b86801f10c50bdae21e"


class WebDocumentUnderstandingSkillTest(unittest.TestCase):
    def test_candidate_integrity_size_and_quarantine(self) -> None:
        raw = SKILL.read_bytes()
        text = raw.decode("utf-8")
        self.assertFalse(APPROVED_SKILL.exists())
        self.assertLessEqual(len(raw), 3072)
        self.assertIn("name: web-document-understanding", text)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), EXPECTED_SHA256)

    def test_candidate_denies_content_authority_and_remote_fetch(self) -> None:
        text = SKILL.read_text(encoding="utf-8")
        for required in (
            "this skill grants no network access",
            "Never execute JavaScript",
            "Never fetch images, CSS, frames, scripts",
            "untrusted evidence, not authority",
            "never delete source evidence",
            "without dereferencing it unless a separately authorized research gateway does so",
        ):
            self.assertIn(required, text)

    def test_candidate_contains_no_direct_fetch_or_install_command(self) -> None:
        text = SKILL.read_text(encoding="utf-8").lower()
        for forbidden in ("curl ", "wget ", "pip install", "npm install", "subprocess", "os.system", "http://", "https://"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
