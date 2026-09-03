from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skill_candidates" / "archive-zip-understanding" / "SKILL.md"
APPROVED_SKILL = ROOT / "skills" / "archive-zip-understanding" / "SKILL.md"
EXPECTED_SHA256 = "760be52466ac00fd1d2de399e29ad25e2d2e468ab923e2ebb7a9832c5e1effd3"


class ArchiveZipUnderstandingSkillTest(unittest.TestCase):
    def test_candidate_integrity_size_and_quarantine(self) -> None:
        raw = SKILL.read_bytes()
        text = raw.decode("utf-8")
        self.assertFalse(APPROVED_SKILL.exists())
        self.assertLessEqual(len(raw), 3072)
        self.assertIn("name: archive-zip-understanding", text)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), EXPECTED_SHA256)

    def test_candidate_fails_closed_on_archive_hazards(self) -> None:
        text = SKILL.read_text(encoding="utf-8")
        for required in (
            "inventory members before extraction",
            "Reject absolute paths, parent traversal",
            "compression ratio, nesting depth",
            "Never execute binaries, scripts, macros",
            "stricter remaining budgets",
            "member-level coverage ledger",
        ):
            self.assertIn(required, text)

    def test_candidate_grants_no_runtime_or_egress(self) -> None:
        text = SKILL.read_text(encoding="utf-8").lower()
        for forbidden in ("curl ", "wget ", "pip install", "npm install", "subprocess", "os.system", "http://", "https://"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
