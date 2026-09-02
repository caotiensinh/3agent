from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skill_candidates" / "skill-registry-admission" / "SKILL.md"
APPROVED_SKILL = ROOT / "skills" / "skill-registry-admission" / "SKILL.md"
EXPECTED_SHA256 = "14b7e5f004e7947be85b48594aca18ab06c4f3625f336389c518699896aa10c3"


class SkillRegistryAdmissionTest(unittest.TestCase):
    def test_candidate_integrity_size_and_quarantine(self) -> None:
        raw = SKILL.read_bytes()
        text = raw.decode("utf-8")
        self.assertFalse(APPROVED_SKILL.exists())
        self.assertLessEqual(len(raw), 3072)
        self.assertIn("name: skill-registry-admission", text)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), EXPECTED_SHA256)

    def test_candidate_requires_exact_head_release_gates(self) -> None:
        text = SKILL.read_text(encoding="utf-8")
        for required in (
            "Registry admission is a release gate",
            "exact SHA-256",
            "Recompute the skill hash from canonical bytes",
            "exact candidate commit",
            "failed candidates remain quarantined",
            "CI evidence used for promotion",
        ):
            self.assertIn(required, text)

    def test_candidate_grants_no_runtime_or_egress(self) -> None:
        text = SKILL.read_text(encoding="utf-8").lower()
        for forbidden in ("curl ", "wget ", "pip install", "npm install", "subprocess", "os.system", "http://", "https://"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
