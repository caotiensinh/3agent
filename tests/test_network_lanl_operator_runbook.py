from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "evaluation" / "network_v3_02e_lanl_operator_runbook_v1.json"
RUNBOOK = ROOT / "docs" / "WORKSPACE_NETWORK_V3_02E_LANL_OPERATOR_RUNBOOK.md"


class LANLOperatorRunbookContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        cls.text = RUNBOOK.read_text(encoding="utf-8")

    def test_required_sections_are_present(self) -> None:
        for section in self.profile["required_sections"]:
            self.assertIn(f"## {section}", self.text)

    def test_official_publisher_page_is_the_only_lanl_url(self) -> None:
        urls = re.findall(r"https://[^\s)`]+", self.text)
        lanl_urls = [url for url in urls if urlsplit(url).hostname == "csr.lanl.gov"]
        self.assertEqual(lanl_urls, [self.profile["official_publisher_page"]])

    def test_exact_expected_source_set_is_documented(self) -> None:
        for filename in self.profile["expected_files"]:
            self.assertIn(f"`{filename}`", self.text)

    def test_reviewed_handoff_command_is_exact(self) -> None:
        command = self.profile["expected_handoff_command"]
        self.assertEqual(self.text.count(command), 1)

    def test_required_security_statements_are_present(self) -> None:
        for statement in self.profile["required_security_statements"]:
            self.assertIn(statement, self.text)

    def test_forbidden_patterns_are_absent(self) -> None:
        lowered = self.text.casefold()
        for pattern in self.profile["forbidden_patterns"]:
            self.assertNotIn(pattern.casefold(), lowered)

    def test_ready_state_is_not_execution_authority(self) -> None:
        self.assertIn(self.profile["expected_ready_state"], self.text)
        self.assertIn("does not authorize corpus download or execution", self.text)
        self.assertIn("At this point, stop.", self.text)

    def test_incomplete_state_remains_blocked(self) -> None:
        self.assertIn(self.profile["blocked_real_source_state"], self.text)
        self.assertIn("Do not proceed to LANL execution.", self.text)

    def test_no_positive_direct_download_or_mirror_instructions(self) -> None:
        forbidden_phrases = (
            "direct download url:",
            "download handle example:",
            "download from a mirror",
            "use alternate download host",
            "automate lanl enrollment",
        )
        lowered = self.text.casefold()
        for phrase in forbidden_phrases:
            self.assertNotIn(phrase, lowered)

    def test_no_secret_transport_instructions(self) -> None:
        forbidden_phrases = (
            "save the handles",
            "store the handles",
            "export the handles",
            "pass the handles as arguments",
            "write the handles to",
        )
        lowered = self.text.casefold()
        for phrase in forbidden_phrases:
            self.assertNotIn(phrase, lowered)


if __name__ == "__main__":
    unittest.main()
