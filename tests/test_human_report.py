import json
import tempfile
import unittest
from pathlib import Path

from three_agent.human_report import build_report_data, create_human_report, render_markdown


class HumanReportTests(unittest.TestCase):
    @staticmethod
    def handoff():
        return {
            "schema_version": "1.0",
            "task_id": "TASK-1",
            "presentation_ready": True,
            "blockers": [],
            "key_facts": [
                {"fact_id": "F001", "claim": "Verified product fact.", "source_ids": ["S1"], "confidence": "medium"}
            ],
            "inferences": [
                {"claim": "The product may fit the use case.", "source_ids": ["S1"], "confidence": "medium"}
            ],
            "conflicts": [],
            "unresolved_items": ["Market share was not verified."],
            "conclusion": "The available primary evidence confirms the product specification.",
            "recommended_next_actions": ["Collect a direct competitor source."],
            "sources": [
                {"source_id": "S1", "title": "Official source", "url": "https://example.com", "fetch_status": "ok"}
            ],
        }

    def test_reader_report_hides_internal_daily_evidence_ids(self):
        data = build_report_data("TASK-1", "Product review", "Compare", self.handoff(), "en")
        text = render_markdown(data)
        self.assertIn("# Product review", text)
        self.assertIn("Verified product fact. [S1]", text)
        self.assertIn("## Sources", text)
        self.assertNotIn("[A1]", text)
        self.assertNotIn("[T1]", text)
        self.assertNotIn("Evidence digest", text)

    def test_docx_and_pdf_exports_are_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            handoff_path = root / "handoff.json"
            handoff_path.write_text(json.dumps(self.handoff()), encoding="utf-8")
            bundle = create_human_report(
                task_id="TASK-1",
                title="Product review",
                request="Compare",
                handoff_path=handoff_path,
                artifact_root=root,
                language="en",
            )
            paths = [Path(x) for x in bundle.paths]
            self.assertTrue(any(x.suffix == ".md" for x in paths))
            self.assertTrue(any(x.suffix == ".docx" for x in paths))
            pdf = next((x for x in paths if x.suffix == ".pdf"), None)
            self.assertIsNotNone(pdf, bundle.warnings)
            self.assertTrue(pdf.read_bytes().startswith(b"%PDF"))
            docx = next(x for x in paths if x.suffix == ".docx")
            self.assertTrue(docx.read_bytes().startswith(b"PK"))

    def test_blocked_report_is_human_readable_without_inventing_facts(self):
        handoff = self.handoff()
        handoff["presentation_ready"] = False
        handoff["blockers"] = ["NO_VERIFIED_FACT"]
        handoff["key_facts"] = []
        data = build_report_data("TASK-2", "Blocked research", "Request", handoff, "vi")
        text = render_markdown(data)
        self.assertIn("Cần xác nhận", text)
        self.assertIn("NO_VERIFIED_FACT", text)
        self.assertNotIn("Verified product fact.", text)


if __name__ == "__main__":
    unittest.main()
