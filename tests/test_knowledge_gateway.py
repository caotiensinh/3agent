import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from PIL import Image

from three_agent.knowledge_gateway import KnowledgeGateway, UploadSecurityError
from three_agent.web_research import ResearchSource, SearchResult


class FakeWeb:
    def search_many(self, agent_id, task_id, queries, **kwargs):
        del agent_id, task_id, queries, kwargs
        return [SearchResult("Official", "https://example.com/official", "official")], []

    def fetch_sources(self, agent_id, task_id, results, **kwargs):
        del agent_id, task_id, results, kwargs
        return [
            ResearchSource(
                source_id="S1",
                title="Official",
                url="https://example.com/official",
                search_snippet="official",
                extracted_text="Official web evidence.",
                fetch_status="ok",
            )
        ]


class KnowledgeGatewayTests(unittest.TestCase):
    def gateway(self, root: Path) -> KnowledgeGateway:
        return KnowledgeGateway(root, FakeWeb())

    def test_txt_upload_becomes_research_source_before_web(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = self.gateway(Path(tmp))
            record = gateway.ingest_upload("notes.md", b"# Test\nUploaded evidence.")
            sources, diagnostics = gateway.collect(
                "research",
                "TASK-1",
                ["test"],
                upload_ids=[record.upload_id],
            )
            self.assertFalse(diagnostics)
            self.assertEqual([x.source_id for x in sources], ["S1", "S2"])
            self.assertTrue(sources[0].url.startswith("upload://"))
            self.assertEqual(sources[0].fetch_status, "ok")
            self.assertIn("Uploaded evidence", sources[0].extracted_text)
            self.assertEqual(sources[1].url, "https://example.com/official")

    def test_html_upload_removes_script_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = self.gateway(Path(tmp))
            record = gateway.ingest_upload(
                "page.html",
                b"<html><title>Doc</title><body><script>SECRET()</script><main>Visible fact</main></body></html>",
            )
            sources, _ = gateway.load_upload_sources([record.upload_id])
            self.assertEqual(len(sources), 1)
            self.assertIn("Visible fact", sources[0].extracted_text)
            self.assertNotIn("SECRET", sources[0].extracted_text)

    def test_zip_is_read_in_memory_and_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = self.gateway(Path(tmp))
            data = io.BytesIO()
            with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("../escape.txt", "bad")
            with self.assertRaises(UploadSecurityError):
                gateway.ingest_upload("bad.zip", data.getvalue())
            self.assertFalse((Path(tmp) / "escape.txt").exists())

    def test_zip_accepts_supported_docs_and_skips_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = self.gateway(Path(tmp))
            data = io.BytesIO()
            with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("docs/a.md", "Alpha evidence")
                archive.writestr("docs/b.html", "<p>Beta evidence</p>")
                archive.writestr("bin/run.exe", b"MZ")
            record = gateway.ingest_upload("bundle.zip", data.getvalue())
            self.assertEqual(record.document_count, 2)
            self.assertTrue(any("run.exe" in item for item in record.warnings))
            sources, _ = gateway.load_upload_sources([record.upload_id])
            self.assertEqual(len(sources), 2)

    def test_image_is_validated_but_not_used_as_semantic_text_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = self.gateway(Path(tmp))
            data = io.BytesIO()
            Image.new("RGB", (8, 6), "white").save(data, format="PNG")
            record = gateway.ingest_upload("camera.png", data.getvalue())
            self.assertEqual(record.image_count, 1)
            self.assertEqual(record.document_count, 0)
            sources, diagnostics = gateway.load_upload_sources([record.upload_id])
            self.assertEqual(sources, [])
            self.assertTrue(any("image_not_semantically_parsed" in item for item in diagnostics))

    def test_unsupported_type_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = self.gateway(Path(tmp))
            with self.assertRaises(UploadSecurityError):
                gateway.ingest_upload("payload.sh", b"echo nope")


if __name__ == "__main__":
    unittest.main()
