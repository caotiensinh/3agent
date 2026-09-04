import tempfile
import unittest
from pathlib import Path

from three_agent.chat_gateway import ProgressJob, _daily_report_text


class ChatGatewayV2Tests(unittest.TestCase):
    def test_progress_job_exposes_three_agent_stages(self):
        job = ProgressJob(
            job_id="job1",
            channel="web",
            sender="192.168.1.2",
            message="test",
            language="ja",
            output_format="source",
        )
        payload = job.public_dict()
        self.assertEqual([stage["id"] for stage in payload["stages"]], ["research", "presentation", "daily_report"])
        self.assertTrue(all(stage["status"] == "queued" for stage in payload["stages"]))

    def test_artifact_public_view_hides_server_paths(self):
        job = ProgressJob(
            job_id="job1",
            channel="web",
            sender="192.168.1.2",
            message="test",
            language="ja",
            output_format="source",
            artifacts=["/home/aiserver/3agent/data/daily_reports/2026-08-28.md"],
        )
        payload = job.public_dict()
        self.assertEqual(payload["artifacts"][0]["name"], "2026-08-28.md")
        self.assertEqual(payload["artifacts"][0]["url"], "/api/artifacts/job1/0")
        self.assertNotIn("/home/aiserver", str(payload["artifacts"]))

    def test_daily_report_is_rendered_in_chat(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.md"
            path.write_text("# Daily Report\n\n- completed task", encoding="utf-8")
            text = _daily_report_text([str(path)])
            self.assertIn("Daily Report", text)
            self.assertIn("completed task", text)


if __name__ == "__main__":
    unittest.main()
