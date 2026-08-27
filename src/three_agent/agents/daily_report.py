from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from .base import BaseAgent
from ..artifacts import ArtifactManager
from ..store import TaskStore

TZ = ZoneInfo("Asia/Tokyo")


class DailyReportAgent(BaseAgent):
    agent_id = "daily_report"
    profile_file = "agent_daily_report.md"

    def run(self, date: str, store: TaskStore, artifacts: ArtifactManager, live: bool = False):
        rows = store.activities_for_date(date)
        evidence = [
            {
                "timestamp": r["timestamp"],
                "task_id": r["task_id"],
                "agent_id": r["agent_id"],
                "action": r["action"],
                "status": r["status"],
                "details": r["details"],
            }
            for r in rows
        ]
        if live:
            import json

            content = self.llm.generate(
                self.profile(),
                "Create a concise Japanese R&D daily report using only the activity evidence below. "
                "Do not invent unrecorded work.\n\n" + json.dumps(evidence, ensure_ascii=False, indent=2),
            )
            status = "model_generated"
        else:
            lines = ["## Recorded activity"]
            if evidence:
                for item in evidence:
                    lines.append(
                        f"- {item['timestamp']} | {item['agent_id']} | {item['task_id'] or '-'} | "
                        f"{item['action']} | {item['status']}"
                    )
            else:
                lines.append("- No recorded activity for this date.")
            content = "\n".join(lines)
            status = "deterministic_from_activity_log"

        payload = {
            "date": date,
            "agent_id": self.agent_id,
            "status": status,
            "activity_count": len(evidence),
            "activities": evidence,
            "generated_at": datetime.now(TZ).isoformat(),
        }
        markdown = f"# 日報 — {date}\n\n**Status:** `{status}`\n\n{content}\n"
        json_path, md_path = artifacts.write_daily_report(date, payload, markdown)
        store.record_artifact(None, self.agent_id, "daily_report_json", str(json_path))
        store.record_artifact(None, self.agent_id, "daily_report_markdown", str(md_path))
        store.record_activity(None, self.agent_id, "daily_report_created", "ok", str(json_path))
        return json_path, md_path
