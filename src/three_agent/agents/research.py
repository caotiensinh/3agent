from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from .base import BaseAgent
from ..artifacts import ArtifactManager
from ..models import TaskStatus
from ..store import TaskStore

TZ = ZoneInfo("Asia/Tokyo")


class ResearchAgent(BaseAgent):
    agent_id = "research"
    profile_file = "agent_research.md"

    def run(self, task_id: str, store: TaskStore, artifacts: ArtifactManager, live: bool = False):
        task = store.get_task(task_id)
        store.set_status(task_id, TaskStatus.RESEARCHING)
        store.record_activity(task_id, self.agent_id, "research_started", "ok", f"live={live}")
        timestamp = datetime.now(TZ).isoformat()

        if live:
            prompt = (
                "Produce a structured research report for the following task. Do not fabricate sources. "
                "If no web/search tool evidence is present, clearly state that limitation.\n\n"
                f"TITLE: {task.title}\nREQUEST: {task.request}"
            )
            content = self.llm.generate(self.profile(), prompt)
            status = "model_generated_requires_source_validation"
        else:
            content = "Dry-run scaffold only. No research, web search, or factual verification was performed."
            status = "dry_run_not_researched"

        payload = {
            "task_id": task.task_id,
            "agent_id": self.agent_id,
            "status": status,
            "title": task.title,
            "request": task.request,
            "verified_facts": [],
            "inferences": [],
            "unresolved_items": [],
            "sources": [],
            "content": content,
            "generated_at": timestamp,
        }
        markdown = f"# Research — {task.title}\n\n**Task:** `{task.task_id}`  \n**Status:** `{status}`\n\n{content}\n"
        json_path, md_path = artifacts.write_task_artifact("research", task_id, payload, markdown)
        store.record_artifact(task_id, self.agent_id, "research_json", str(json_path))
        store.record_artifact(task_id, self.agent_id, "research_markdown", str(md_path))
        store.set_status(task_id, TaskStatus.RESEARCH_COMPLETED)
        store.record_activity(task_id, self.agent_id, "research_artifact_created", "ok", str(json_path))
        return json_path, md_path
