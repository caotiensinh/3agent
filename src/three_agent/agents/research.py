from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from .base import BaseAgent
from ..artifacts import ArtifactManager
from ..models import TaskStatus
from ..store import TaskStore
from ..web_research import ResearchSource, WebResearchClient

TZ = ZoneInfo("Asia/Tokyo")


class ResearchAgent(BaseAgent):
    agent_id = "research"
    profile_file = "agent_research.md"

    def __init__(self, profile_root: Path, llm, web: WebResearchClient | None = None):
        super().__init__(profile_root, llm)
        self.web = web

    @staticmethod
    def _clean_queries(value: Any, fallback: str) -> list[str]:
        queries: list[str] = []
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.strip():
                    query = " ".join(item.split())
                    if query not in queries:
                        queries.append(query)
        if not queries:
            queries.append(" ".join(fallback.split()))
        return queries[:4]

    def _plan(self, title: str, request: str) -> tuple[str, list[str], list[str]]:
        fallback = f"{title} {request}"
        prompt = f"""
Create a concise web-research plan for this task.
Return JSON only with exactly these top-level fields:
- objective: string
- queries: array of 2 to 4 practical web search queries
- focus: array of short strings describing what must be verified

Do not answer the research question yet.
TITLE: {title}
REQUEST: {request}
""".strip()
        try:
            plan = self.llm.generate_json(self.profile(), prompt, think=False, num_predict=768)
        except Exception:
            return request, [fallback], []

        objective = plan.get("objective") if isinstance(plan.get("objective"), str) else request
        queries = self._clean_queries(plan.get("queries"), fallback)
        focus_raw = plan.get("focus")
        focus = [str(item).strip() for item in focus_raw if str(item).strip()] if isinstance(focus_raw, list) else []
        return objective.strip(), queries, focus[:8]

    @staticmethod
    def _evidence_text(sources: list[ResearchSource]) -> str:
        chunks: list[str] = []
        total = 0
        max_total = 48000
        for source in sources:
            if source.fetch_status != "ok" or not source.extracted_text:
                continue
            chunk = (
                f"[{source.source_id}]\n"
                f"TITLE: {source.title}\n"
                f"URL: {source.url}\n"
                f"TEXT:\n{source.extracted_text}\n"
            )
            remaining = max_total - total
            if remaining <= 0:
                break
            chunk = chunk[:remaining]
            chunks.append(chunk)
            total += len(chunk)
        return "\n---\n".join(chunks)

    @staticmethod
    def _normalize_claims(value: Any, valid_source_ids: set[str]) -> tuple[list[dict], list[str]]:
        claims: list[dict] = []
        rejected: list[str] = []
        if not isinstance(value, list):
            return claims, rejected
        for item in value:
            if isinstance(item, str):
                claim = item.strip()
                source_ids: list[str] = []
            elif isinstance(item, dict):
                claim = str(item.get("claim", "")).strip()
                raw_ids = item.get("source_ids", [])
                source_ids = [sid for sid in raw_ids if isinstance(sid, str) and sid in valid_source_ids] if isinstance(raw_ids, list) else []
            else:
                continue
            if not claim:
                continue
            if not source_ids:
                rejected.append(claim)
                continue
            claims.append({"claim": claim, "source_ids": source_ids})
        return claims, rejected

    def _synthesize(
        self,
        title: str,
        request: str,
        objective: str,
        focus: list[str],
        sources: list[ResearchSource],
    ) -> dict[str, Any]:
        usable = [source for source in sources if source.fetch_status == "ok" and source.extracted_text]
        if not usable:
            return {
                "verified_facts": [],
                "inferences": [],
                "unresolved": ["No usable web source could be retrieved for this task."],
                "conclusion": "Research could not be evidence-validated because no readable source was collected.",
                "recommended_next_actions": ["Retry research with different search terms or verify Internet/source accessibility."],
            }

        evidence = self._evidence_text(usable)
        prompt = f"""
You are completing an evidence-bounded research task.
Use ONLY the SOURCE blocks below. Never use unstated background knowledge as a verified fact.
Every verified fact and inference MUST cite one or more source IDs exactly as S1, S2, etc.
If evidence is insufficient, put the point in unresolved instead of guessing.

Return JSON only with this structure:
{{
  "verified_facts": [{{"claim": "...", "source_ids": ["S1"]}}],
  "inferences": [{{"claim": "...", "source_ids": ["S1", "S2"]}}],
  "unresolved": ["..."],
  "conclusion": "...",
  "recommended_next_actions": ["..."]
}}

TITLE: {title}
REQUEST: {request}
OBJECTIVE: {objective}
FOCUS: {focus}

SOURCES:
{evidence}
""".strip()
        result = self.llm.generate_json(self.profile(), prompt, think=False, num_predict=4096)
        valid_ids = {source.source_id for source in usable}
        verified, rejected_verified = self._normalize_claims(result.get("verified_facts"), valid_ids)
        inferences, rejected_inferences = self._normalize_claims(result.get("inferences"), valid_ids)

        unresolved = result.get("unresolved") if isinstance(result.get("unresolved"), list) else []
        unresolved_clean = [str(item).strip() for item in unresolved if str(item).strip()]
        unresolved_clean.extend(f"Uncited model claim rejected: {claim}" for claim in rejected_verified)
        unresolved_clean.extend(f"Uncited model inference rejected: {claim}" for claim in rejected_inferences)

        conclusion = result.get("conclusion") if isinstance(result.get("conclusion"), str) else ""
        actions = result.get("recommended_next_actions") if isinstance(result.get("recommended_next_actions"), list) else []
        actions_clean = [str(item).strip() for item in actions if str(item).strip()]
        return {
            "verified_facts": verified,
            "inferences": inferences,
            "unresolved": unresolved_clean,
            "conclusion": conclusion.strip(),
            "recommended_next_actions": actions_clean,
        }

    @staticmethod
    def _render_markdown(payload: dict[str, Any]) -> str:
        lines = [
            f"# Research — {payload['title']}",
            "",
            f"**Task:** `{payload['task_id']}`  ",
            f"**Status:** `{payload['status']}`  ",
            f"**Objective:** {payload['objective']}",
            "",
            "## Search queries",
        ]
        lines.extend(f"- {query}" for query in payload["search_queries"])

        lines.extend(["", "## Sources"])
        for source in payload["sources"]:
            state = source["fetch_status"]
            lines.append(f"- **[{source['source_id']}] {source['title']}** — {source['url']} (`{state}`)")
            if source.get("search_snippet"):
                lines.append(f"  - {source['search_snippet']}")
            if source.get("error"):
                lines.append(f"  - Fetch error: `{source['error']}`")

        lines.extend(["", "## Verified facts"])
        if payload["verified_facts"]:
            for item in payload["verified_facts"]:
                refs = ", ".join(f"[{sid}]" for sid in item["source_ids"])
                lines.append(f"- {item['claim']} — {refs}")
        else:
            lines.append("- None verified.")

        lines.extend(["", "## Inferences"])
        if payload["inferences"]:
            for item in payload["inferences"]:
                refs = ", ".join(f"[{sid}]" for sid in item["source_ids"])
                lines.append(f"- {item['claim']} — {refs}")
        else:
            lines.append("- None.")

        lines.extend(["", "## Unresolved"])
        lines.extend(f"- {item}" for item in payload["unresolved_items"]) if payload["unresolved_items"] else lines.append("- None.")

        lines.extend(["", "## Conclusion", payload["conclusion"] or "No conclusion available."])
        lines.extend(["", "## Recommended next actions"])
        lines.extend(f"- {item}" for item in payload["recommended_next_actions"]) if payload["recommended_next_actions"] else lines.append("- None.")
        return "\n".join(lines)

    def run(self, task_id: str, store: TaskStore, artifacts: ArtifactManager, live: bool = False):
        task = store.get_task(task_id)
        store.set_status(task_id, TaskStatus.RESEARCHING)
        store.record_activity(task_id, self.agent_id, "research_started", "ok", f"live={live}")
        timestamp = datetime.now(TZ).isoformat()

        if not live:
            payload = {
                "task_id": task.task_id,
                "agent_id": self.agent_id,
                "status": "dry_run_not_researched",
                "title": task.title,
                "request": task.request,
                "objective": task.request,
                "search_queries": [],
                "focus": [],
                "sources": [],
                "search_errors": [],
                "verified_facts": [],
                "inferences": [],
                "unresolved_items": [],
                "conclusion": "Dry-run scaffold only. No research, web search, or factual verification was performed.",
                "recommended_next_actions": [],
                "generated_at": timestamp,
            }
        else:
            if self.web is None:
                raise RuntimeError("Research Agent live mode requires InternetGateway/WebResearchClient")

            objective, queries, focus = self._plan(task.title, task.request)
            store.record_activity(task_id, self.agent_id, "research_plan_created", "ok", " | ".join(queries))
            search_results, search_errors = self.web.search_many(self.agent_id, task_id, queries)
            store.record_activity(
                task_id,
                self.agent_id,
                "web_search_completed",
                "ok" if search_results else "warning",
                f"results={len(search_results)} errors={len(search_errors)}",
            )
            sources = self.web.fetch_sources(self.agent_id, task_id, search_results)
            synthesis = self._synthesize(task.title, task.request, objective, focus, sources)
            usable_count = sum(1 for source in sources if source.fetch_status == "ok" and source.extracted_text)
            status = "researched_with_sources" if usable_count else "research_completed_no_usable_sources"
            payload = {
                "task_id": task.task_id,
                "agent_id": self.agent_id,
                "status": status,
                "title": task.title,
                "request": task.request,
                "objective": objective,
                "search_queries": queries,
                "focus": focus,
                "sources": [source.to_dict() for source in sources],
                "search_errors": search_errors,
                "verified_facts": synthesis["verified_facts"],
                "inferences": synthesis["inferences"],
                "unresolved_items": synthesis["unresolved"],
                "conclusion": synthesis["conclusion"],
                "recommended_next_actions": synthesis["recommended_next_actions"],
                "generated_at": timestamp,
            }

        markdown = self._render_markdown(payload)
        json_path, md_path = artifacts.write_task_artifact("research", task_id, payload, markdown)
        store.record_artifact(task_id, self.agent_id, "research_json", str(json_path))
        store.record_artifact(task_id, self.agent_id, "research_markdown", str(md_path))
        store.set_status(task_id, TaskStatus.RESEARCH_COMPLETED)
        store.record_activity(task_id, self.agent_id, "research_artifact_created", "ok", str(json_path))
        return json_path, md_path
