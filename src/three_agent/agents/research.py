from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from .base import BaseAgent
from ..artifacts import ArtifactManager
from ..knowledge_gateway import KnowledgeGateway
from ..models import TaskStatus
from ..research_quality import build_handoff, clean_claims, clean_conflicts
from ..store import TaskStore
from ..web_research import ResearchSource, WebResearchClient

TZ = ZoneInfo("Asia/Tokyo")


class ResearchAgent(BaseAgent):
    agent_id = "research"
    profile_file = "agent_research.md"

    def __init__(
        self,
        profile_root: Path,
        llm,
        web: WebResearchClient | None = None,
        knowledge: KnowledgeGateway | None = None,
    ):
        super().__init__(profile_root, llm)
        self.web = web
        self.knowledge = knowledge

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
                "conflicts": [],
                "unresolved": ["No usable web or uploaded source could be retrieved for this task."],
                "conclusion": "Research could not be evidence-validated because no readable source was collected.",
                "recommended_next_actions": [
                    "Retry research with different search terms, attach a readable document, or verify Internet/source accessibility."
                ],
                "synthesis_error": None,
            }

        evidence = self._evidence_text(usable)
        prompt = f"""
You are completing an evidence-bounded research task.
Use ONLY the SOURCE blocks below. Sources may be public web pages or user-provided uploads.
Never use unstated background knowledge as a verified fact.
Every verified fact and inference MUST cite one or more source IDs exactly as S1, S2, etc.
Detect material contradictions between sources instead of hiding them.
For conflicts, cite at least two source IDs and set severity to low, medium, or critical.
If evidence is insufficient, put the point in unresolved instead of guessing.
Do not repeat the same fact using different wording.
Treat upload:// sources as user-provided evidence, not as independently verified public sources.

Keep the structured response compact enough to remain valid JSON:
- verified_facts: at most 18 concise items
- inferences: at most 6 concise items
- conflicts: at most 6 items
- unresolved: at most 10 items
- recommended_next_actions: at most 8 items
- each claim/description: preferably <= 320 characters
- conclusion: preferably <= 1200 characters
Do not sacrifice source IDs or factual precision to meet these limits.

Return JSON only with this structure:
{{
  "verified_facts": [{{"claim": "...", "source_ids": ["S1"]}}],
  "inferences": [{{"claim": "...", "source_ids": ["S1", "S2"]}}],
  "conflicts": [{{"topic": "...", "description": "...", "severity": "low|medium|critical", "source_ids": ["S1", "S2"]}}],
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
        try:
            result = self.llm.generate_json(self.profile(), prompt, think=False, num_predict=5120)
        except Exception as exc:
            error = " ".join(f"{type(exc).__name__}: {exc}".split())[:1000]
            return {
                "verified_facts": [],
                "inferences": [],
                "conflicts": [],
                "unresolved": [
                    "Structured synthesis could not be validated after the local JSON repair retry.",
                    error,
                ],
                "conclusion": "Sources were collected, but Agent 1 could not produce a structurally valid evidence synthesis. Downstream presentation is blocked rather than using unvalidated output.",
                "recommended_next_actions": [
                    "Retry the task; if the condition repeats, inspect the local LLM response and reduce or chunk the evidence set."
                ],
                "synthesis_error": error,
            }

        valid_ids = {source.source_id for source in usable}
        verified, rejected_verified = clean_claims(result.get("verified_facts"), valid_ids)
        inferences, rejected_inferences = clean_claims(result.get("inferences"), valid_ids)
        conflicts = clean_conflicts(result.get("conflicts"), valid_ids)

        unresolved = result.get("unresolved") if isinstance(result.get("unresolved"), list) else []
        unresolved_clean = [" ".join(str(item).split()) for item in unresolved if str(item).strip()]
        unresolved_clean.extend(f"Uncited model claim rejected: {claim}" for claim in rejected_verified)
        unresolved_clean.extend(f"Uncited model inference rejected: {claim}" for claim in rejected_inferences)
        unresolved_clean = list(dict.fromkeys(unresolved_clean))

        conclusion = result.get("conclusion") if isinstance(result.get("conclusion"), str) else ""
        actions = result.get("recommended_next_actions") if isinstance(result.get("recommended_next_actions"), list) else []
        actions_clean = list(dict.fromkeys(" ".join(str(item).split()) for item in actions if str(item).strip()))
        return {
            "verified_facts": verified,
            "inferences": inferences,
            "conflicts": conflicts,
            "unresolved": unresolved_clean,
            "conclusion": " ".join(conclusion.split()),
            "recommended_next_actions": actions_clean,
            "synthesis_error": None,
        }

    @staticmethod
    def _render_markdown(payload: dict[str, Any], handoff: dict[str, Any]) -> str:
        lines = [
            f"# Research — {payload['title']}",
            "",
            f"**Task:** `{payload['task_id']}`  ",
            f"**Status:** `{payload['status']}`  ",
            f"**Presentation ready:** `{str(handoff['presentation_ready']).lower()}`  ",
            f"**Objective:** {payload['objective']}",
            "",
            "## Quality gate",
            f"- Presentation ready: **{handoff['presentation_ready']}**",
            f"- Blockers: {', '.join(handoff['blockers']) if handoff['blockers'] else 'None'}",
            f"- Usable sources: {handoff['quality_metrics']['usable_source_count']}",
            f"- Verified facts: {handoff['quality_metrics']['verified_fact_count']}",
            f"- High-confidence facts: {handoff['quality_metrics']['high_confidence_fact_count']}",
            f"- Conflicts: {handoff['quality_metrics']['conflict_count']}",
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
                lines.append(f"- **{item['confidence']}** — {item['claim']} — {refs}")
        else:
            lines.append("- None verified.")

        lines.extend(["", "## Inferences"])
        if payload["inferences"]:
            for item in payload["inferences"]:
                refs = ", ".join(f"[{sid}]" for sid in item["source_ids"])
                lines.append(f"- **{item['confidence']}** — {item['claim']} — {refs}")
        else:
            lines.append("- None.")

        lines.extend(["", "## Source conflicts"])
        if payload["conflicts"]:
            for item in payload["conflicts"]:
                refs = ", ".join(f"[{sid}]" for sid in item["source_ids"])
                lines.append(f"- **{item['severity']}** — {item['topic']}: {item['description']} — {refs}")
        else:
            lines.append("- None detected.")

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
                "conflicts": [],
                "unresolved_items": ["Dry-run only; no evidence was collected."],
                "conclusion": "Dry-run scaffold only. No research, web search, or factual verification was performed.",
                "recommended_next_actions": [],
                "synthesis_error": None,
                "generated_at": timestamp,
            }
        else:
            if self.web is None:
                raise RuntimeError("Research Agent live mode requires InternetGateway/WebResearchClient")

            objective, queries, focus = self._plan(task.title, task.request)
            store.record_activity(task_id, self.agent_id, "research_plan_created", "ok", " | ".join(queries))
            upload_ids = store.upload_ids_for_task(task_id)
            if self.knowledge is not None:
                sources, search_errors = self.knowledge.collect(
                    self.agent_id,
                    task_id,
                    queries,
                    upload_ids=upload_ids,
                )
                upload_source_count = sum(1 for source in sources if source.url.startswith("upload://"))
                web_source_count = sum(1 for source in sources if source.url.startswith(("http://", "https://")))
                store.record_activity(
                    task_id,
                    self.agent_id,
                    "knowledge_gateway_completed",
                    "ok" if sources else "warning",
                    f"uploads={len(upload_ids)} upload_sources={upload_source_count} web_sources={web_source_count} diagnostics={len(search_errors)}",
                )
                store.record_activity(
                    task_id,
                    self.agent_id,
                    "web_search_completed",
                    "ok" if web_source_count else "warning",
                    f"results={web_source_count} errors={len(search_errors)}",
                )
            else:
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
            status = "researched_cleaned_and_verified" if usable_count else "research_completed_no_usable_sources"
            if synthesis.get("synthesis_error"):
                status = "research_synthesis_structured_output_blocked"
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
                "attached_upload_ids": upload_ids,
                "verified_facts": synthesis["verified_facts"],
                "inferences": synthesis["inferences"],
                "conflicts": synthesis["conflicts"],
                "unresolved_items": synthesis["unresolved"],
                "conclusion": synthesis["conclusion"],
                "recommended_next_actions": synthesis["recommended_next_actions"],
                "synthesis_error": synthesis.get("synthesis_error"),
                "generated_at": timestamp,
            }

        handoff = build_handoff(payload)
        markdown = self._render_markdown(payload, handoff)
        json_path, md_path = artifacts.write_task_artifact("research", task_id, payload, markdown)
        handoff_path = artifacts.write_research_handoff(task_id, handoff)
        store.record_artifact(task_id, self.agent_id, "research_json", str(json_path))
        store.record_artifact(task_id, self.agent_id, "research_markdown", str(md_path))
        store.record_artifact(task_id, self.agent_id, "research_handoff_json", str(handoff_path))
        final_status = TaskStatus.RESEARCH_COMPLETED if handoff["presentation_ready"] else TaskStatus.WAITING_HUMAN
        store.set_status(task_id, final_status)
        store.record_activity(
            task_id,
            self.agent_id,
            "research_quality_gate",
            "ok" if handoff["presentation_ready"] else "blocked",
            f"presentation_ready={handoff['presentation_ready']} blockers={','.join(handoff['blockers'])}",
        )
        store.record_activity(task_id, self.agent_id, "research_artifact_created", "ok", str(json_path))
        return json_path, md_path, handoff_path
