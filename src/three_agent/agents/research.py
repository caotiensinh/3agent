from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from .base import BaseAgent
from ..artifacts import ArtifactManager
from ..knowledge_gateway import KnowledgeGateway
from ..models import TaskStatus
from ..research_integrity import (
    clean_source_assessments,
    core_constraint_gaps,
    detect_request_constraints,
    enforce_numeric_evidence,
    vetted_source_ids,
)
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
    def _evidence_text(sources: list[ResearchSource], *, max_total: int = 48000) -> str:
        chunks: list[str] = []
        total = 0
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

    def _assess_sources(
        self,
        request: str,
        objective: str,
        sources: list[ResearchSource],
    ) -> tuple[list[dict], list[ResearchSource], str | None]:
        usable = [source for source in sources if source.fetch_status == "ok" and source.extracted_text]
        if not usable:
            return [], [], None

        previews: list[str] = []
        total = 0
        for source in usable:
            preview = (
                f"[{source.source_id}]\nTITLE: {source.title}\nURL: {source.url}\n"
                f"PREVIEW: {source.extracted_text[:1800]}\n"
            )
            if total + len(preview) > 22000:
                break
            previews.append(preview)
            total += len(preview)

        today = datetime.now(TZ).date().isoformat()
        prompt = f"""
You are a source suitability gate, not a research answer generator.
Assess whether each SOURCE is actually suitable for the user's task.
Use only the supplied title, URL and preview. Do not add facts.

For every source return:
- source_id: exact S-number
- relevance: high, medium, or low
- scope_match: true only when the source content matches the requested product/topic/category/geography/scope
- time_match: true when the source visibly supports the requested/current time window; false when visibly stale; null when time is not material or cannot be established
- authority: primary, secondary, or unknown
- reason: concise explanation

Important:
- A page that merely shares generic keywords is LOW relevance.
- A source about another product/category/meeting/topic is scope_match=false.
- Search-engine redirect pages are not primary evidence.
- For latest/current/past-week requests, old material is not time-matched unless it directly supplies still-current evidence needed by the task.
- User upload sources may be relevant but are not automatically independent verification.

Return JSON only:
{{"sources":[{{"source_id":"S1","relevance":"high|medium|low","scope_match":true,"time_match":true,"authority":"primary|secondary|unknown","reason":"..."}}]}}

TODAY: {today}
REQUEST: {request}
OBJECTIVE: {objective}

SOURCES:
{chr(10).join(previews)}
""".strip()
        try:
            raw = self.llm.generate_json(self.profile(), prompt, think=False, num_predict=2200)
        except Exception as exc:
            error = " ".join(f"{type(exc).__name__}: {exc}".split())[:800]
            return [], [], error

        valid_ids = {source.source_id for source in usable}
        assessments = clean_source_assessments(raw.get("sources"), valid_ids)
        if {item["source_id"] for item in assessments} != valid_ids:
            missing = sorted(valid_ids - {item["source_id"] for item in assessments})
            return assessments, [], "Source suitability assessment incomplete for: " + ",".join(missing)

        accepted_ids = vetted_source_ids(assessments)
        vetted = [source for source in usable if source.source_id in accepted_ids]
        return assessments, vetted, None

    def _synthesize(
        self,
        title: str,
        request: str,
        objective: str,
        focus: list[str],
        sources: list[ResearchSource],
        source_assessments: list[dict],
    ) -> dict[str, Any]:
        usable = [source for source in sources if source.fetch_status == "ok" and source.extracted_text]
        if not usable:
            return {
                "verified_facts": [],
                "inferences": [],
                "conflicts": [],
                "unresolved": ["No source passed the source suitability gate for this task."],
                "conclusion": "Research could not be evidence-validated because no suitable readable source remained after relevance/scope screening.",
                "recommended_next_actions": [
                    "Retry with more specific search terms or attach a directly relevant primary document."
                ],
                "rejected_numeric_claims": [],
                "synthesis_error": None,
            }

        evidence = self._evidence_text(usable)
        prompt = f"""
You are completing an evidence-bounded research task using sources that already passed a suitability gate.
Use ONLY the SOURCE blocks below. Sources may be public web pages or user-provided uploads.
Never use unstated background knowledge as a verified fact.
Every verified fact and inference MUST cite one or more source IDs exactly as S1, S2, etc.
Detect material contradictions between sources instead of hiding them.
For conflicts, cite at least two source IDs and set severity to low, medium, or critical.
If evidence is insufficient, put the point in unresolved instead of guessing.
Do not repeat the same fact using different wording.
Treat upload:// sources as user-provided evidence, not as independently verified public sources.

CRITICAL NUMERICAL RULE:
For every verified fact containing a number, percentage, price, sales quantity, rank, date, capacity, dimension, or count, include evidence_quotes. Each quote must be a short VERBATIM substring copied from the cited source and must contain the numeric value being asserted. Never infer or transform a number that is not explicitly present.

Keep the structured response compact enough to remain valid JSON:
- verified_facts: at most 18 concise items
- inferences: at most 6 concise items
- conflicts: at most 6 items
- unresolved: at most 10 items
- recommended_next_actions: at most 8 items
- conclusion: preferably <= 1200 characters

Return JSON only with this structure:
{{
  "verified_facts": [{{"claim":"...","source_ids":["S1"],"evidence_quotes":[{{"source_id":"S1","quote":"verbatim source text"}}]}}],
  "inferences": [{{"claim":"...","source_ids":["S1","S2"]}}],
  "conflicts": [{{"topic":"...","description":"...","severity":"low|medium|critical","source_ids":["S1","S2"]}}],
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
                "rejected_numeric_claims": [],
                "synthesis_error": error,
            }

        valid_ids = {source.source_id for source in usable}
        verified, rejected_verified = clean_claims(result.get("verified_facts"), valid_ids)
        inferences, rejected_inferences = clean_claims(result.get("inferences"), valid_ids)
        conflicts = clean_conflicts(result.get("conflicts"), valid_ids)

        assessment_map = {item["source_id"]: item for item in source_assessments}
        source_texts = {source.source_id: source.extracted_text for source in usable}
        constraints = detect_request_constraints(request)
        verified, rejected_numeric = enforce_numeric_evidence(
            verified,
            source_texts,
            temporal_required=constraints["temporal"] and (constraints["ranking"] or constraints["quantity"]),
            source_assessments=assessment_map,
        )

        unresolved = result.get("unresolved") if isinstance(result.get("unresolved"), list) else []
        unresolved_clean = [" ".join(str(item).split()) for item in unresolved if str(item).strip()]
        unresolved_clean.extend(f"Uncited model claim rejected: {claim}" for claim in rejected_verified)
        unresolved_clean.extend(f"Uncited model inference rejected: {claim}" for claim in rejected_inferences)
        unresolved_clean.extend(f"Quantitative claim rejected: {claim}" for claim in rejected_numeric)
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
            "rejected_numeric_claims": rejected_numeric,
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
            f"- Rejected sources: {handoff['quality_metrics'].get('rejected_source_count', 0)}",
            f"- Verified facts: {handoff['quality_metrics']['verified_fact_count']}",
            f"- Rejected numerical claims: {handoff['quality_metrics'].get('rejected_numeric_claim_count', 0)}",
            f"- Core constraint gaps: {', '.join(payload.get('constraint_gaps', [])) if payload.get('constraint_gaps') else 'None'}",
            f"- Conflicts: {handoff['quality_metrics']['conflict_count']}",
            "",
            "## Search queries",
        ]
        lines.extend(f"- {query}" for query in payload["search_queries"])

        assessments = {item.get("source_id"): item for item in payload.get("source_assessments", [])}
        lines.extend(["", "## Sources"])
        for source in payload["sources"]:
            state = source["fetch_status"]
            assessment = assessments.get(source.get("source_id"), {})
            quality = ""
            if assessment:
                quality = (
                    f"; relevance={assessment.get('relevance')}"
                    f"; scope_match={assessment.get('scope_match')}"
                    f"; time_match={assessment.get('time_match')}"
                    f"; authority={assessment.get('authority')}"
                )
            lines.append(f"- **[{source['source_id']}] {source['title']}** — {source['url']} (`{state}{quality}`)")
            if assessment.get("reason"):
                lines.append(f"  - Suitability: {assessment['reason']}")
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
                "source_assessments": [],
                "rejected_sources": [],
                "search_errors": [],
                "verified_facts": [],
                "inferences": [],
                "conflicts": [],
                "unresolved_items": ["Dry-run only; no evidence was collected."],
                "constraint_gaps": [],
                "rejected_numeric_claims": [],
                "conclusion": "Dry-run scaffold only. No research, web search, or factual verification was performed.",
                "recommended_next_actions": [],
                "source_assessment_error": None,
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

            assessments, vetted_sources, assessment_error = self._assess_sources(task.request, objective, sources)
            vetted_ids = {source.source_id for source in vetted_sources}
            rejected_sources = [source.source_id for source in sources if source.fetch_status == "ok" and source.extracted_text and source.source_id not in vetted_ids]
            store.record_activity(
                task_id,
                self.agent_id,
                "source_suitability_gate",
                "error" if assessment_error else ("ok" if vetted_sources else "blocked"),
                f"vetted={len(vetted_sources)} rejected={len(rejected_sources)} error={bool(assessment_error)}",
            )

            synthesis = self._synthesize(task.title, task.request, objective, focus, vetted_sources, assessments)
            constraint_gaps = core_constraint_gaps(task.request, synthesis["verified_facts"], assessments)
            unresolved = list(synthesis["unresolved"])
            unresolved.extend(f"Core requirement unresolved: {gap}" for gap in constraint_gaps)
            unresolved = list(dict.fromkeys(unresolved))

            usable_count = sum(1 for source in sources if source.fetch_status == "ok" and source.extracted_text)
            status = "researched_cleaned_and_verified" if usable_count else "research_completed_no_usable_sources"
            if assessment_error:
                status = "research_source_suitability_blocked"
            elif synthesis.get("synthesis_error"):
                status = "research_synthesis_structured_output_blocked"
            elif constraint_gaps:
                status = "research_core_requirements_blocked"

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
                "source_assessments": assessments,
                "rejected_sources": rejected_sources,
                "search_errors": search_errors,
                "attached_upload_ids": upload_ids,
                "verified_facts": synthesis["verified_facts"],
                "inferences": synthesis["inferences"],
                "conflicts": synthesis["conflicts"],
                "unresolved_items": unresolved,
                "constraint_gaps": constraint_gaps,
                "rejected_numeric_claims": synthesis.get("rejected_numeric_claims", []),
                "conclusion": synthesis["conclusion"],
                "recommended_next_actions": synthesis["recommended_next_actions"],
                "source_assessment_error": assessment_error,
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
