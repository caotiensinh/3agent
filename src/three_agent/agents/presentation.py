from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .base import BaseAgent
from ..artifacts import ArtifactManager
from ..models import TaskStatus
from ..presentation_model import (
    EvidenceCatalog,
    PresentationOptions,
    PresentationValidationError,
    build_dry_run_plan,
    normalize_plan,
    render_markdown,
    research_is_presentable,
)
from ..presentation_renderer import PptxRenderer, convert_pptx_to_pdf
from ..store import TaskStore

TZ = ZoneInfo("Asia/Tokyo")


class PresentationAgent(BaseAgent):
    agent_id = "presentation"
    profile_file = "agent_presentation.md"

    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def _dry_run_qa() -> dict:
        return {
            "schema_version": "presentation-qa/v1",
            "status": "dry_run",
            "errors": [],
            "warnings": ["No live research/model generation was performed."],
            "unique_titles": True,
            "visible_facts_source_bounded": True,
            "referenced_claim_count": 0,
            "available_claim_count": 0,
            "evidence_coverage_ratio": 0.0,
            "source_appendix_present": False,
            "accessibility": {
                "unique_slide_titles": True,
                "deterministic_reading_order": True,
                "minimum_body_font_target_pt": 20,
                "color_only_meaning": False,
            },
        }

    @staticmethod
    def _planner_prompt(task_title: str, task_request: str, catalog: EvidenceCatalog, options: PresentationOptions) -> str:
        content_slide_budget = max(2, options.slide_count - 1)
        return f"""
Plan an evidence-bounded professional presentation.
Return JSON only. Do NOT rewrite or paraphrase factual claims in the plan. Select facts only by claim ID.

Required top-level fields:
- title: string
- subtitle: string
- slides: array

Each slide object must contain:
- kind: one of title, content, comparison, risks, decision, timeline, summary
- title: short unique title, not a new factual claim
- claim_refs: array containing only claim IDs from EVIDENCE_CATALOG
- proposal_points: recommendations/proposals; they will be visibly labeled as proposals
- context_points: non-factual framing only, such as meeting purpose or task scope
- speaker_notes: delivery guidance only; never introduce new external facts

Rules:
1. Use at most {content_slide_budget} planned slides. Source/limitation appendix slides are added deterministically later.
2. Use at most 4 claim_refs per slide and at most 6 visible items total.
3. Normally place a title slide first.
4. Prefer verified facts to inferences.
5. If an inference is selected, keep the slide title neutral and do not present it as certainty.
6. Never invent statistics, dates, products, capabilities, customers, prices, risks or conclusions.
7. Never repeat source URLs. The renderer adds source references automatically.
8. Audience: {options.audience!r}. Purpose: {options.purpose!r}. Output language: {options.language!r}.

TASK TITLE: {task_title}
TASK REQUEST: {task_request}

EVIDENCE_CATALOG:
{json.dumps(catalog.to_prompt_payload(), ensure_ascii=False, indent=2)}
""".strip()

    def run(
        self,
        task_id: str,
        store: TaskStore,
        artifacts: ArtifactManager,
        live: bool = False,
        *,
        audience: str = "R&D internal",
        purpose: str = "inform",
        language: str = "ja",
        slide_count: int = 6,
        output_format: str = "source",
        allow_incomplete_research: bool = False,
    ):
        options = PresentationOptions(
            audience=audience,
            purpose=purpose,
            language=language,
            slide_count=slide_count,
            output_format=output_format,
            allow_incomplete_research=allow_incomplete_research,
        ).normalized()
        task = store.get_task(task_id)
        research_path = artifacts.find_latest_task_artifact("research", task_id, suffix=".json")
        if research_path is None:
            raise FileNotFoundError(f"Research artifact not found for task: {task_id}")
        research = json.loads(research_path.read_text(encoding="utf-8"))
        source_status = str(research.get("status", ""))
        handoff_path = artifacts.find_latest_task_artifact("research", task_id, suffix="_handoff.json")
        handoff = json.loads(handoff_path.read_text(encoding="utf-8")) if handoff_path else None

        store.set_status(task_id, TaskStatus.PRESENTATION_CREATING)
        store.record_activity(
            task_id,
            self.agent_id,
            "presentation_started",
            "ok",
            f"live={live} format={options.output_format} audience={options.audience}",
        )

        try:
            if live:
                if handoff is not None and not bool(handoff.get("presentation_ready")) and not options.allow_incomplete_research:
                    blockers = handoff.get("blockers") or ["RESEARCH_HANDOFF_BLOCKED"]
                    reason = "Agent 1 presentation handoff blocked: " + ",".join(str(item) for item in blockers)
                    store.set_status(task_id, TaskStatus.WAITING_HUMAN)
                    store.record_activity(task_id, self.agent_id, "presentation_blocked", "warning", reason)
                    raise PresentationValidationError(reason)
                ready, reason = research_is_presentable(research, options.allow_incomplete_research)
                if not ready:
                    store.set_status(task_id, TaskStatus.WAITING_HUMAN)
                    store.record_activity(task_id, self.agent_id, "presentation_blocked", "warning", reason)
                    raise PresentationValidationError(reason)

                catalog = EvidenceCatalog.from_research(research)
                prompt = self._planner_prompt(task.title, task.request, catalog, options)
                raw_plan = self.llm.generate_json(self.profile(), prompt, think=False, num_predict=4096)
                plan, qa = normalize_plan(raw_plan, catalog, options, task.title)
                status = "model_planned_evidence_validated"
            else:
                plan = build_dry_run_plan(task.title, task.request, options)
                qa = self._dry_run_qa()
                status = "dry_run"

            generated_at = datetime.now(TZ).isoformat()
            source_digest = self._sha256(research_path)
            output_folder = artifacts.root / "presentations" / artifacts.today()
            output_folder.mkdir(parents=True, exist_ok=True)
            generated_artifacts: dict[str, str] = {}

            wants_pptx = options.output_format in {"pptx", "pdf", "all"}
            if wants_pptx:
                pptx_path = output_folder / f"{task_id}.pptx"
                PptxRenderer().render(plan, pptx_path)
                generated_artifacts["pptx"] = str(pptx_path)
                if options.output_format in {"pdf", "all"}:
                    pdf_path = convert_pptx_to_pdf(pptx_path, output_folder)
                    generated_artifacts["pdf"] = str(pdf_path)

            payload = {
                "schema_version": "presentation-artifact/v1",
                "task_id": task_id,
                "agent_id": self.agent_id,
                "status": status,
                "source_research_artifact": str(research_path),
                "source_research_sha256": source_digest,
                "source_research_status": source_status,
                "source_research_handoff": str(handoff_path) if handoff_path else None,
                "source_research_handoff_ready": handoff.get("presentation_ready") if handoff else None,
                "options": asdict(options),
                "plan": plan,
                "qa": qa,
                "generated_artifacts": generated_artifacts,
                "generated_at": generated_at,
            }
            markdown = (
                f"# Presentation artifact — {task.title}\n\n"
                f"**Task:** `{task_id}`  \n"
                f"**Status:** `{status}`  \n"
                f"**Source research:** `{research_path}`  \n"
                f"**Source SHA-256:** `{source_digest}`  \n\n"
                + render_markdown(plan, qa)
            )
            json_path, md_path = artifacts.write_task_artifact("presentations", task_id, payload, markdown)

            store.record_artifact(task_id, self.agent_id, "presentation_json", str(json_path))
            store.record_artifact(task_id, self.agent_id, "presentation_markdown", str(md_path))
            for artifact_type, path in generated_artifacts.items():
                store.record_artifact(task_id, self.agent_id, f"presentation_{artifact_type}", path)

            store.set_status(task_id, TaskStatus.PRESENTATION_COMPLETED)
            store.record_activity(
                task_id,
                self.agent_id,
                "presentation_completed",
                "ok",
                f"qa={qa['status']} outputs={','.join(generated_artifacts) or 'source'}",
            )
            return json_path, md_path
        except PresentationValidationError:
            if store.get_task(task_id).status != TaskStatus.WAITING_HUMAN:
                store.set_status(task_id, TaskStatus.FAILED)
            raise
        except Exception as exc:
            store.set_status(task_id, TaskStatus.FAILED)
            store.record_activity(task_id, self.agent_id, "presentation_failed", "error", str(exc))
            raise
