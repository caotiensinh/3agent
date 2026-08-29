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
    handoff_is_presentable,
    normalize_plan,
    render_markdown,
)
from ..presentation_renderer import PptxRenderer, convert_pptx_to_pdf
from ..runtime_efficiency import sanitize_untrusted_payload
from ..store import TaskStore

TZ = ZoneInfo("Asia/Tokyo")
HANDOFF_SCHEMA_VERSION = "1.0"
HANDOFF_SANITIZER_VERSION = "workspace-handoff-sanitizer/v1"
_RISK_ORDER = {"low": 0, "medium": 1, "high": 2}


class ResearchHandoffNotReady(PresentationValidationError):
    """Raised when Agent 1 has not produced a valid presentation-ready handoff."""


class PresentationAgent(BaseAgent):
    agent_id = "presentation"
    profile_file = "agent_presentation.md"

    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def _drop_empty_model_slides(raw_plan: dict) -> tuple[dict, list[int]]:
        """Drop model-created non-title slides that contain no visible content.

        This is a deterministic structural recovery only. It never invents or moves
        evidence. Invalid objects, unknown claim references, duplicate titles and
        other contract violations remain for normalize_plan() to reject.
        """
        if not isinstance(raw_plan, dict):
            return raw_plan, []
        raw_slides = raw_plan.get("slides")
        if not isinstance(raw_slides, list):
            return raw_plan, []

        cleaned: list[object] = []
        dropped: list[int] = []
        for index, slide in enumerate(raw_slides, start=1):
            if not isinstance(slide, dict):
                cleaned.append(slide)
                continue
            kind = str(slide.get("kind", "content")).strip().lower()
            if kind == "title":
                cleaned.append(slide)
                continue

            has_visible_content = False
            for key in ("claim_refs", "proposal_points", "context_points"):
                value = slide.get(key)
                if isinstance(value, list) and any(str(item).strip() for item in value):
                    has_visible_content = True
                    break

            if not has_visible_content:
                dropped.append(index)
                continue
            cleaned.append(slide)

        if not dropped:
            return raw_plan, []
        sanitized = dict(raw_plan)
        sanitized["slides"] = cleaned
        return sanitized, dropped

    @staticmethod
    def _sanitize_research_boundary(payload: object, *, source: str) -> tuple[dict, dict]:
        """Sanitize an Agent 1 payload before Agent 2 consumes its semantics.

        Suspicious instructions remain ordinary data. The returned metadata contains
        only paths, risk levels and signal names; it never contains the raw payload.
        """
        sanitized, findings = sanitize_untrusted_payload(payload)
        if not isinstance(sanitized, dict):
            raise PresentationValidationError(f"{source.upper()}_PAYLOAD_NOT_OBJECT")

        highest_risk = "low"
        signal_names: set[str] = set()
        finding_paths: list[str] = []
        for finding in findings:
            risk = str(finding.get("risk", "low"))
            if _RISK_ORDER.get(risk, 0) > _RISK_ORDER.get(highest_risk, 0):
                highest_risk = risk
            finding_paths.append(str(finding.get("path", "$")))
            for signal in finding.get("signals", []) or []:
                signal_names.add(str(signal))

        metadata = {
            "sanitizer_version": HANDOFF_SANITIZER_VERSION,
            "source": source,
            "risk": highest_risk,
            "finding_count": len(findings),
            "finding_paths": sorted(set(finding_paths)),
            "signals": sorted(signal_names),
            "raw_content_logged": False,
        }
        return sanitized, metadata

    def _record_research_boundary(
        self,
        task_id: str,
        store: TaskStore,
        metadata: dict,
    ) -> None:
        store.record_activity(
            task_id,
            self.agent_id,
            "research_handoff_sanitized",
            "warning" if metadata["risk"] != "low" else "ok",
            json.dumps(metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        )

    def _block(self, task_id: str, store: TaskStore, reason: str) -> None:
        store.set_status(task_id, TaskStatus.WAITING_HUMAN)
        store.record_activity(
            task_id,
            self.agent_id,
            "presentation_blocked_by_research_gate",
            "blocked",
            reason,
        )
        raise ResearchHandoffNotReady(reason)

    @staticmethod
    def _validate_research_handoff_consistency(
        task_id: str,
        research: dict,
        handoff: dict,
    ) -> None:
        if research.get("task_id") != task_id:
            raise PresentationValidationError("RESEARCH_TASK_ID_MISMATCH")
        if handoff.get("task_id") != task_id:
            raise ResearchHandoffNotReady("HANDOFF_TASK_ID_MISMATCH")
        if handoff.get("schema_version") != HANDOFF_SCHEMA_VERSION:
            raise ResearchHandoffNotReady("UNSUPPORTED_HANDOFF_SCHEMA")

        research_facts = research.get("verified_facts", [])
        handoff_facts = handoff.get("key_facts", [])
        if not isinstance(research_facts, list) or not isinstance(handoff_facts, list):
            raise PresentationValidationError("INVALID_RESEARCH_HANDOFF_FACTS")

        normalized_research = []
        for item in research_facts:
            if not isinstance(item, dict):
                continue
            normalized_research.append((
                str(item.get("claim", "")).strip(),
                tuple(item.get("source_ids", []) or []),
            ))
        normalized_handoff = []
        for item in handoff_facts:
            if not isinstance(item, dict):
                continue
            normalized_handoff.append((
                str(item.get("claim", "")).strip(),
                tuple(item.get("source_ids", []) or []),
            ))
        if normalized_research != normalized_handoff:
            raise PresentationValidationError("RESEARCH_HANDOFF_EVIDENCE_MISMATCH")

    @staticmethod
    def _dry_run_qa(plan: dict, catalog: EvidenceCatalog) -> dict:
        referenced = {
            ref for slide in plan["slides"] for ref in slide.get("claim_refs", [])
        }
        return {
            "schema_version": "presentation-qa/v1",
            "status": "dry_run",
            "errors": [],
            "warnings": ["No LLM deck planning was performed."],
            "unique_titles": len({s["title"] for s in plan["slides"]}) == len(plan["slides"]),
            "visible_facts_source_bounded": True,
            "referenced_claim_count": len(referenced),
            "available_claim_count": len(catalog.claims),
            "evidence_coverage_ratio": (
                0.0 if not catalog.claims else round(len(referenced) / len(catalog.claims), 3)
            ),
            "source_appendix_present": any(s["kind"] == "sources" for s in plan["slides"]),
            "accessibility": {
                "unique_slide_titles": True,
                "title_placeholders_required": True,
                "deterministic_reading_order": True,
                "minimum_body_font_target_pt": 20,
                "color_only_meaning": False,
            },
        }

    @staticmethod
    def _planner_prompt(
        task_title: str,
        task_request: str,
        catalog: EvidenceCatalog,
        options: PresentationOptions,
    ) -> str:
        return f"""
Plan an evidence-bounded professional presentation.
Return JSON only. Do NOT rewrite or paraphrase factual claims in the plan.
Select factual/inference material only by claim ID.

Required top-level fields:
- title: string
- subtitle: string
- slides: array

Each slide object:
- kind: title | content | comparison | risks | decision | timeline | summary
- title: short unique title; title itself must not introduce a new factual claim
- claim_refs: only IDs from EVIDENCE_CATALOG
- proposal_points: recommendations/proposals, not established facts
- context_points: non-factual framing such as meeting purpose or task scope
- speaker_notes: delivery guidance only; never introduce new external facts

Rules:
1. Use at most {options.slide_count} planned slides. Source/limitation appendices are added later.
2. At most 4 claim_refs per slide and 6 visible content items total.
3. Normally place a title slide first.
4. Every non-title slide MUST contain at least one visible item in claim_refs, proposal_points, or context_points. Never emit placeholder or empty slides.
5. Prefer verified facts over inferences.
6. Never promote an inference to fact.
7. Never invent numbers, dates, products, capabilities, prices, customers, risks, or source URLs.
8. New research belongs back in Agent 1, not in this deck.
9. Audience: {options.audience!r}
10. Purpose: {options.purpose!r}
11. Output language: {options.language!r}

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
    ):
        options = PresentationOptions(
            audience=audience,
            purpose=purpose,
            language=language,
            slide_count=slide_count,
            output_format=output_format,
        ).normalized()
        task = store.get_task(task_id)

        handoff_path = artifacts.find_latest_task_artifact(
            "research", task_id, suffix="_handoff.json"
        )
        if handoff_path is None:
            self._block(task_id, store, "RESEARCH_HANDOFF_NOT_FOUND")

        raw_handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
        handoff, handoff_security = self._sanitize_research_boundary(
            raw_handoff, source="research_handoff"
        )
        self._record_research_boundary(task_id, store, handoff_security)
        if handoff.get("task_id") != task_id:
            self._block(task_id, store, "HANDOFF_TASK_ID_MISMATCH")
        if handoff.get("schema_version") != HANDOFF_SCHEMA_VERSION:
            self._block(task_id, store, "UNSUPPORTED_HANDOFF_SCHEMA")

        research_path = artifacts.find_latest_task_artifact(
            "research", task_id, suffix=".json"
        )
        research = None
        research_security = None
        if research_path is not None:
            raw_research = json.loads(research_path.read_text(encoding="utf-8"))
            research, research_security = self._sanitize_research_boundary(
                raw_research, source="research_artifact"
            )
            self._record_research_boundary(task_id, store, research_security)
            try:
                self._validate_research_handoff_consistency(
                    task_id, research, handoff
                )
            except ResearchHandoffNotReady as exc:
                self._block(task_id, store, str(exc))
            except PresentationValidationError as exc:
                store.set_status(task_id, TaskStatus.FAILED)
                store.record_activity(
                    task_id,
                    self.agent_id,
                    "presentation_lineage_validation_failed",
                    "error",
                    str(exc),
                )
                raise

        ready, reason = handoff_is_presentable(handoff)
        if not ready:
            self._block(task_id, store, reason)

        catalog = EvidenceCatalog.from_handoff(handoff)
        store.set_status(task_id, TaskStatus.PRESENTATION_CREATING)
        store.record_activity(
            task_id,
            self.agent_id,
            "presentation_started",
            "ok",
            (
                f"live={live} format={options.output_format} "
                f"audience={options.audience} language={options.language}"
            ),
        )

        try:
            if live:
                raw_plan = self.llm.generate_json(
                    self.profile(),
                    self._planner_prompt(task.title, task.request, catalog, options),
                    think=False,
                    num_predict=4096,
                )
                raw_plan, dropped_empty_slides = self._drop_empty_model_slides(raw_plan)
                plan, qa = normalize_plan(
                    raw_plan, catalog, options, task.title
                )
                if dropped_empty_slides:
                    qa.setdefault("warnings", []).append(
                        "Dropped empty model-planned non-title slides before validation: "
                        + ", ".join(str(index) for index in dropped_empty_slides)
                    )
                    store.record_activity(
                        task_id,
                        self.agent_id,
                        "presentation_empty_slides_dropped",
                        "warning",
                        "raw_slide_indexes=" + ",".join(str(index) for index in dropped_empty_slides),
                    )
                status = "model_planned_evidence_validated"
            else:
                plan = build_dry_run_plan(
                    task.title, task.request, options, catalog
                )
                qa = self._dry_run_qa(plan, catalog)
                status = "dry_run_from_verified_handoff"

            source_research_sha = (
                self._sha256(research_path) if research_path is not None else None
            )
            source_handoff_sha = self._sha256(handoff_path)
            if research_path is None:
                qa.setdefault("warnings", []).append(
                    "Raw research JSON was not found; canonical Agent 1 handoff remains the evidence source."
                )
            output_folder = artifacts.root / "presentations" / artifacts.today()
            output_folder.mkdir(parents=True, exist_ok=True)

            generated_artifacts: dict[str, str] = {}
            render_inspection: dict | None = None

            if options.output_format in {"pptx", "pdf", "all"}:
                pptx_path = output_folder / f"{task_id}.pptx"
                renderer = PptxRenderer()
                renderer.render(plan, pptx_path)
                render_inspection = renderer.inspect(
                    pptx_path,
                    expected_titles=[slide["title"] for slide in plan["slides"]],
                )
                generated_artifacts["pptx"] = str(pptx_path)

                if options.output_format in {"pdf", "all"}:
                    pdf_path = convert_pptx_to_pdf(pptx_path, output_folder)
                    generated_artifacts["pdf"] = str(pdf_path)

            if render_inspection is not None:
                qa["render_inspection"] = render_inspection
                qa["accessibility"]["title_placeholders_present"] = (
                    render_inspection["title_placeholder_count"]
                    == render_inspection["slide_count"]
                )

            payload = {
                "schema_version": "presentation-artifact/v1",
                "task_id": task_id,
                "agent_id": self.agent_id,
                "status": status,
                "source_research_artifact": str(handoff_path),
                "source_research_handoff": str(handoff_path),
                "source_research_handoff_sha256": f"sha256:{source_handoff_sha}",
                "source_research_raw_artifact": (
                    str(research_path) if research_path is not None else None
                ),
                "source_research_raw_sha256": (
                    f"sha256:{source_research_sha}"
                    if source_research_sha is not None
                    else None
                ),
                "source_research_status": (
                    str(research.get("status", "")) if research is not None else None
                ),
                "source_research_schema_version": handoff.get("schema_version"),
                "source_quality_metrics": handoff.get("quality_metrics", {}),
                "source_blockers": handoff.get("blockers", []),
                "source_handoff_security": handoff_security,
                "source_research_security": research_security,
                "options": asdict(options),
                "plan": plan,
                "qa": qa,
                "generated_artifacts": generated_artifacts,
                "generated_at": datetime.now(TZ).isoformat(),
            }

            markdown = (
                f"# Presentation artifact — {task.title}\n\n"
                f"**Task:** `{task_id}`  \n"
                f"**Status:** `{status}`  \n"
                f"**Canonical research handoff:** `{handoff_path}`  \n"
                f"**Handoff SHA-256:** `sha256:{source_handoff_sha}`  \n"
                + (
                    f"**Raw research:** `{research_path}`  \n"
                    f"**Raw research SHA-256:** `sha256:{source_research_sha}`  \n"
                    if research_path is not None
                    else "**Raw research:** `not available`  \n"
                )
                + "\n"
                + render_markdown(plan, qa)
            )
            json_path, md_path = artifacts.write_task_artifact(
                "presentations", task_id, payload, markdown
            )

            store.record_artifact(
                task_id, self.agent_id, "presentation_json", str(json_path)
            )
            store.record_artifact(
                task_id, self.agent_id, "presentation_markdown", str(md_path)
            )
            for artifact_type, path in generated_artifacts.items():
                store.record_artifact(
                    task_id,
                    self.agent_id,
                    f"presentation_{artifact_type}",
                    path,
                )

            store.set_status(task_id, TaskStatus.PRESENTATION_COMPLETED)
            store.record_activity(
                task_id,
                self.agent_id,
                "presentation_completed",
                "ok",
                (
                    f"qa={qa['status']} "
                    f"outputs={','.join(generated_artifacts) or 'source'}"
                ),
            )
            return json_path, md_path

        except ResearchHandoffNotReady:
            raise
        except PresentationValidationError as exc:
            store.set_status(task_id, TaskStatus.FAILED)
            store.record_activity(
                task_id,
                self.agent_id,
                "presentation_validation_failed",
                "error",
                str(exc),
            )
            raise
        except Exception as exc:
            store.set_status(task_id, TaskStatus.FAILED)
            store.record_activity(
                task_id,
                self.agent_id,
                "presentation_failed",
                "error",
                str(exc),
            )
            raise
