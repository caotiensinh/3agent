from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


class PresentationValidationError(ValueError):
    pass


@dataclass(frozen=True)
class PresentationOptions:
    audience: str = "R&D internal"
    purpose: str = "inform"
    language: str = "ja"
    slide_count: int = 6
    output_format: str = "source"
    allow_incomplete_research: bool = False

    def normalized(self) -> "PresentationOptions":
        audience = " ".join(self.audience.split()) or "R&D internal"
        purpose = " ".join(self.purpose.split()) or "inform"
        language = self.language.strip().lower() or "ja"
        if language not in {"ja", "en", "vi"}:
            raise PresentationValidationError("language must be one of: ja, en, vi")
        if not 3 <= self.slide_count <= 20:
            raise PresentationValidationError("slide_count must be between 3 and 20")
        if self.output_format not in {"source", "pptx", "pdf", "all"}:
            raise PresentationValidationError("output_format must be source, pptx, pdf, or all")
        return PresentationOptions(
            audience=audience,
            purpose=purpose,
            language=language,
            slide_count=self.slide_count,
            output_format=self.output_format,
            allow_incomplete_research=self.allow_incomplete_research,
        )


@dataclass(frozen=True)
class EvidenceClaim:
    claim_id: str
    kind: str
    text: str
    source_ids: tuple[str, ...]
    confidence: str = "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "kind": self.kind,
            "text": self.text,
            "source_ids": list(self.source_ids),
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class EvidenceCatalog:
    claims: tuple[EvidenceClaim, ...]
    sources: tuple[dict[str, Any], ...]
    unresolved_items: tuple[str, ...]
    conclusion: str
    recommended_next_actions: tuple[str, ...]

    @classmethod
    def from_research(cls, research: dict[str, Any]) -> "EvidenceCatalog":
        claims: list[EvidenceClaim] = []
        for prefix, key, kind in (("F", "verified_facts", "verified_fact"), ("I", "inferences", "inference")):
            raw_items = research.get(key, [])
            if not isinstance(raw_items, list):
                continue
            for index, item in enumerate(raw_items, start=1):
                if not isinstance(item, dict):
                    continue
                text = str(item.get("claim", "")).strip()
                raw_source_ids = item.get("source_ids", [])
                source_ids = tuple(
                    source_id
                    for source_id in raw_source_ids
                    if isinstance(source_id, str) and source_id.strip()
                ) if isinstance(raw_source_ids, list) else ()
                if text and source_ids:
                    confidence = str(item.get("confidence", "low")).strip().lower()
                    if confidence not in {"low", "medium", "high"}:
                        confidence = "low"
                    claims.append(EvidenceClaim(f"{prefix}{index}", kind, text, source_ids, confidence))

        sources: list[dict[str, Any]] = []
        for source in research.get("sources", []):
            if not isinstance(source, dict):
                continue
            source_id = str(source.get("source_id", "")).strip()
            url = str(source.get("url", "")).strip()
            if not source_id or not url:
                continue
            sources.append(
                {
                    "source_id": source_id,
                    "title": str(source.get("title", "")).strip() or source_id,
                    "url": url,
                    "fetch_status": str(source.get("fetch_status", "")).strip(),
                }
            )

        unresolved = research.get("unresolved_items", [])
        unresolved_items = tuple(str(item).strip() for item in unresolved if str(item).strip()) if isinstance(unresolved, list) else ()
        actions = research.get("recommended_next_actions", [])
        recommended = tuple(str(item).strip() for item in actions if str(item).strip()) if isinstance(actions, list) else ()
        return cls(
            claims=tuple(claims),
            sources=tuple(sources),
            unresolved_items=unresolved_items,
            conclusion=str(research.get("conclusion", "")).strip(),
            recommended_next_actions=recommended,
        )

    @property
    def claim_map(self) -> dict[str, EvidenceClaim]:
        return {claim.claim_id: claim for claim in self.claims}

    @property
    def source_map(self) -> dict[str, dict[str, Any]]:
        return {str(source["source_id"]): source for source in self.sources}

    def to_prompt_payload(self) -> dict[str, Any]:
        return {
            "claims": [claim.to_dict() for claim in self.claims],
            "unresolved_items": list(self.unresolved_items),
            "conclusion": self.conclusion,
            "recommended_next_actions": list(self.recommended_next_actions),
        }


def research_is_presentable(research: dict[str, Any], allow_incomplete: bool = False) -> tuple[bool, str]:
    status = str(research.get("status", ""))
    if status in {"researched_with_sources", "researched_cleaned_and_verified"}:
        catalog = EvidenceCatalog.from_research(research)
        if catalog.claims:
            return True, "research evidence available"
        return False, "research status is complete but contains no source-backed claims"
    if allow_incomplete and status in {"research_completed_no_usable_sources", "dry_run_not_researched"}:
        return True, f"incomplete research explicitly allowed: {status}"
    return False, f"research status is not presentation-ready: {status or 'missing'}"


def build_dry_run_plan(task_title: str, task_request: str, options: PresentationOptions) -> dict[str, Any]:
    options = options.normalized()
    return {
        "schema_version": "presentation-plan/v1",
        "title": task_title,
        "subtitle": "DRY RUN — no verified research content",
        "audience": options.audience,
        "purpose": options.purpose,
        "language": options.language,
        "slides": [
            {
                "slide_id": "P01",
                "kind": "title",
                "title": task_title,
                "claim_refs": [],
                "proposal_points": [],
                "context_points": [task_request],
                "speaker_notes": "Dry-run template. No factual claims are presented.",
            },
            {
                "slide_id": "P02",
                "kind": "content",
                "title": "Research input required",
                "claim_refs": [],
                "proposal_points": [],
                "context_points": ["Run Agent 1 in live mode before creating a factual presentation."],
                "speaker_notes": "This slide intentionally contains no external factual claim.",
            },
            {
                "slide_id": "P03",
                "kind": "decision",
                "title": "Next action",
                "claim_refs": [],
                "proposal_points": ["Complete source-backed research, then rerun Presentation Agent in live mode."],
                "context_points": [],
                "speaker_notes": "Dry-run next action only.",
            },
        ],
    }


def _clean_strings(value: Any, limit: int = 8) -> list[str]:
    if not isinstance(value, list):
        return []
    cleaned: list[str] = []
    for item in value:
        text = " ".join(str(item).split())
        if text and text not in cleaned:
            cleaned.append(text)
    return cleaned[:limit]


def normalize_plan(
    raw_plan: dict[str, Any],
    catalog: EvidenceCatalog,
    options: PresentationOptions,
    task_title: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    options = options.normalized()
    claim_map = catalog.claim_map
    allowed_kinds = {"title", "content", "comparison", "risks", "decision", "timeline", "summary"}
    raw_slides = raw_plan.get("slides")
    if not isinstance(raw_slides, list) or not raw_slides:
        raise PresentationValidationError("presentation plan must contain a non-empty slides array")

    slides: list[dict[str, Any]] = []
    errors: list[str] = []
    warnings: list[str] = []
    seen_titles: set[str] = set()
    referenced_claims: set[str] = set()

    for index, raw_slide in enumerate(raw_slides[: max(2, options.slide_count - 1)], start=1):
        if not isinstance(raw_slide, dict):
            errors.append(f"slide {index}: must be an object")
            continue
        kind = str(raw_slide.get("kind", "content")).strip().lower()
        if kind not in allowed_kinds:
            warnings.append(f"slide {index}: unknown kind '{kind}' normalized to content")
            kind = "content"
        title = " ".join(str(raw_slide.get("title", "")).split())
        if not title:
            errors.append(f"slide {index}: title is required")
            continue
        if title in seen_titles:
            errors.append(f"slide {index}: duplicate title '{title}'")
        seen_titles.add(title)

        raw_refs = raw_slide.get("claim_refs", [])
        claim_refs: list[str] = []
        if isinstance(raw_refs, list):
            for ref in raw_refs:
                if not isinstance(ref, str):
                    continue
                ref = ref.strip()
                if ref not in claim_map:
                    errors.append(f"slide {index}: unknown claim reference '{ref}'")
                    continue
                if ref not in claim_refs:
                    claim_refs.append(ref)
        if len(claim_refs) > 4:
            warnings.append(f"slide {index}: claim_refs truncated to 4 for readability")
            claim_refs = claim_refs[:4]
        referenced_claims.update(claim_refs)

        proposals = _clean_strings(raw_slide.get("proposal_points"), limit=2)
        contexts = _clean_strings(raw_slide.get("context_points"), limit=2)
        if len(claim_refs) + len(proposals) + len(contexts) > 6:
            errors.append(f"slide {index}: more than 6 visible content items")
        if not claim_refs and not proposals and not contexts and kind != "title":
            errors.append(f"slide {index}: has no content")

        notes = " ".join(str(raw_slide.get("speaker_notes", "")).split())
        if len(notes) > 1200:
            notes = notes[:1200].rstrip() + "…"
            warnings.append(f"slide {index}: speaker_notes truncated")

        source_ids: list[str] = []
        claim_items: list[dict[str, Any]] = []
        for ref in claim_refs:
            claim = claim_map[ref]
            claim_items.append(claim.to_dict())
            for source_id in claim.source_ids:
                if source_id not in source_ids:
                    source_ids.append(source_id)

        slides.append(
            {
                "slide_id": f"P{index:02d}",
                "kind": kind,
                "title": title,
                "claim_refs": claim_refs,
                "claims": claim_items,
                "proposal_points": proposals,
                "context_points": contexts,
                "source_ids": source_ids,
                "speaker_notes": notes,
            }
        )

    if errors:
        raise PresentationValidationError("; ".join(errors))

    source_lines: list[str] = []
    used_source_ids: list[str] = []
    for slide in slides:
        for source_id in slide["source_ids"]:
            if source_id not in used_source_ids:
                used_source_ids.append(source_id)
    for source_id in used_source_ids:
        source = catalog.source_map.get(source_id)
        if source:
            source_lines.append(f"[{source_id}] {source['title']} — {source['url']}")

    appendix_base = {"ja": "出典", "en": "Sources", "vi": "Nguồn"}[options.language]
    if not source_lines:
        source_lines = ["No source URL was referenced by the selected claims."]
    for offset in range(0, len(source_lines), 5):
        chunk = source_lines[offset : offset + 5]
        part = offset // 5 + 1
        title = appendix_base if part == 1 else f"{appendix_base} ({part})"
        if title in seen_titles:
            title += " — Appendix"
        seen_titles.add(title)
        slides.append(
            {
                "slide_id": f"P{len(slides)+1:02d}",
                "kind": "sources",
                "title": title,
                "claim_refs": [],
                "claims": [],
                "proposal_points": [],
                "context_points": chunk,
                "source_ids": used_source_ids[offset : offset + 5],
                "speaker_notes": "Source appendix generated deterministically from Agent 1 evidence.",
            }
        )

    if catalog.unresolved_items:
        limitation_title = {"ja": "未解決事項・制約", "en": "Open issues & limitations", "vi": "Vấn đề chưa giải quyết & giới hạn"}[options.language]
        if limitation_title in seen_titles:
            limitation_title += " — Appendix"
        slides.append(
            {
                "slide_id": f"P{len(slides)+1:02d}",
                "kind": "limitations",
                "title": limitation_title,
                "claim_refs": [],
                "claims": [],
                "proposal_points": [f"LIMITATION: {item}" for item in catalog.unresolved_items[:5]],
                "context_points": [],
                "source_ids": [],
                "speaker_notes": "Limitations are copied from Agent 1 unresolved evidence, not invented by Agent 2.",
            }
        )

    coverage = 0.0 if not claim_map else round(len(referenced_claims) / len(claim_map), 3)
    qa = {
        "schema_version": "presentation-qa/v1",
        "status": "pass",
        "errors": [],
        "warnings": warnings,
        "unique_titles": len({slide["title"] for slide in slides}) == len(slides),
        "visible_facts_source_bounded": True,
        "referenced_claim_count": len(referenced_claims),
        "available_claim_count": len(claim_map),
        "evidence_coverage_ratio": coverage,
        "source_appendix_present": True,
        "accessibility": {
            "unique_slide_titles": True,
            "deterministic_reading_order": True,
            "minimum_body_font_target_pt": 20,
            "color_only_meaning": False,
        },
    }
    plan = {
        "schema_version": "presentation-plan/v1",
        "title": " ".join(str(raw_plan.get("title", task_title)).split()) or task_title,
        "subtitle": " ".join(str(raw_plan.get("subtitle", "")).split()),
        "audience": options.audience,
        "purpose": options.purpose,
        "language": options.language,
        "slides": slides,
    }
    return plan, qa


def render_markdown(plan: dict[str, Any], qa: dict[str, Any]) -> str:
    lines = [
        f"# {plan['title']}",
        "",
        f"**Audience:** {plan['audience']}  ",
        f"**Purpose:** {plan['purpose']}  ",
        f"**Language:** `{plan['language']}`  ",
        f"**QA:** `{qa['status']}`",
        "",
    ]
    if plan.get("subtitle"):
        lines.extend([plan["subtitle"], ""])
    for index, slide in enumerate(plan["slides"], start=1):
        lines.extend([f"## Slide {index}: {slide['title']}", ""])
        for claim in slide.get("claims", []):
            label = "FACT" if claim["kind"] == "verified_fact" else "INFERENCE"
            refs = ", ".join(claim["source_ids"])
            lines.append(f"- **{label} {claim['claim_id']}**: {claim['text']} — [{refs}]")
        for item in slide.get("context_points", []):
            lines.append(f"- {item}")
        for item in slide.get("proposal_points", []):
            lines.append(f"- **PROPOSAL/LIMITATION:** {item}")
        if slide.get("speaker_notes"):
            lines.extend(["", f"_Speaker notes:_ {slide['speaker_notes']}"])
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
