from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .runtime_efficiency import sanitize_untrusted_payload


class PresentationValidationError(ValueError):
    """Raised when model output or presentation input violates the deterministic contract."""


PRESENTATION_OUTPUT_SANITIZER_VERSION = "workspace-presentation-output-sanitizer/v1"
_RISK_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class PresentationOptions:
    audience: str = "R&D internal"
    purpose: str = "inform"
    language: str = "ja"
    slide_count: int = 6
    output_format: str = "source"

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
    conflicts: tuple[dict[str, Any], ...]
    unresolved_items: tuple[str, ...]
    conclusion: str
    recommended_next_actions: tuple[str, ...]

    @staticmethod
    def _confidence(value: Any) -> str:
        value = str(value or "low").strip().lower()
        return value if value in {"low", "medium", "high"} else "low"

    @staticmethod
    def _source_ids(value: Any) -> tuple[str, ...]:
        if not isinstance(value, list):
            return ()
        return tuple(dict.fromkeys(
            item.strip() for item in value
            if isinstance(item, str) and item.strip()
        ))

    @classmethod
    def from_handoff(cls, handoff: dict[str, Any]) -> "EvidenceCatalog":
        """Build the Agent-2 evidence catalog from Agent-1 handoff schema 1.0."""
        claims: list[EvidenceClaim] = []
        key_facts = handoff.get("key_facts", [])
        if isinstance(key_facts, list):
            for index, item in enumerate(key_facts, start=1):
                if not isinstance(item, dict):
                    continue
                claim_id = str(item.get("fact_id") or f"F{index:03d}").strip()
                text = str(item.get("claim", "")).strip()
                source_ids = cls._source_ids(item.get("source_ids"))
                if claim_id and text and source_ids:
                    claims.append(EvidenceClaim(
                        claim_id=claim_id,
                        kind="verified_fact",
                        text=text,
                        source_ids=source_ids,
                        confidence=cls._confidence(item.get("confidence")),
                    ))

        inferences = handoff.get("inferences", [])
        if isinstance(inferences, list):
            for index, item in enumerate(inferences, start=1):
                if not isinstance(item, dict):
                    continue
                text = str(item.get("claim", "")).strip()
                source_ids = cls._source_ids(item.get("source_ids"))
                if text and source_ids:
                    claims.append(EvidenceClaim(
                        claim_id=f"I{index:03d}",
                        kind="inference",
                        text=text,
                        source_ids=source_ids,
                        confidence=cls._confidence(item.get("confidence")),
                    ))

        sources: list[dict[str, Any]] = []
        raw_sources = handoff.get("sources", [])
        if isinstance(raw_sources, list):
            for source in raw_sources:
                if not isinstance(source, dict):
                    continue
                source_id = str(source.get("source_id", "")).strip()
                url = str(source.get("url", "")).strip()
                if not source_id or not url:
                    continue
                sources.append({
                    "source_id": source_id,
                    "title": str(source.get("title", "")).strip() or source_id,
                    "url": url,
                    "fetch_status": str(source.get("fetch_status", "")).strip(),
                })

        conflicts = handoff.get("conflicts", [])
        clean_conflicts = tuple(item for item in conflicts if isinstance(item, dict)) if isinstance(conflicts, list) else ()
        unresolved = handoff.get("unresolved_items", [])
        unresolved_items = tuple(" ".join(str(item).split()) for item in unresolved if str(item).strip()) if isinstance(unresolved, list) else ()
        actions = handoff.get("recommended_next_actions", [])
        recommended = tuple(" ".join(str(item).split()) for item in actions if str(item).strip()) if isinstance(actions, list) else ()
        return cls(
            claims=tuple(claims),
            sources=tuple(sources),
            conflicts=clean_conflicts,
            unresolved_items=unresolved_items,
            conclusion=" ".join(str(handoff.get("conclusion", "")).split()),
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
            "conflicts": list(self.conflicts),
            "unresolved_items": list(self.unresolved_items),
            "conclusion": self.conclusion,
            "recommended_next_actions": list(self.recommended_next_actions),
        }


def handoff_is_presentable(handoff: dict[str, Any]) -> tuple[bool, str]:
    if handoff.get("schema_version") != "1.0":
        return False, "UNSUPPORTED_HANDOFF_SCHEMA"
    if handoff.get("presentation_ready") is not True:
        blockers = handoff.get("blockers") or ["UNKNOWN_RESEARCH_BLOCKER"]
        return False, "RESEARCH_HANDOFF_BLOCKED:" + ",".join(str(x) for x in blockers)
    catalog = EvidenceCatalog.from_handoff(handoff)
    if not any(claim.kind == "verified_fact" for claim in catalog.claims):
        return False, "HANDOFF_HAS_NO_KEY_FACTS"
    return True, "presentation-ready handoff"


def build_dry_run_plan(task_title: str, task_request: str, options: PresentationOptions, catalog: EvidenceCatalog) -> dict[str, Any]:
    options = options.normalized()
    facts = [claim for claim in catalog.claims if claim.kind == "verified_fact"][:3]
    raw = {
        "title": task_title,
        "subtitle": "DRY RUN — deterministic evidence layout",
        "slides": [
            {"kind": "title", "title": task_title, "claim_refs": [], "proposal_points": [], "context_points": [task_request], "speaker_notes": "Dry-run layout. No LLM planning was used."},
            {"kind": "content", "title": {"ja": "確認済みの要点", "en": "Verified highlights", "vi": "Các điểm đã xác minh"}[options.language], "claim_refs": [claim.claim_id for claim in facts], "proposal_points": [], "context_points": [], "speaker_notes": "Facts are copied exactly from the Agent 1 handoff."},
            {"kind": "decision", "title": {"ja": "次のアクション", "en": "Next action", "vi": "Hành động tiếp theo"}[options.language], "claim_refs": [], "proposal_points": list(catalog.recommended_next_actions[:2]) or [{"ja": "必要に応じて発表目的に合わせてライブ生成を実行する。", "en": "Run live presentation planning when audience-specific narrative is required.", "vi": "Chạy lập kế hoạch live khi cần nội dung phù hợp đối tượng cụ thể."}[options.language]], "context_points": [], "speaker_notes": "Dry-run recommendation only."},
        ],
    }
    plan, _ = normalize_plan(raw, catalog, options, task_title)
    return plan


def _clean_strings(value: Any, limit: int = 8) -> list[str]:
    if not isinstance(value, list):
        return []
    cleaned: list[str] = []
    for item in value:
        text = " ".join(str(item).split())
        if text and text not in cleaned:
            cleaned.append(text)
    return cleaned[:limit]


def _presentation_output_security(findings: tuple[dict[str, Any], ...]) -> dict[str, Any]:
    risks = [str(item.get("risk", "low")) for item in findings]
    max_risk = max(risks, key=lambda value: _RISK_ORDER.get(value, -1), default="low")
    signal_types = sorted({
        str(signal)
        for item in findings
        for signal in item.get("signals", [])
        if isinstance(signal, str) and signal
    })
    safe_findings = [
        {
            "path": str(item.get("path", "")),
            "risk": str(item.get("risk", "low")),
            "signals": [
                str(signal)
                for signal in item.get("signals", [])
                if isinstance(signal, str) and signal
            ],
        }
        for item in findings
    ]
    return {
        "sanitizer_version": PRESENTATION_OUTPUT_SANITIZER_VERSION,
        "source": "presentation_plan_input",
        "destination": "presentation_exports",
        "trust_classification": "untrusted_model_output",
        "authorization_effect": "none",
        "max_risk": max_risk,
        "finding_count": len(safe_findings),
        "signal_types": signal_types,
        "findings": safe_findings,
    }


def normalize_plan(raw_plan: dict[str, Any], catalog: EvidenceCatalog, options: PresentationOptions, task_title: str) -> tuple[dict[str, Any], dict[str, Any]]:
    options = options.normalized()
    sanitized_raw, sanitizer_findings = sanitize_untrusted_payload(raw_plan)
    if not isinstance(sanitized_raw, dict):
        raise PresentationValidationError("presentation plan must sanitize to an object")
    raw_plan = sanitized_raw
    output_security = _presentation_output_security(sanitizer_findings)

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

    for index, raw_slide in enumerate(raw_slides[:max(2, options.slide_count)], start=1):
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

        refs: list[str] = []
        raw_refs = raw_slide.get("claim_refs", [])
        if isinstance(raw_refs, list):
            for ref in raw_refs:
                if not isinstance(ref, str):
                    continue
                ref = ref.strip()
                if ref not in claim_map:
                    errors.append(f"slide {index}: unknown claim reference '{ref}'")
                    continue
                if ref not in refs:
                    refs.append(ref)
        if len(refs) > 4:
            warnings.append(f"slide {index}: claim_refs truncated to 4 for readability")
            refs = refs[:4]
        proposals = _clean_strings(raw_slide.get("proposal_points"), limit=2)
        contexts = _clean_strings(raw_slide.get("context_points"), limit=2)
        visible_count = len(refs) + len(proposals) + len(contexts)
        if visible_count > 6:
            errors.append(f"slide {index}: more than 6 visible content items")
        if visible_count == 0 and kind != "title":
            errors.append(f"slide {index}: has no content")
        notes = " ".join(str(raw_slide.get("speaker_notes", "")).split())
        if len(notes) > 1200:
            notes = notes[:1200].rstrip() + "…"
            warnings.append(f"slide {index}: speaker_notes truncated")

        source_ids: list[str] = []
        materialized: list[dict[str, Any]] = []
        for ref in refs:
            claim = claim_map[ref]
            materialized.append(claim.to_dict())
            referenced_claims.add(ref)
            for source_id in claim.source_ids:
                if source_id not in source_ids:
                    source_ids.append(source_id)
        slides.append({"slide_id": f"P{index:02d}", "kind": kind, "title": title, "claim_refs": refs, "claims": materialized, "proposal_points": proposals, "context_points": contexts, "source_ids": source_ids, "speaker_notes": notes})

    if errors:
        raise PresentationValidationError("; ".join(errors))
    verified_refs = {ref for ref in referenced_claims if claim_map[ref].kind == "verified_fact"}
    if not verified_refs:
        raise PresentationValidationError("presentation must reference at least one verified fact")

    used_source_ids: list[str] = []
    for slide in slides:
        for source_id in slide["source_ids"]:
            if source_id not in used_source_ids:
                used_source_ids.append(source_id)
    source_lines: list[str] = []
    for source_id in used_source_ids:
        source = catalog.source_map.get(source_id)
        if source:
            source_lines.append(f"[{source_id}] {source['title']} — {source['url']}")

    appendix_title = {"ja": "出典", "en": "Sources", "vi": "Nguồn"}[options.language]
    if not source_lines:
        source_lines = [{"ja": "選択された主張に対応する出典URLはありません。", "en": "No source URL was referenced by the selected claims.", "vi": "Không có URL nguồn nào được tham chiếu bởi các luận điểm đã chọn."}[options.language]]
    for offset in range(0, len(source_lines), 4):
        part = offset // 4 + 1
        title = appendix_title if part == 1 else f"{appendix_title} ({part})"
        if title in seen_titles:
            title += " — Appendix"
        seen_titles.add(title)
        slides.append({"slide_id": f"P{len(slides)+1:02d}", "kind": "sources", "title": title, "claim_refs": [], "claims": [], "proposal_points": [], "context_points": source_lines[offset:offset+4], "source_ids": used_source_ids[offset:offset+4], "speaker_notes": "Source appendix generated deterministically from Agent 1 evidence."})

    limitations: list[str] = list(catalog.unresolved_items)
    for conflict in catalog.conflicts:
        severity = str(conflict.get("severity", "medium")).upper()
        topic = " ".join(str(conflict.get("topic", "")).split())
        description = " ".join(str(conflict.get("description", "")).split())
        if topic or description:
            limitations.append(f"CONFLICT[{severity}] {topic}: {description}".strip(": "))
    if limitations:
        title = {"ja": "未解決事項・制約", "en": "Open issues & limitations", "vi": "Vấn đề chưa giải quyết & giới hạn"}[options.language]
        if title in seen_titles:
            title += " — Appendix"
        slides.append({"slide_id": f"P{len(slides)+1:02d}", "kind": "limitations", "title": title, "claim_refs": [], "claims": [], "proposal_points": [f"LIMITATION: {item}" for item in limitations[:5]], "context_points": [], "source_ids": [], "speaker_notes": "Limitations/conflicts originate from Agent 1 handoff."})

    unique_titles = len({slide["title"] for slide in slides}) == len(slides)
    if not unique_titles:
        raise PresentationValidationError("appendix/title generation produced duplicate slide titles")
    coverage = 0.0 if not claim_map else round(len(referenced_claims) / len(claim_map), 3)
    qa = {
        "schema_version": "presentation-qa/v1", "status": "pass", "errors": [], "warnings": warnings,
        "unique_titles": unique_titles, "visible_facts_source_bounded": True,
        "referenced_claim_count": len(referenced_claims), "referenced_verified_fact_count": len(verified_refs),
        "available_claim_count": len(claim_map), "evidence_coverage_ratio": coverage,
        "source_appendix_present": any(slide["kind"] == "sources" for slide in slides), "limitations_visible": bool(limitations),
        "output_security": output_security,
        "accessibility": {"unique_slide_titles": unique_titles, "title_placeholders_required": True, "deterministic_reading_order": True, "minimum_body_font_target_pt": 20, "color_only_meaning": False},
    }
    plan = {"schema_version": "presentation-plan/v1", "title": " ".join(str(raw_plan.get("title", task_title)).split()) or task_title, "subtitle": " ".join(str(raw_plan.get("subtitle", "")).split()), "audience": options.audience, "purpose": options.purpose, "language": options.language, "slides": slides}
    return plan, qa


def render_markdown(plan: dict[str, Any], qa: dict[str, Any]) -> str:
    labels = {
        "ja": {"fact": "事実", "inference": "推論", "proposal": "提案・制約", "context": "文脈"},
        "en": {"fact": "FACT", "inference": "INFERENCE", "proposal": "PROPOSAL / LIMITATION", "context": "CONTEXT"},
        "vi": {"fact": "SỰ KIỆN", "inference": "SUY LUẬN", "proposal": "ĐỀ XUẤT / GIỚI HẠN", "context": "BỐI CẢNH"},
    }[plan["language"]]
    lines = [f"# {plan['title']}", "", f"**Audience:** {plan['audience']}  ", f"**Purpose:** {plan['purpose']}  ", f"**Language:** `{plan['language']}`  ", f"**QA:** `{qa['status']}`", ""]
    if plan.get("subtitle"):
        lines.extend([plan["subtitle"], ""])
    for index, slide in enumerate(plan["slides"], start=1):
        lines.extend([f"## Slide {index}: {slide['title']}", ""])
        for claim in slide.get("claims", []):
            label = labels["fact"] if claim["kind"] == "verified_fact" else labels["inference"]
            refs = ", ".join(claim["source_ids"])
            lines.append(f"- **{label} {claim['claim_id']}**: {claim['text']} [{refs}]")
        for item in slide.get("context_points", []):
            lines.append(f"- **{labels['context']}**: {item}")
        for item in slide.get("proposal_points", []):
            lines.append(f"- **{labels['proposal']}**: {item}")
        if slide.get("speaker_notes"):
            lines.extend(["", f"_Notes: {slide['speaker_notes']}_"])
        lines.append("")
    lines.extend(["## QA", "", f"- Evidence coverage: {qa['evidence_coverage_ratio']}", f"- Source bounded: {qa['visible_facts_source_bounded']}", f"- Unique titles: {qa['unique_titles']}"])
    return "\n".join(lines)
