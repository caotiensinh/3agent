from __future__ import annotations

import re
from typing import Any

from .evidence_packing import PACKING_RECEIPT_SCHEMA
from .handoff_security import build_handoff_security_metadata
from .runtime_efficiency import sanitize_untrusted_payload


_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}
_UNCITED_REJECTION_PREFIXES = (
    "Uncited model claim rejected:",
    "Uncited model inference rejected:",
)
_SYNTHESIS_CONTEXT_MAX_CHARS = 48000
_CONTEXT_PROXY_KIND = "source_level_citation_char_proxy"
_CONTEXT_PROXY_SCOPE = "research_synthesis_only"
_CONTEXT_RECALL_PROXY_KIND = "vetted_source_char_retention_proxy"
_CONTEXT_RECALL_PROXY_SCOPE = "research_synthesis_context_budget"


def _clean_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _claim_key(value: str) -> str:
    value = value.casefold()
    value = re.sub(r"[^\w\s]", " ", value, flags=re.UNICODE)
    return re.sub(r"\s+", " ", value).strip()


def confidence_for_sources(source_ids: list[str]) -> str:
    unique = list(dict.fromkeys(source_ids))
    if len(unique) >= 2:
        return "high"
    if len(unique) == 1:
        return "medium"
    return "low"


def _clean_evidence_quotes(value: Any, source_ids: list[str]) -> list[dict]:
    cleaned: list[dict] = []
    seen: set[tuple[str, str]] = set()
    if not isinstance(value, list):
        return cleaned
    allowed = set(source_ids)
    for item in value:
        if not isinstance(item, dict):
            continue
        source_id = _clean_text(item.get("source_id"))
        quote = _clean_text(item.get("quote"))
        if source_id not in allowed or not quote:
            continue
        key = (source_id, quote.casefold())
        if key in seen:
            continue
        seen.add(key)
        cleaned.append({"source_id": source_id, "quote": quote[:500]})
    return cleaned


def clean_claims(items: Any, valid_source_ids: set[str]) -> tuple[list[dict], list[str]]:
    """Normalize, deduplicate and reject unsupported claims.

    The function is intentionally deterministic. The model may propose claims, but
    only claims with collected source IDs can pass through this gate. Optional
    evidence_quotes are retained for later verbatim/numerical validation.
    """
    accepted_by_key: dict[str, dict] = {}
    rejected: list[str] = []
    if not isinstance(items, list):
        return [], rejected

    for item in items:
        if isinstance(item, str):
            claim = _clean_text(item)
            raw_ids: list[str] = []
            raw_quotes: Any = []
        elif isinstance(item, dict):
            claim = _clean_text(item.get("claim"))
            raw = item.get("source_ids", [])
            raw_ids = [sid for sid in raw if isinstance(sid, str)] if isinstance(raw, list) else []
            raw_quotes = item.get("evidence_quotes", [])
        else:
            continue

        if not claim:
            continue
        source_ids = list(dict.fromkeys(sid for sid in raw_ids if sid in valid_source_ids))
        if not source_ids:
            rejected.append(claim)
            continue

        key = _claim_key(claim)
        if not key:
            continue
        candidate = {
            "claim": claim,
            "source_ids": source_ids,
            "confidence": confidence_for_sources(source_ids),
            "evidence_quotes": _clean_evidence_quotes(raw_quotes, source_ids),
        }
        current = accepted_by_key.get(key)
        if current is None:
            accepted_by_key[key] = candidate
            continue

        merged_ids = list(dict.fromkeys(current["source_ids"] + source_ids))
        current["source_ids"] = merged_ids
        current["confidence"] = confidence_for_sources(merged_ids)
        current_quotes = current.get("evidence_quotes", []) + candidate.get("evidence_quotes", [])
        current["evidence_quotes"] = _clean_evidence_quotes(current_quotes, merged_ids)

    return list(accepted_by_key.values()), rejected


def clean_conflicts(items: Any, valid_source_ids: set[str]) -> list[dict]:
    cleaned: list[dict] = []
    seen: set[str] = set()
    if not isinstance(items, list):
        return cleaned

    for item in items:
        if not isinstance(item, dict):
            continue
        topic = _clean_text(item.get("topic"))
        description = _clean_text(item.get("description"))
        severity = _clean_text(item.get("severity")).lower()
        if severity not in {"low", "medium", "critical"}:
            severity = "medium"
        raw = item.get("source_ids", [])
        source_ids = list(
            dict.fromkeys(sid for sid in raw if isinstance(sid, str) and sid in valid_source_ids)
        ) if isinstance(raw, list) else []
        if not topic or not description or len(source_ids) < 2:
            continue
        key = _claim_key(f"{topic} {description}")
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(
            {
                "topic": topic,
                "description": description,
                "severity": severity,
                "source_ids": source_ids,
            }
        )
    return cleaned


def source_refs(sources: list[dict]) -> list[dict]:
    """Return compact source metadata without raw page text for downstream agents."""
    refs: list[dict] = []
    for source in sources:
        refs.append(
            {
                "source_id": source.get("source_id"),
                "title": _clean_text(source.get("title")),
                "url": _clean_text(source.get("url")),
                "fetch_status": source.get("fetch_status"),
            }
        )
    return refs


def evidence_claim_accounting(research: dict) -> dict[str, int | float | None]:
    """Derive D3-05 claim coverage from deterministic Research gate outcomes."""
    verified = research.get("verified_facts")
    inferences = research.get("inferences")
    unresolved = research.get("unresolved_items")
    rejected_numeric = research.get("rejected_numeric_claims")

    supported = (
        len(verified) if isinstance(verified, list) else 0
    ) + (
        len(inferences) if isinstance(inferences, list) else 0
    )
    uncited_rejected = 0
    if isinstance(unresolved, list):
        for item in unresolved:
            text = str(item)
            if any(text.startswith(prefix) for prefix in _UNCITED_REJECTION_PREFIXES):
                uncited_rejected += 1
    numeric_rejected = len(rejected_numeric) if isinstance(rejected_numeric, list) else 0
    unsupported = uncited_rejected + numeric_rejected
    required = supported + unsupported
    coverage = round(supported / required, 6) if required else None
    return {
        "material_claims_requiring_evidence": required,
        "evidence_supported_material_claims": supported,
        "unsupported_material_claims": unsupported,
        "uncited_rejected_material_claims": uncited_rejected,
        "quantitative_rejected_material_claims": numeric_rejected,
        "evidence_coverage": coverage,
    }


def _non_negative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"PACKING_RECEIPT_INVALID_{field.upper()}")
    return value


def _cited_source_ids(research: dict) -> set[str]:
    cited_ids: set[str] = set()
    for key in ("verified_facts", "inferences", "conflicts"):
        items = research.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            source_ids = item.get("source_ids")
            if not isinstance(source_ids, list):
                continue
            cited_ids.update(str(source_id) for source_id in source_ids if isinstance(source_id, str))
    return cited_ids


def _receipt_context_accounting(research: dict) -> dict[str, Any] | None:
    """Consume authoritative packing metadata when a v1 receipt is present.

    Complete absence means a legacy artifact and is handled by the historical
    reconstruction path. Partial, inconsistent or tampered receipt metadata fails
    closed so context-retention metrics cannot silently become optimistic.
    """
    raw_assessments = research.get("source_assessments")
    assessments = raw_assessments if isinstance(raw_assessments, list) else []
    accepted = [
        item
        for item in assessments
        if isinstance(item, dict)
        and item.get("relevance") in {"high", "medium"}
        and item.get("scope_match") is True
    ]
    receipt_items = [
        item for item in accepted if item.get("synthesis_packing_receipt_version") is not None
    ]
    if not receipt_items:
        return None
    if len(receipt_items) != len(accepted):
        raise ValueError("PACKING_RECEIPT_INCOMPLETE")

    raw_sources = research.get("sources")
    sources = raw_sources if isinstance(raw_sources, list) else []
    source_text_chars = {
        str(source.get("source_id") or ""): len(str(source.get("extracted_text") or ""))
        for source in sources
        if isinstance(source, dict)
        and source.get("fetch_status") == "ok"
        and source.get("extracted_text")
    }

    budget: int | None = None
    mode: str | None = None
    seen: set[str] = set()
    vetted_text_chars = 0
    supplied_text_chars = 0
    supplied_source_ids: set[str] = set()
    cited_source_ids: set[str] = set()
    cited_text_chars = 0
    cited = _cited_source_ids(research)

    for item in receipt_items:
        source_id = str(item.get("source_id") or "")
        if not source_id or source_id in seen:
            raise ValueError("PACKING_RECEIPT_SOURCE_ID_INVALID")
        seen.add(source_id)
        if item.get("synthesis_packing_receipt_version") != PACKING_RECEIPT_SCHEMA:
            raise ValueError("PACKING_RECEIPT_SCHEMA_UNSUPPORTED")

        item_budget = _non_negative_int(
            item.get("synthesis_context_budget_chars"), "context_budget_chars"
        )
        item_mode = str(item.get("synthesis_packing_mode") or "")
        if not item_mode:
            raise ValueError("PACKING_RECEIPT_MODE_INVALID")
        if budget is None:
            budget = item_budget
        elif budget != item_budget:
            raise ValueError("PACKING_RECEIPT_BUDGET_MISMATCH")
        if mode is None:
            mode = item_mode
        elif mode != item_mode:
            raise ValueError("PACKING_RECEIPT_MODE_MISMATCH")

        vetted = _non_negative_int(item.get("synthesis_vetted_text_chars"), "vetted_text_chars")
        supplied = _non_negative_int(
            item.get("synthesis_supplied_text_chars"), "supplied_text_chars"
        )
        if supplied > vetted:
            raise ValueError("PACKING_RECEIPT_SUPPLIED_EXCEEDS_VETTED")
        if source_id not in source_text_chars or source_text_chars[source_id] != vetted:
            raise ValueError("PACKING_RECEIPT_SOURCE_LENGTH_MISMATCH")
        supplied_flag = item.get("synthesis_supplied")
        if not isinstance(supplied_flag, bool) or supplied_flag != (supplied > 0):
            raise ValueError("PACKING_RECEIPT_SUPPLIED_FLAG_MISMATCH")

        vetted_text_chars += vetted
        supplied_text_chars += supplied
        if supplied > 0:
            supplied_source_ids.add(source_id)
            if source_id in cited:
                cited_source_ids.add(source_id)
                cited_text_chars += supplied

    return {
        "context_precision_proxy_kind": _CONTEXT_PROXY_KIND,
        "context_precision_proxy_scope": _CONTEXT_PROXY_SCOPE,
        "context_recall_proxy_kind": _CONTEXT_RECALL_PROXY_KIND,
        "context_recall_proxy_scope": _CONTEXT_RECALL_PROXY_SCOPE,
        "synthesis_context_budget_chars": budget or 0,
        "synthesis_vetted_source_count": len(receipt_items),
        "synthesis_supplied_source_count": len(supplied_source_ids),
        "synthesis_cited_source_count": len(cited_source_ids),
        "synthesis_vetted_source_text_chars": vetted_text_chars,
        "synthesis_supplied_source_text_chars": supplied_text_chars,
        "synthesis_cited_source_text_chars": cited_text_chars,
        "context_precision_proxy": (
            round(cited_text_chars / supplied_text_chars, 6)
            if supplied_text_chars
            else None
        ),
        "context_recall_proxy": (
            round(supplied_text_chars / vetted_text_chars, 6)
            if vetted_text_chars
            else None
        ),
        "synthesis_packing_receipt_version": PACKING_RECEIPT_SCHEMA,
        "synthesis_packing_mode": mode,
    }


def synthesis_context_proxy_accounting(
    research: dict,
    *,
    max_total: int = _SYNTHESIS_CONTEXT_MAX_CHARS,
) -> dict[str, Any]:
    """Measure D3-06/D3-07 from receipt, with legacy-artifact fallback only."""
    if not isinstance(max_total, int) or isinstance(max_total, bool) or max_total < 0:
        raise ValueError("max_total must be a non-negative integer")

    base: dict[str, Any] = {
        "context_precision_proxy_kind": _CONTEXT_PROXY_KIND,
        "context_precision_proxy_scope": _CONTEXT_PROXY_SCOPE,
        "context_recall_proxy_kind": _CONTEXT_RECALL_PROXY_KIND,
        "context_recall_proxy_scope": _CONTEXT_RECALL_PROXY_SCOPE,
        "synthesis_context_budget_chars": max_total,
        "synthesis_vetted_source_count": 0,
        "synthesis_supplied_source_count": 0,
        "synthesis_cited_source_count": 0,
        "synthesis_vetted_source_text_chars": 0,
        "synthesis_supplied_source_text_chars": 0,
        "synthesis_cited_source_text_chars": 0,
        "context_precision_proxy": None,
        "context_recall_proxy": None,
    }
    if research.get("source_assessment_error"):
        return base

    receipt = _receipt_context_accounting(research)
    if receipt is not None:
        return receipt

    # Legacy artifact fallback: reconstruct the historical 48k packing behavior.
    raw_sources = research.get("sources")
    raw_assessments = research.get("source_assessments")
    sources = raw_sources if isinstance(raw_sources, list) else []
    assessments = raw_assessments if isinstance(raw_assessments, list) else []
    accepted_ids = {
        str(item.get("source_id") or "")
        for item in assessments
        if isinstance(item, dict)
        and item.get("relevance") in {"high", "medium"}
        and item.get("scope_match") is True
    }
    cited_ids = _cited_source_ids(research)

    vetted_sources: list[tuple[str, str, str, str]] = []
    vetted_source_ids: set[str] = set()
    vetted_text_chars = 0
    for source in sources:
        if not isinstance(source, dict):
            continue
        source_id = str(source.get("source_id") or "")
        if (
            source_id not in accepted_ids
            or source.get("fetch_status") != "ok"
            or not source.get("extracted_text")
        ):
            continue
        text = str(source.get("extracted_text") or "")
        vetted_sources.append(
            (
                source_id,
                str(source.get("title") or ""),
                str(source.get("url") or ""),
                text,
            )
        )
        vetted_source_ids.add(source_id)
        vetted_text_chars += len(text)

    total_chunk_chars = 0
    supplied_text_chars = 0
    cited_text_chars = 0
    supplied_source_ids: set[str] = set()
    cited_source_ids: set[str] = set()

    for source_id, title, url, text in vetted_sources:
        header = (
            f"[{source_id}]\n"
            f"TITLE: {title}\n"
            f"URL: {url}\n"
            "TEXT:\n"
        )
        chunk = header + text + "\n"
        remaining = max_total - total_chunk_chars
        if remaining <= 0:
            break
        chunk = chunk[:remaining]
        total_chunk_chars += len(chunk)
        included_text_chars = max(0, min(len(text), len(chunk) - len(header)))
        if included_text_chars <= 0:
            continue
        supplied_text_chars += included_text_chars
        supplied_source_ids.add(source_id)
        if source_id in cited_ids:
            cited_text_chars += included_text_chars
            cited_source_ids.add(source_id)

    base.update(
        {
            "synthesis_vetted_source_count": len(vetted_source_ids),
            "synthesis_supplied_source_count": len(supplied_source_ids),
            "synthesis_cited_source_count": len(cited_source_ids),
            "synthesis_vetted_source_text_chars": vetted_text_chars,
            "synthesis_supplied_source_text_chars": supplied_text_chars,
            "synthesis_cited_source_text_chars": cited_text_chars,
            "context_precision_proxy": (
                round(cited_text_chars / supplied_text_chars, 6)
                if supplied_text_chars
                else None
            ),
            "context_recall_proxy": (
                round(supplied_text_chars / vetted_text_chars, 6)
                if vetted_text_chars
                else None
            ),
        }
    )
    return base


def build_handoff(research: dict) -> dict:
    verified = list(research.get("verified_facts") or [])
    inferences = list(research.get("inferences") or [])
    conflicts = list(research.get("conflicts") or [])
    sources = list(research.get("sources") or [])
    usable_sources = [s for s in sources if s.get("fetch_status") == "ok" and s.get("extracted_text")]
    high_confidence = sum(1 for item in verified if item.get("confidence") == "high")
    critical_conflicts = [item for item in conflicts if item.get("severity") == "critical"]
    constraint_gaps = list(research.get("constraint_gaps") or [])
    claim_accounting = evidence_claim_accounting(research)
    context_accounting = synthesis_context_proxy_accounting(research)

    blockers: list[str] = []
    if not usable_sources:
        blockers.append("NO_USABLE_SOURCE")
    if research.get("source_assessment_error"):
        blockers.append("SOURCE_SUITABILITY_UNVERIFIED")
    if research.get("synthesis_error"):
        blockers.append("SYNTHESIS_INVALID_STRUCTURED_OUTPUT")
    if not verified:
        blockers.append("NO_VERIFIED_FACT")
    if critical_conflicts:
        blockers.append("CRITICAL_SOURCE_CONFLICT")
    if constraint_gaps:
        blockers.append("CORE_REQUIREMENTS_UNMET")

    presentation_ready = not blockers
    key_facts = []
    for index, item in enumerate(verified, start=1):
        key_facts.append(
            {
                "fact_id": f"F{index:03d}",
                "claim": item["claim"],
                "source_ids": item["source_ids"],
                "confidence": item.get("confidence", "low"),
            }
        )

    conclusion = _clean_text(research.get("conclusion"))
    if constraint_gaps:
        conclusion = (
            "The collected evidence does not fully satisfy the request's core requirements: "
            + ", ".join(constraint_gaps)
            + ". Unsupported details remain unresolved and must not be treated as verified."
        )

    handoff = {
        "schema_version": "1.0",
        "task_id": research.get("task_id"),
        "agent_id": "research",
        "presentation_ready": presentation_ready,
        "blockers": blockers,
        "objective": research.get("objective", ""),
        "key_facts": key_facts,
        "inferences": inferences,
        "conflicts": conflicts,
        "unresolved_items": list(research.get("unresolved_items") or []),
        "constraint_gaps": constraint_gaps,
        "conclusion": conclusion,
        "recommended_next_actions": list(research.get("recommended_next_actions") or []),
        "sources": source_refs(sources),
        "source_assessments": list(research.get("source_assessments") or []),
        "quality_metrics": {
            "source_count": len(sources),
            "usable_source_count": len(usable_sources),
            "verified_fact_count": len(verified),
            "high_confidence_fact_count": high_confidence,
            "inference_count": len(inferences),
            "conflict_count": len(conflicts),
            "critical_conflict_count": len(critical_conflicts),
            "unresolved_count": len(research.get("unresolved_items") or []),
            "structured_synthesis_error": bool(research.get("synthesis_error")),
            "source_assessment_error": bool(research.get("source_assessment_error")),
            "rejected_source_count": len(research.get("rejected_sources") or []),
            "rejected_numeric_claim_count": len(research.get("rejected_numeric_claims") or []),
            "constraint_gap_count": len(constraint_gaps),
            **claim_accounting,
            **context_accounting,
        },
        "generated_at": research.get("generated_at"),
    }

    sanitized_handoff, handoff_findings = sanitize_untrusted_payload(handoff)
    if not isinstance(sanitized_handoff, dict):
        raise ValueError("research handoff must remain an object after sanitization")

    source_findings: list[dict[str, Any]] = []
    provenance_refs: list[str] = []
    for source in sources:
        sid = str(source.get("source_id") or "")
        url = str(source.get("url") or "")
        if sid:
            provenance_refs.append(sid)
        if url:
            provenance_refs.append(url)
        sanitization = source.get("sanitization")
        if isinstance(sanitization, dict):
            findings = sanitization.get("findings")
            if isinstance(findings, list):
                source_findings.extend(item for item in findings if isinstance(item, dict))

    security = build_handoff_security_metadata(
        sanitized_handoff,
        [*source_findings, *handoff_findings],
        source_agent="research",
        source_type="research_handoff",
        target_agent="presentation",
        task_id=str(research.get("task_id") or ""),
        trust_domain="workspace-local-derived-from-untrusted",
        sanitizer_version="workspace-handoff-sanitizer/v1",
        provenance_refs=provenance_refs,
    )
    sanitized_handoff["security"] = security.to_dict()
    return sanitized_handoff


def confidence_at_least(value: str, threshold: str) -> bool:
    return _CONFIDENCE_ORDER.get(value, -1) >= _CONFIDENCE_ORDER.get(threshold, 99)
