from __future__ import annotations

import re
from typing import Any


_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


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


def clean_claims(items: Any, valid_source_ids: set[str]) -> tuple[list[dict], list[str]]:
    """Normalize, deduplicate and reject unsupported claims.

    The function is intentionally deterministic. The model may propose claims, but
    only claims with collected source IDs can pass through this gate.
    """
    accepted_by_key: dict[str, dict] = {}
    rejected: list[str] = []
    if not isinstance(items, list):
        return [], rejected

    for item in items:
        if isinstance(item, str):
            claim = _clean_text(item)
            raw_ids: list[str] = []
        elif isinstance(item, dict):
            claim = _clean_text(item.get("claim"))
            raw = item.get("source_ids", [])
            raw_ids = [sid for sid in raw if isinstance(sid, str)] if isinstance(raw, list) else []
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
        }
        current = accepted_by_key.get(key)
        if current is None:
            accepted_by_key[key] = candidate
            continue

        merged_ids = list(dict.fromkeys(current["source_ids"] + source_ids))
        current["source_ids"] = merged_ids
        current["confidence"] = confidence_for_sources(merged_ids)

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


def build_handoff(research: dict) -> dict:
    verified = list(research.get("verified_facts") or [])
    inferences = list(research.get("inferences") or [])
    conflicts = list(research.get("conflicts") or [])
    sources = list(research.get("sources") or [])
    usable_sources = [s for s in sources if s.get("fetch_status") == "ok" and s.get("extracted_text")]
    high_confidence = sum(1 for item in verified if item.get("confidence") == "high")
    critical_conflicts = [item for item in conflicts if item.get("severity") == "critical"]

    blockers: list[str] = []
    if not usable_sources:
        blockers.append("NO_USABLE_SOURCE")
    if not verified:
        blockers.append("NO_VERIFIED_FACT")
    if critical_conflicts:
        blockers.append("CRITICAL_SOURCE_CONFLICT")

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

    return {
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
        "conclusion": research.get("conclusion", ""),
        "recommended_next_actions": list(research.get("recommended_next_actions") or []),
        "sources": source_refs(sources),
        "quality_metrics": {
            "source_count": len(sources),
            "usable_source_count": len(usable_sources),
            "verified_fact_count": len(verified),
            "high_confidence_fact_count": high_confidence,
            "inference_count": len(inferences),
            "conflict_count": len(conflicts),
            "critical_conflict_count": len(critical_conflicts),
            "unresolved_count": len(research.get("unresolved_items") or []),
        },
        "generated_at": research.get("generated_at"),
    }


def confidence_at_least(value: str, threshold: str) -> bool:
    return _CONFIDENCE_ORDER.get(value, -1) >= _CONFIDENCE_ORDER.get(threshold, 99)
