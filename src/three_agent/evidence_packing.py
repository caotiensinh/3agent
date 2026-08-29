from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


LEGACY_PACKING_MODE = "legacy_v1"
QUALITY_RANKED_PACKING_MODE = "quality_ranked_v1"
PACKING_RECEIPT_SCHEMA = "workspace-evidence-packing-receipt/v1"
DEFAULT_SYNTHESIS_CONTEXT_BUDGET_CHARS = 48000
MIN_SYNTHESIS_CONTEXT_BUDGET_CHARS = 4096
MAX_SYNTHESIS_CONTEXT_BUDGET_CHARS = 64000
_ALLOWED_MODES = {LEGACY_PACKING_MODE, QUALITY_RANKED_PACKING_MODE}


@dataclass(frozen=True)
class EvidencePackingPolicy:
    """Deterministic policy controlling synthesis evidence order and budget.

    The production-compatible default remains legacy ordering with the historical
    48k character budget. Alternate ordering/budgets are benchmark candidates and
    are fingerprinted into WorkSpace benchmark lineage before they can be compared.
    """

    mode: str = LEGACY_PACKING_MODE
    budget_chars: int = DEFAULT_SYNTHESIS_CONTEXT_BUDGET_CHARS

    def to_fingerprint_dict(self) -> dict[str, str | int]:
        return {
            "schema_version": "workspace-evidence-packing-policy/v2",
            "mode": self.mode,
            "budget_chars": self.budget_chars,
        }


def _budget_from_env(value: Any) -> int:
    raw = str(value).strip()
    try:
        budget = int(raw, 10)
    except (TypeError, ValueError) as exc:
        raise ValueError("WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS must be an integer") from exc
    if not MIN_SYNTHESIS_CONTEXT_BUDGET_CHARS <= budget <= MAX_SYNTHESIS_CONTEXT_BUDGET_CHARS:
        raise ValueError(
            "WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS must be between "
            f"{MIN_SYNTHESIS_CONTEXT_BUDGET_CHARS} and {MAX_SYNTHESIS_CONTEXT_BUDGET_CHARS}"
        )
    return budget


def resolve_evidence_packing_policy(
    environ: Mapping[str, str] | None = None,
) -> EvidencePackingPolicy:
    env = os.environ if environ is None else environ
    mode = str(env.get("WORKSPACE_EVIDENCE_PACKING_MODE", LEGACY_PACKING_MODE)).strip().lower()
    if mode not in _ALLOWED_MODES:
        allowed = ", ".join(sorted(_ALLOWED_MODES))
        raise ValueError(f"WORKSPACE_EVIDENCE_PACKING_MODE must be one of: {allowed}")
    budget = _budget_from_env(
        env.get(
            "WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS",
            str(DEFAULT_SYNTHESIS_CONTEXT_BUDGET_CHARS),
        )
    )
    return EvidencePackingPolicy(mode=mode, budget_chars=budget)


def _assessment_score(item: dict[str, Any] | None) -> int:
    if not isinstance(item, dict):
        return -1000

    relevance = str(item.get("relevance") or "").strip().lower()
    authority = str(item.get("authority") or "").strip().lower()
    time_match = item.get("time_match")

    score = {
        "high": 100,
        "medium": 60,
        "low": 0,
    }.get(relevance, 0)
    if item.get("scope_match") is True:
        score += 40
    score += {
        "primary": 20,
        "secondary": 10,
        "unknown": 0,
    }.get(authority, 0)
    if time_match is True:
        score += 30
    elif time_match is False:
        score -= 30
    return score


def rank_vetted_sources(
    sources: Sequence[Any],
    assessments: Sequence[dict[str, Any]],
    *,
    policy: EvidencePackingPolicy | None = None,
) -> tuple[list[Any], list[dict[str, Any]]]:
    """Return a stable deterministic ordering plus metadata-only rank receipt.

    Only source_id and already-sanitized suitability metadata influence ranking.
    Source text, URLs, titles, prompts and model output are never inspected here.
    Equal-score sources preserve collection order.
    """

    resolved = policy or resolve_evidence_packing_policy()
    original = list(sources)
    assessment_map = {
        str(item.get("source_id") or ""): item
        for item in assessments
        if isinstance(item, dict) and str(item.get("source_id") or "")
    }

    if resolved.mode == LEGACY_PACKING_MODE:
        ranked = original
    else:
        decorated: list[tuple[int, int, Any]] = []
        for index, source in enumerate(original):
            source_id = str(getattr(source, "source_id", "") or "")
            score = _assessment_score(assessment_map.get(source_id))
            decorated.append((-score, index, source))
        decorated.sort(key=lambda item: (item[0], item[1]))
        ranked = [item[2] for item in decorated]

    receipt: list[dict[str, Any]] = []
    for rank, source in enumerate(ranked, start=1):
        source_id = str(getattr(source, "source_id", "") or "")
        assessment = assessment_map.get(source_id, {})
        receipt.append(
            {
                "source_id": source_id,
                "rank": rank,
                "score": _assessment_score(assessment),
                "relevance": assessment.get("relevance"),
                "authority": assessment.get("authority"),
                "time_match": assessment.get("time_match"),
            }
        )
    return ranked, receipt


def pack_evidence_sources(
    sources: Sequence[Any],
    *,
    policy: EvidencePackingPolicy | None = None,
) -> tuple[str, dict[str, Any]]:
    """Pack vetted sources exactly once and return a metadata-only receipt.

    The rendering intentionally preserves the legacy algorithm: the character
    budget applies to each source block before the ``\n---\n`` join separators are
    inserted. This keeps default 48k output byte-compatible with the old
    ``ResearchAgent._evidence_text`` implementation while making truncation
    accounting authoritative for future benchmark candidates.
    """

    resolved = policy or resolve_evidence_packing_policy()
    chunks: list[str] = []
    source_receipts: list[dict[str, Any]] = []
    packed_chunk_chars = 0
    vetted_text_chars = 0
    supplied_text_chars = 0
    supplied_sources = 0

    for rank, source in enumerate(list(sources), start=1):
        source_id = str(getattr(source, "source_id", "") or "")
        title = str(getattr(source, "title", "") or "")
        url = str(getattr(source, "url", "") or "")
        text = str(getattr(source, "extracted_text", "") or "")
        vetted_chars = len(text)
        vetted_text_chars += vetted_chars

        header = (
            f"[{source_id}]\n"
            f"TITLE: {title}\n"
            f"URL: {url}\n"
            "TEXT:\n"
        )
        full_chunk = header + text + "\n"
        remaining = resolved.budget_chars - packed_chunk_chars
        rendered_chunk = full_chunk[: max(0, remaining)] if remaining > 0 else ""
        included_text_chars = max(
            0,
            min(vetted_chars, len(rendered_chunk) - len(header)),
        )

        if rendered_chunk:
            chunks.append(rendered_chunk)
            packed_chunk_chars += len(rendered_chunk)
        if included_text_chars > 0:
            supplied_sources += 1
            supplied_text_chars += included_text_chars

        source_receipts.append(
            {
                "source_id": source_id,
                "rank": rank,
                "vetted_text_chars": vetted_chars,
                "supplied_text_chars": included_text_chars,
                "supplied": included_text_chars > 0,
            }
        )

    rendered = "\n---\n".join(chunks)
    receipt = {
        "schema_version": PACKING_RECEIPT_SCHEMA,
        "mode": resolved.mode,
        "budget_chars": resolved.budget_chars,
        "source_count": len(source_receipts),
        "supplied_source_count": supplied_sources,
        "vetted_source_text_chars": vetted_text_chars,
        "supplied_source_text_chars": supplied_text_chars,
        "packed_chunk_chars": packed_chunk_chars,
        "packed_output_chars": len(rendered),
        "sources": source_receipts,
        "raw_content_logged": False,
    }
    return rendered, receipt
