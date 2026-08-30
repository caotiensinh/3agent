from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


LEGACY_PACKING_MODE = "legacy_v1"
QUALITY_RANKED_PACKING_MODE = "quality_ranked_v1"
PACKING_RECEIPT_SCHEMA = "workspace-evidence-packing-receipt/v1"
PACKING_ALGORITHM_VERSION = "workspace-evidence-hard-pack/v3"
DEFAULT_SYNTHESIS_CONTEXT_BUDGET_CHARS = 48000
MIN_SYNTHESIS_CONTEXT_BUDGET_CHARS = 4096
MAX_SYNTHESIS_CONTEXT_BUDGET_CHARS = 64000
_ALLOWED_MODES = {LEGACY_PACKING_MODE, QUALITY_RANKED_PACKING_MODE}
_SEPARATOR = "\n---\n"
_EXACT_BODY_DEDUPE_ENV = "WORKSPACE_EVIDENCE_EXACT_BODY_DEDUPE"


@dataclass(frozen=True)
class EvidencePackingPolicy:
    """Deterministic policy controlling synthesis evidence order and budget.

    The production-compatible default remains legacy ordering with the historical
    48k character budget and exact-body suppression disabled. Alternate ordering,
    budgets and exact-body suppression are benchmark candidates and are fingerprinted
    into WorkSpace benchmark lineage before they can be compared.
    """

    mode: str = LEGACY_PACKING_MODE
    budget_chars: int = DEFAULT_SYNTHESIS_CONTEXT_BUDGET_CHARS
    exact_body_dedupe: bool = False

    def to_fingerprint_dict(self) -> dict[str, str | int | bool]:
        return {
            "schema_version": "workspace-evidence-packing-policy/v3",
            "mode": self.mode,
            "budget_chars": self.budget_chars,
            "exact_body_dedupe": self.exact_body_dedupe,
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


def _bool_from_env(value: Any, *, field: str) -> bool:
    raw = str(value).strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{field} must be a boolean")


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
    exact_body_dedupe = _bool_from_env(
        env.get(_EXACT_BODY_DEDUPE_ENV, "false"),
        field=_EXACT_BODY_DEDUPE_ENV,
    )
    return EvidencePackingPolicy(
        mode=mode,
        budget_chars=budget,
        exact_body_dedupe=exact_body_dedupe,
    )


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


def _source_parts(source: Any) -> tuple[str, str, str, str]:
    return (
        str(getattr(source, "source_id", "") or ""),
        str(getattr(source, "title", "") or ""),
        str(getattr(source, "url", "") or ""),
        str(getattr(source, "extracted_text", "") or ""),
    )


def _source_header(source_id: str, title: str, url: str) -> str:
    return (
        f"[{source_id}]\n"
        f"TITLE: {title}\n"
        f"URL: {url}\n"
        "TEXT:\n"
    )


def _body_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def pack_evidence_sources(
    sources: Sequence[Any],
    *,
    policy: EvidencePackingPolicy | None = None,
) -> tuple[str, dict[str, Any]]:
    """Hard-pack vetted evidence and return a metadata-only receipt.

    The full rendered output, including inter-source separators, is bounded by the
    configured character budget. Provenance/data-boundary headers are indivisible:
    a source is included only when its complete header plus at least one evidence
    character fits. Body text may be truncated; headers never are.

    Optional D5-02a exact-body suppression is intentionally narrow. A later source
    is suppressed only when its complete cleaned body is byte-identical to a body
    that was already supplied in full. Truncated or skipped bodies never establish a
    duplicate canonical. The receipt records only source relationships and counts;
    body hashes and raw content are never emitted.

    With exact-body suppression disabled and a comfortably large budget, rendering
    remains byte-compatible with the historical format.
    """

    resolved = policy or resolve_evidence_packing_policy()
    blocks: list[str] = []
    source_receipts: list[dict[str, Any]] = []
    vetted_text_chars = 0
    supplied_text_chars = 0
    supplied_sources = 0
    header_budget_skips = 0
    packed_chunk_chars = 0
    duplicate_bodies_suppressed = 0
    duplicate_text_chars_saved = 0
    fully_supplied_body_sources: dict[str, str] = {}

    for rank, source in enumerate(list(sources), start=1):
        source_id, title, url, text = _source_parts(source)
        vetted_chars = len(text)
        vetted_text_chars += vetted_chars
        header = _source_header(source_id, title, url)
        separator_cost = len(_SEPARATOR) if blocks else 0
        remaining = resolved.budget_chars - (
            packed_chunk_chars
            + max(0, len(blocks) - 1) * len(_SEPARATOR)
        )

        rendered_chunk = ""
        included_text_chars = 0
        skip_reason: str | None = None
        duplicate_of_source_id: str | None = None
        exact_body_duplicate_suppressed = False
        body_fully_supplied = False
        digest = _body_sha256(text) if text and resolved.exact_body_dedupe else None

        if digest is not None:
            duplicate_of_source_id = fully_supplied_body_sources.get(digest)

        # A source carrying no evidence text is never worth consuming provenance
        # budget. More importantly, the header itself is never partially emitted.
        if not text:
            skip_reason = "empty_evidence_text"
        elif duplicate_of_source_id is not None:
            exact_body_duplicate_suppressed = True
            skip_reason = "exact_body_duplicate_of_fully_supplied_source"
            duplicate_bodies_suppressed += 1
            duplicate_text_chars_saved += vetted_chars
        elif remaining < separator_cost + len(header) + 1:
            skip_reason = "provenance_header_or_first_text_char_does_not_fit"
            header_budget_skips += 1
        else:
            available_after_prefix = remaining - separator_cost - len(header)
            if len(text) + 1 <= available_after_prefix:
                body = text
                suffix = "\n"
            else:
                body = text[:available_after_prefix]
                suffix = ""
            included_text_chars = len(body)
            body_fully_supplied = included_text_chars == vetted_chars
            if included_text_chars <= 0:
                skip_reason = "no_body_budget"
                header_budget_skips += 1
            else:
                rendered_chunk = header + body + suffix

        if rendered_chunk:
            blocks.append(rendered_chunk)
            packed_chunk_chars += len(rendered_chunk)
            supplied_sources += 1
            supplied_text_chars += included_text_chars
            if digest is not None and body_fully_supplied:
                fully_supplied_body_sources.setdefault(digest, source_id)

        source_receipts.append(
            {
                "source_id": source_id,
                "rank": rank,
                "vetted_text_chars": vetted_chars,
                "supplied_text_chars": included_text_chars,
                "supplied": included_text_chars > 0,
                "body_fully_supplied": body_fully_supplied,
                "provenance_header_preserved": included_text_chars > 0,
                "exact_body_duplicate_suppressed": exact_body_duplicate_suppressed,
                "duplicate_of_source_id": duplicate_of_source_id,
                "skip_reason": skip_reason,
            }
        )

    rendered = _SEPARATOR.join(blocks)
    if len(rendered) > resolved.budget_chars:
        raise ValueError("EVIDENCE_HARD_PACK_BUDGET_EXCEEDED")

    separator_chars = max(0, len(blocks) - 1) * len(_SEPARATOR)
    receipt = {
        "schema_version": PACKING_RECEIPT_SCHEMA,
        "packing_algorithm_version": PACKING_ALGORITHM_VERSION,
        "mode": resolved.mode,
        "budget_chars": resolved.budget_chars,
        "exact_body_dedupe_enabled": resolved.exact_body_dedupe,
        "exact_duplicate_bodies_suppressed": duplicate_bodies_suppressed,
        "exact_duplicate_text_chars_saved": duplicate_text_chars_saved,
        "source_count": len(source_receipts),
        "supplied_source_count": supplied_sources,
        "vetted_source_text_chars": vetted_text_chars,
        "supplied_source_text_chars": supplied_text_chars,
        "packed_chunk_chars": packed_chunk_chars,
        "separator_chars": separator_chars,
        "packed_output_chars": len(rendered),
        "hard_budget_respected": len(rendered) <= resolved.budget_chars,
        "critical_provenance_header_truncated": False,
        "sources_skipped_for_header_budget": header_budget_skips,
        "sources": source_receipts,
        "body_hashes_logged": False,
        "raw_content_logged": False,
    }
    return rendered, receipt
