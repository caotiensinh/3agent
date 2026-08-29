from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


LEGACY_PACKING_MODE = "legacy_v1"
QUALITY_RANKED_PACKING_MODE = "quality_ranked_v1"
_ALLOWED_MODES = {LEGACY_PACKING_MODE, QUALITY_RANKED_PACKING_MODE}


@dataclass(frozen=True)
class EvidencePackingPolicy:
    """Deterministic policy controlling synthesis evidence ordering.

    v1 intentionally changes ordering only. It does not change the existing 48k
    synthesis budget or truncate source bodies differently. This keeps the first
    optimization independently benchmarkable before any context-budget reduction.
    """

    mode: str = LEGACY_PACKING_MODE

    def to_fingerprint_dict(self) -> dict[str, str]:
        return {
            "schema_version": "workspace-evidence-packing-policy/v1",
            "mode": self.mode,
        }


def resolve_evidence_packing_policy(
    environ: Mapping[str, str] | None = None,
) -> EvidencePackingPolicy:
    env = os.environ if environ is None else environ
    mode = str(env.get("WORKSPACE_EVIDENCE_PACKING_MODE", LEGACY_PACKING_MODE)).strip().lower()
    if mode not in _ALLOWED_MODES:
        allowed = ", ".join(sorted(_ALLOWED_MODES))
        raise ValueError(f"WORKSPACE_EVIDENCE_PACKING_MODE must be one of: {allowed}")
    return EvidencePackingPolicy(mode=mode)


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
