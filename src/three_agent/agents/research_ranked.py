from __future__ import annotations

from typing import Any

from ..evidence_packing import (
    LEGACY_PACKING_MODE,
    rank_vetted_sources,
    resolve_evidence_packing_policy,
)
from .research import ResearchAgent as _BaseResearchAgent


class ResearchAgent(_BaseResearchAgent):
    """ResearchAgent with benchmark-gated deterministic evidence ordering.

    The default policy is byte-for-byte behavioral compatibility (`legacy_v1`).
    `quality_ranked_v1` only reorders vetted sources before the existing synthesis
    packing loop; it does not change the 48k budget or grant new capabilities.
    """

    def _assess_sources(
        self,
        request: str,
        objective: str,
        sources: list[Any],
    ) -> tuple[list[dict], list[Any], str | None]:
        assessments, vetted, error = super()._assess_sources(request, objective, sources)
        if error or not vetted:
            return assessments, vetted, error

        policy = resolve_evidence_packing_policy()
        ranked, receipt = rank_vetted_sources(vetted, assessments, policy=policy)
        if policy.mode == LEGACY_PACKING_MODE:
            return assessments, vetted, error

        vetted_ids = {str(getattr(source, "source_id", "") or "") for source in vetted}
        remaining = [
            source
            for source in sources
            if str(getattr(source, "source_id", "") or "") not in vetted_ids
        ]
        # Research payload preserves this order, so D3-06/D3-07 reconstruction
        # observes the same vetted-source ordering that synthesis received.
        sources[:] = [*ranked, *remaining]

        ranking = {item["source_id"]: item for item in receipt}
        for assessment in assessments:
            if not isinstance(assessment, dict):
                continue
            source_id = str(assessment.get("source_id") or "")
            item = ranking.get(source_id)
            if item is None:
                continue
            assessment["synthesis_rank"] = item["rank"]
            assessment["synthesis_rank_score"] = item["score"]
            assessment["synthesis_packing_mode"] = policy.mode

        return assessments, ranked, error
