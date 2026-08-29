from __future__ import annotations

from contextvars import ContextVar
from typing import Any

from ..evidence_packing import (
    LEGACY_PACKING_MODE,
    PACKING_RECEIPT_SCHEMA,
    pack_evidence_sources,
    rank_vetted_sources,
    resolve_evidence_packing_policy,
)
from .research import ResearchAgent as _BaseResearchAgent


_ACTIVE_SOURCE_ASSESSMENTS: ContextVar[list[dict] | None] = ContextVar(
    "workspace_active_source_assessments",
    default=None,
)


class ResearchAgent(_BaseResearchAgent):
    """ResearchAgent with benchmark-gated evidence ordering and packing receipt.

    Default behavior remains legacy ordering with the historical 48k budget. The
    receipt is metadata only and records how much already-vetted source text was
    actually supplied to synthesis. It carries no raw text, URL, title, prompt or
    model response.
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
        ranked, rank_receipt = rank_vetted_sources(vetted, assessments, policy=policy)

        if policy.mode != LEGACY_PACKING_MODE:
            vetted_ids = {str(getattr(source, "source_id", "") or "") for source in vetted}
            remaining = [
                source
                for source in sources
                if str(getattr(source, "source_id", "") or "") not in vetted_ids
            ]
            # Persist the exact vetted order that synthesis receives so old
            # artifacts/diagnostics remain understandable even without a receipt.
            sources[:] = [*ranked, *remaining]

        ranking = {item["source_id"]: item for item in rank_receipt}
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

        return assessments, ranked if policy.mode != LEGACY_PACKING_MODE else vetted, error

    def _synthesize(
        self,
        title: str,
        request: str,
        objective: str,
        focus: list[str],
        sources: list[Any],
        source_assessments: list[dict],
    ) -> dict[str, Any]:
        token = _ACTIVE_SOURCE_ASSESSMENTS.set(source_assessments)
        try:
            return super()._synthesize(
                title,
                request,
                objective,
                focus,
                sources,
                source_assessments,
            )
        finally:
            _ACTIVE_SOURCE_ASSESSMENTS.reset(token)

    @staticmethod
    def _evidence_text(sources: list[Any], *, max_total: int = 48000) -> str:
        # ``max_total`` remains in the signature for compatibility with tests and
        # callers, but the effective benchmarked budget is policy-controlled.
        # Explicit non-default test budgets still work without mutating process env.
        policy = resolve_evidence_packing_policy()
        if max_total != 48000:
            policy = type(policy)(mode=policy.mode, budget_chars=max_total)

        rendered, receipt = pack_evidence_sources(sources, policy=policy)
        assessments = _ACTIVE_SOURCE_ASSESSMENTS.get()
        if assessments is None:
            return rendered

        by_id = {
            str(item.get("source_id") or ""): item
            for item in receipt.get("sources", [])
            if isinstance(item, dict) and str(item.get("source_id") or "")
        }
        for assessment in assessments:
            if not isinstance(assessment, dict):
                continue
            source_id = str(assessment.get("source_id") or "")
            item = by_id.get(source_id)
            if item is None:
                continue
            assessment["synthesis_packing_receipt_version"] = PACKING_RECEIPT_SCHEMA
            assessment["synthesis_packing_mode"] = receipt["mode"]
            assessment["synthesis_context_budget_chars"] = receipt["budget_chars"]
            assessment["synthesis_vetted_text_chars"] = item["vetted_text_chars"]
            assessment["synthesis_supplied_text_chars"] = item["supplied_text_chars"]
            assessment["synthesis_supplied"] = item["supplied"]
            assessment["synthesis_packed_rank"] = item["rank"]

        return rendered
