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

    Default behavior remains legacy ordering with the historical 48k budget and
    exact-body suppression disabled. The receipt is metadata only and records how
    much already-vetted source text was actually supplied to synthesis. It carries
    no raw text, URL, title, prompt, body hash or model response.
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
            assessment["synthesis_exact_body_dedupe_enabled"] = policy.exact_body_dedupe

        return assessments, ranked if policy.mode != LEGACY_PACKING_MODE else vetted, error

    @staticmethod
    def _supplied_sources_after_pack(
        sources: list[Any],
        source_assessments: list[dict],
    ) -> list[Any]:
        """Restrict synthesis citation authority to evidence actually rendered.

        Provenance metadata may retain a source that the hard packer did not render
        because of budget or D5-02a exact-body suppression. Such a source must not
        remain available to the base synthesis validator merely because its source
        ID still exists. Once packing receipts are authoritative, every candidate
        source must have a complete receipt projection or the path fails closed.
        """

        by_id = {
            str(item.get("source_id") or ""): item
            for item in source_assessments
            if isinstance(item, dict) and str(item.get("source_id") or "")
        }
        supplied: list[Any] = []
        for source in sources:
            source_id = str(getattr(source, "source_id", "") or "")
            item = by_id.get(source_id)
            if not isinstance(item, dict):
                raise ValueError("SYNTHESIS_PACKING_RECEIPT_CITATION_SCOPE_INCOMPLETE")
            if item.get("synthesis_packing_receipt_version") != PACKING_RECEIPT_SCHEMA:
                raise ValueError("SYNTHESIS_PACKING_RECEIPT_CITATION_SCOPE_INVALID")
            supplied_flag = item.get("synthesis_supplied")
            if not isinstance(supplied_flag, bool):
                raise ValueError("SYNTHESIS_PACKING_RECEIPT_CITATION_SCOPE_INVALID")
            if supplied_flag:
                supplied.append(source)
        return supplied

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
            # Materialize the authoritative packing receipt before synthesis so
            # source IDs omitted from the rendered context cannot remain citation
            # authority. This is deterministic and performs no additional model call.
            self._evidence_text(sources)
            supplied_sources = self._supplied_sources_after_pack(
                sources,
                source_assessments,
            )

            # The base synthesizer calls ``self._evidence_text`` again to build its
            # prompt. Suppress receipt mutation for that identical second rendering
            # so duplicate/skip relationships retain the authoritative first-pass
            # ranks and metadata instead of being rewritten after filtering.
            nested = _ACTIVE_SOURCE_ASSESSMENTS.set(None)
            try:
                return super()._synthesize(
                    title,
                    request,
                    objective,
                    focus,
                    supplied_sources,
                    source_assessments,
                )
            finally:
                _ACTIVE_SOURCE_ASSESSMENTS.reset(nested)
        finally:
            _ACTIVE_SOURCE_ASSESSMENTS.reset(token)

    @staticmethod
    def _evidence_text(sources: list[Any], *, max_total: int = 48000) -> str:
        # ``max_total`` remains in the signature for compatibility with tests and
        # callers, but the effective benchmarked budget is policy-controlled.
        # Explicit non-default test budgets still work without mutating process env.
        policy = resolve_evidence_packing_policy()
        if max_total != 48000:
            policy = type(policy)(
                mode=policy.mode,
                budget_chars=max_total,
                exact_body_dedupe=policy.exact_body_dedupe,
            )

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
            assessment["synthesis_exact_body_dedupe_enabled"] = receipt[
                "exact_body_dedupe_enabled"
            ]
            assessment["synthesis_vetted_text_chars"] = item["vetted_text_chars"]
            assessment["synthesis_supplied_text_chars"] = item["supplied_text_chars"]
            assessment["synthesis_supplied"] = item["supplied"]
            assessment["synthesis_body_fully_supplied"] = item["body_fully_supplied"]
            assessment["synthesis_exact_body_duplicate_suppressed"] = item[
                "exact_body_duplicate_suppressed"
            ]
            assessment["synthesis_duplicate_of_source_id"] = item[
                "duplicate_of_source_id"
            ]
            assessment["synthesis_packed_rank"] = item["rank"]

        return rendered
