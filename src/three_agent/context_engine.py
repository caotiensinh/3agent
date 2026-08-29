from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from .knowledge_plane import EvidenceHit, LocalKnowledgeIndex, render_untrusted_evidence
from .task_contract import TaskContract, TaskContractError


_CONTEXT_TRACE_SCHEMA = "workspace-context-retrieval-trace/v1"


@dataclass(frozen=True)
class PackedContext:
    text: str
    evidence: tuple[dict, ...]
    budget_units_used: int
    budget_units_limit: int
    duplicate_chunks_removed: int
    source_count: int
    retrieval_trace: dict | None = None

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "evidence": list(self.evidence),
            "budget_units_used": self.budget_units_used,
            "budget_units_limit": self.budget_units_limit,
            "duplicate_chunks_removed": self.duplicate_chunks_removed,
            "source_count": self.source_count,
            "retrieval_trace": self.retrieval_trace,
        }


class _MappedKnowledgeIndexView(LocalKnowledgeIndex):
    """Reuse one already-read structural map for the body-search phase.

    `LocalKnowledgeIndex.search()` starts from `self.map()`. Supplying a cached
    metadata map here preserves the exact existing search/ranking implementation
    while proving that the control plane observes structure before chunk bodies and
    avoiding a second manifest-map pass.
    """

    def __init__(self, source: LocalKnowledgeIndex, source_map: list[dict]):
        super().__init__(source.root)
        self._source_map = tuple(dict(row) for row in source_map)

    def map(self) -> list[dict]:
        return [dict(row) for row in self._source_map]


class ContextEngine:
    """Map -> search -> rank -> deduplicate -> hard-pack.

    The default counter uses UTF-8 bytes as a conservative tokenizer-independent
    budget unit. Production serving adapters should inject the exact tokenizer
    counter for their model. The engine never silently exceeds the Task Contract.

    D5 structural-first behavior is observable through a metadata-only retrieval
    trace. The bounded structural preview never changes search semantics: the full
    already-read map is still supplied to the unchanged deterministic lexical
    search path. Progressive body expansion remains a separate D5 item.
    """

    def __init__(
        self,
        public_index: LocalKnowledgeIndex,
        *,
        token_counter: Callable[[str], int] | None = None,
    ):
        self.public_index = public_index
        self.token_counter = token_counter or (lambda text: len(text.encode("utf-8")))

    @staticmethod
    def _deduplicate(hits: Iterable[EvidenceHit]) -> tuple[list[EvidenceHit], int]:
        seen: set[tuple[str, str]] = set()
        output: list[EvidenceHit] = []
        removed = 0
        for hit in hits:
            key = (hit.content_sha256, hit.text)
            if key in seen:
                removed += 1
                continue
            seen.add(key)
            output.append(hit)
        return output, removed

    @staticmethod
    def _structural_receipt(source_map: list[dict], *, max_hits: int) -> dict:
        # This is a bounded first-view receipt, not a body-selection shortcut.
        # Keeping selection semantics unchanged prevents an unbenchmarked recall
        # regression while still making map-before-body behavior auditable.
        preview_limit = max(8, min(64, max(1, max_hits) * 4))
        preview = source_map[:preview_limit]
        risk_counts = {"low": 0, "medium": 0, "high": 0, "unknown": 0}
        for row in preview:
            risk = str(row.get("injection_risk") or "unknown").strip().lower()
            risk_counts[risk if risk in {"low", "medium", "high"} else "unknown"] += 1
        return {
            "schema_version": "workspace-context-structural-map/v1",
            "map_entries_total": len(source_map),
            "preview_limit": preview_limit,
            "preview_entries": len(preview),
            "preview_bundle_count": len(
                {str(row.get("bundle_id") or "") for row in preview if row.get("bundle_id")}
            ),
            "preview_injection_risk_counts": risk_counts,
            "body_text_in_preview": False,
            "raw_title_emitted": False,
            "raw_url_emitted": False,
            "selection_shortcut_applied": False,
        }

    @staticmethod
    def _empty_trace(*, reason: str) -> dict:
        return {
            "schema_version": _CONTEXT_TRACE_SCHEMA,
            "map_before_body_retrieval": False,
            "structural_map": None,
            "candidate_hits_after_rank": 0,
            "exact_duplicate_chunks_removed": 0,
            "accepted_hits": 0,
            "hard_budget_respected": True,
            "critical_provenance_header_truncated": False,
            "progressive_body_expansion": False,
            "reason": reason,
        }

    def build_public_evidence(
        self,
        query: str,
        contract: TaskContract,
        *,
        max_hits: int = 8,
    ) -> PackedContext:
        contract.validate()
        if not query.strip():
            raise TaskContractError("context query cannot be empty")
        # The local knowledge mirror is allowed to support any local task because
        # this direction is PUBLIC -> CORE. This method never performs networking.
        budget = contract.context_budget.max_retrieved_tokens
        if budget <= 0:
            return PackedContext(
                "",
                (),
                0,
                budget,
                0,
                0,
                self._empty_trace(reason="zero_retrieval_budget"),
            )

        # D5-01: the control plane reads a metadata-only structural map first.
        # The full map is then reused by the existing deterministic search method,
        # so this observability change does not alter ranking/recall semantics.
        source_map = self.public_index.map()
        structural = self._structural_receipt(source_map, max_hits=max_hits)
        mapped_index = _MappedKnowledgeIndexView(self.public_index, source_map)

        # Fetch somewhat more candidates than can normally fit, then hard-pack.
        raw_hits = mapped_index.search(
            query,
            max_hits=max(1, min(max_hits * 3, 24)),
            max_chars=max(1, budget * 4),
        )
        hits, removed = self._deduplicate(raw_hits)
        accepted: list[EvidenceHit] = []
        used = 0
        for hit in hits:
            single = render_untrusted_evidence([hit])
            cost = self.token_counter(single)
            if cost > budget:
                # Trim body text conservatively. The provenance/data-boundary
                # header is either preserved in full or the source is skipped;
                # it is never partially emitted.
                prefix = render_untrusted_evidence(
                    [EvidenceHit(**{**hit.to_dict(), "text": ""})]
                )
                overhead = self.token_counter(prefix)
                available = budget - used - overhead
                if available <= 0:
                    continue
                raw = hit.text.encode("utf-8")[:available]
                while raw:
                    try:
                        trimmed = raw.decode("utf-8")
                        break
                    except UnicodeDecodeError:
                        raw = raw[:-1]
                else:
                    continue
                hit = EvidenceHit(**{**hit.to_dict(), "text": trimmed})
                single = render_untrusted_evidence([hit])
                cost = self.token_counter(single)
            if used + cost > budget:
                continue
            accepted.append(hit)
            used += cost
            if len(accepted) >= max_hits:
                break

        packed = render_untrusted_evidence(accepted)
        final_cost = self.token_counter(packed)
        if final_cost > budget:
            # This is a programming invariant, not an LLM judgment.
            raise TaskContractError("ContextEngine hard-pack exceeded Task Contract budget")
        evidence = tuple(
            {
                "bundle_id": hit.bundle_id,
                "source_id": hit.source_id,
                "chunk_id": hit.chunk_id,
                "title": hit.title,
                "url": hit.url,
                "content_sha256": hit.content_sha256,
                "retrieved_at": hit.retrieved_at,
                "trust": hit.trust,
                "injection_risk": hit.injection_risk,
                "score": hit.score,
            }
            for hit in accepted
        )
        trace = {
            "schema_version": _CONTEXT_TRACE_SCHEMA,
            "map_before_body_retrieval": True,
            "structural_map": structural,
            "ranking_strategy": "deterministic_lexical_v1",
            "deduplication_strategy": "exact_content_sha256_plus_chunk_text_v1",
            "candidate_hits_after_rank": len(raw_hits),
            "exact_duplicate_chunks_removed": removed,
            "accepted_hits": len(accepted),
            "hard_budget_respected": final_cost <= budget,
            "critical_provenance_header_truncated": False,
            "progressive_body_expansion": False,
            "reason": "ok",
        }
        return PackedContext(
            text=packed,
            evidence=evidence,
            budget_units_used=final_cost,
            budget_units_limit=budget,
            duplicate_chunks_removed=removed,
            source_count=len({(hit.bundle_id, hit.source_id) for hit in accepted}),
            retrieval_trace=trace,
        )
