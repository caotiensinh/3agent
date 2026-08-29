from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from .knowledge_plane import EvidenceHit, LocalKnowledgeIndex, render_untrusted_evidence
from .task_contract import TaskContract, TaskContractError


@dataclass(frozen=True)
class PackedContext:
    text: str
    evidence: tuple[dict, ...]
    budget_units_used: int
    budget_units_limit: int
    duplicate_chunks_removed: int
    source_count: int

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "evidence": list(self.evidence),
            "budget_units_used": self.budget_units_used,
            "budget_units_limit": self.budget_units_limit,
            "duplicate_chunks_removed": self.duplicate_chunks_removed,
            "source_count": self.source_count,
        }


class ContextEngine:
    """Map -> search -> rank -> deduplicate -> hard-pack.

    The default counter uses UTF-8 bytes as a conservative tokenizer-independent
    budget unit. Production serving adapters should inject the exact tokenizer
    counter for their model. The engine never silently exceeds the Task Contract.
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
            return PackedContext("", (), 0, budget, 0, 0)

        # Fetch somewhat more candidates than can normally fit, then hard-pack.
        raw_hits = self.public_index.search(
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
                # Trim conservatively rather than allowing one large source to
                # crowd out the entire context.
                prefix = render_untrusted_evidence(
                    [
                        EvidenceHit(
                            **{**hit.to_dict(), "text": ""}
                        )
                    ]
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
        return PackedContext(
            text=packed,
            evidence=evidence,
            budget_units_used=final_cost,
            budget_units_limit=budget,
            duplicate_chunks_removed=removed,
            source_count=len({(hit.bundle_id, hit.source_id) for hit in accepted}),
        )
