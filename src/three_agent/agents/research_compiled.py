from __future__ import annotations

from contextvars import ContextVar
from dataclasses import replace
from typing import Any

from ..adaptive_learning_contract import DOMAINS
from ..adaptive_learning_retrieval import (
    LearningContext,
    LearningRetrievalGateway,
    LearningRetrievalQuery,
    append_learning_reference,
)
from ..prompt_ledger import PromptCompilationLedger
from ..public_query_compiler import compile_public_search_queries
from ..task_contract import SENSITIVITIES
from .research_ranked import ResearchAgent as _RankedResearchAgent


_ACTIVE_LEARNING_CONTEXT: ContextVar[LearningContext | None] = ContextVar(
    "workspace_active_learning_context",
    default=None,
)


class _CompiledTaskStoreView:
    """Delegate storage mutations while exposing one compiled local task request.

    The authoritative original request remains untouched in the underlying local
    TaskStore. Only model-facing `get_task()` reads for this workflow see the
    deterministic compiled representation.
    """

    def __init__(self, store: Any, task_id: str, compiled_text: str) -> None:
        self._store = store
        self._task_id = task_id
        self._compiled_text = compiled_text

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)

    def get_task(self, task_id: str):
        task = self._store.get_task(task_id)
        if task_id != self._task_id:
            return task
        return replace(task, request=self._compiled_text)


class ResearchAgent(_RankedResearchAgent):
    """Research path with local prompt compilation and safe learned reference reuse.

    Credentials and other sensitive values are intentionally preserved in the local
    compiled prompt. Only model-generated web-search queries cross the separate
    public query compiler and the existing strict InternetGateway DLP gate. The raw
    user request is never used as an automatic egress fallback.

    Phase 4C learned knowledge is retrieved only from a separately supplied trusted
    ``LearningRetrievalGateway``. It is deliberately excluded from planning/search
    queries and is attached only to the local synthesis objective as untrusted
    reference data. Therefore learned content cannot become public-search egress,
    system/developer authority, or execution capability.

    The retrieval domain is trusted agent configuration. The task sensitivity is
    never a constructor default: it is read from the exact bound TaskContract for
    each task immediately before retrieval, preventing learned-context downgrade.
    """

    def __init__(
        self,
        *args: Any,
        learning_retrieval: LearningRetrievalGateway | None = None,
        learning_domain: str = "analyst",
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        normalized_domain = str(learning_domain or "").strip().lower()
        if normalized_domain not in DOMAINS:
            raise ValueError("unsupported learning retrieval domain")
        self.learning_retrieval = learning_retrieval
        self.learning_domain = normalized_domain

    @staticmethod
    def _task_learning_sensitivity(store: Any, task_id: str) -> str:
        loader = getattr(store, "task_contract_for_task", None)
        if not callable(loader):
            raise ValueError("bound TaskContract is required for learned retrieval")
        payload = loader(task_id)
        if not isinstance(payload, dict):
            raise ValueError("bound TaskContract is required for learned retrieval")
        sensitivity = str(payload.get("sensitivity") or "").strip().lower()
        if sensitivity not in SENSITIVITIES:
            raise ValueError("bound TaskContract sensitivity is invalid")
        if str(payload.get("task_id") or "").strip() != task_id:
            raise ValueError("bound TaskContract task_id mismatch")
        return sensitivity

    def _plan(self, title: str, request: str) -> tuple[str, list[str], list[str]]:
        # Learned context MUST NOT be added here. Planning output may cross the
        # public InternetGateway after deterministic declassification.
        objective, queries, focus = super()._plan(title, request)
        public_queries, _diagnostics = compile_public_search_queries(
            queries,
            max_queries=4,
        )
        # Empty is safer than falling back to a raw request. Upload/local evidence
        # can still be processed; public search simply contributes no sources.
        return objective, public_queries, focus

    def _synthesize(
        self,
        title: str,
        request: str,
        objective: str,
        focus: list[str],
        sources: list[Any],
        source_assessments: list[dict],
    ) -> dict[str, Any]:
        context = _ACTIVE_LEARNING_CONTEXT.get()
        local_objective = (
            objective
            if context is None or not context.items
            else append_learning_reference(objective, context)
        )
        # Keep the authoritative request unchanged so all existing request
        # constraint/evidence validators see byte-identical input.
        return super()._synthesize(
            title,
            request,
            local_objective,
            focus,
            sources,
            source_assessments,
        )

    def run(self, task_id: str, store: Any, artifacts: Any, live: bool = False):
        compilation = PromptCompilationLedger(store).compile_and_bind(task_id)
        view = _CompiledTaskStoreView(store, task_id, compilation.compiled_text)

        context: LearningContext | None = None
        if live and self.learning_retrieval is not None:
            try:
                task_sensitivity = self._task_learning_sensitivity(store, task_id)
                query = LearningRetrievalQuery(
                    query=compilation.compiled_text,
                    domain=self.learning_domain,
                    task_sensitivity=task_sensitivity,
                )
                context = self.learning_retrieval.retrieve(query)
            except Exception as exc:
                # Retrieval is optional reference context. Integrity/policy failure
                # therefore fails closed to NO learned context while preserving the
                # pre-Phase-4C research workflow. Never log raw learned/request text.
                store.record_activity(
                    task_id,
                    self.agent_id,
                    "learning_retrieval_blocked",
                    "blocked",
                    f"reason={type(exc).__name__}",
                )
                context = None
            else:
                if context.items:
                    item_ids = ",".join(item.item_id for item in context.items)
                    hashes = ",".join(item.knowledge_sha256 for item in context.items)
                    store.record_activity(
                        task_id,
                        self.agent_id,
                        "learning_retrieval_completed",
                        "ok",
                        f"count={len(context.items)} item_ids={item_ids} knowledge_sha256={hashes}",
                    )

        token = _ACTIVE_LEARNING_CONTEXT.set(context)
        try:
            return super().run(task_id, view, artifacts, live=live)
        finally:
            _ACTIVE_LEARNING_CONTEXT.reset(token)
