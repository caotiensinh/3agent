from __future__ import annotations

from dataclasses import replace
from typing import Any

from ..prompt_ledger import PromptCompilationLedger
from ..public_query_compiler import compile_public_search_queries
from .research_ranked import ResearchAgent as _RankedResearchAgent


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
    """Research path with local prompt compilation plus public-query declassification.

    Credentials and other sensitive values are intentionally preserved in the local
    compiled prompt. Only model-generated web-search queries cross the separate
    public query compiler and the existing strict InternetGateway DLP gate. The raw
    user request is never used as an automatic egress fallback.
    """

    def _plan(self, title: str, request: str) -> tuple[str, list[str], list[str]]:
        objective, queries, focus = super()._plan(title, request)
        public_queries, _diagnostics = compile_public_search_queries(
            queries,
            max_queries=4,
        )
        # Empty is safer than falling back to a raw request. Upload/local evidence
        # can still be processed; public search simply contributes no sources.
        return objective, public_queries, focus

    def run(self, task_id: str, store: Any, artifacts: Any, live: bool = False):
        compilation = PromptCompilationLedger(store).compile_and_bind(task_id)
        view = _CompiledTaskStoreView(store, task_id, compilation.compiled_text)
        return super().run(task_id, view, artifacts, live=live)
