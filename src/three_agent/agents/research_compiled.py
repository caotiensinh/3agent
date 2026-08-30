from __future__ import annotations

from dataclasses import replace
from typing import Any

from ..prompt_ledger import PromptCompilationLedger
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
    """Research path with deterministic local prompt compilation.

    Credentials and other sensitive values are intentionally preserved here. This
    class never performs egress sanitization; public-query compilation happens at
    the web boundary after the local research plan is produced.
    """

    def run(self, task_id: str, store: Any, artifacts: Any, live: bool = False):
        compilation = PromptCompilationLedger(store).compile_and_bind(task_id)
        view = _CompiledTaskStoreView(store, task_id, compilation.compiled_text)
        return super().run(task_id, view, artifacts, live=live)
