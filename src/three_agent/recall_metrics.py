from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable

from .artifacts import ArtifactManager
from .store import TaskStore

_CONTEXT_RECALL_PROXY_KIND = "vetted_source_char_retention_proxy"
_CONTEXT_RECALL_PROXY_SCOPE = "research_synthesis_context_budget"


@dataclass(frozen=True)
class ContextRecallProxyMetrics:
    selected_tasks: int
    tasks_with_recall_accounting: int
    tasks_without_recall_accounting: int
    malformed_handoffs: int
    synthesis_vetted_source_count: int
    synthesis_supplied_source_count: int
    synthesis_vetted_source_text_chars: int
    synthesis_supplied_source_text_chars: int
    context_recall_proxy: float | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "workspace-context-recall-proxy/v1",
            "proxy_kind": _CONTEXT_RECALL_PROXY_KIND,
            "proxy_scope": _CONTEXT_RECALL_PROXY_SCOPE,
            "selected_tasks": self.selected_tasks,
            "tasks_with_recall_accounting": self.tasks_with_recall_accounting,
            "tasks_without_recall_accounting": self.tasks_without_recall_accounting,
            "malformed_handoffs": self.malformed_handoffs,
            "synthesis_vetted_source_count": self.synthesis_vetted_source_count,
            "synthesis_supplied_source_count": self.synthesis_supplied_source_count,
            "synthesis_vetted_source_text_chars": self.synthesis_vetted_source_text_chars,
            "synthesis_supplied_source_text_chars": self.synthesis_supplied_source_text_chars,
            "context_recall_proxy": self.context_recall_proxy,
            "true_semantic_recall": None,
        }


class ContextRecallProxyAggregator:
    """Aggregate D3-07 source-text retention under the synthesis context budget.

    The proxy reports how much text that passed the deterministic suitability gate
    was actually supplied to Research synthesis after packing. It is a context
    retention measure, not a claim that every vetted character is equally relevant
    and not a semantic/token recall score.
    """

    def __init__(self, store: TaskStore, artifacts: ArtifactManager):
        self.store = store
        self.artifacts = artifacts

    @staticmethod
    def _count(value: Any) -> int | None:
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        return None

    @staticmethod
    def _proxy_is_valid(value: Any, vetted: int, supplied: int) -> bool:
        expected = round(supplied / vetted, 6) if vetted else None
        if expected is None:
            return value is None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        return abs(float(value) - expected) <= 0.0000005

    def snapshot(self, task_ids: Iterable[str] | None = None) -> ContextRecallProxyMetrics:
        if task_ids is None:
            selected = [task.task_id for task in self.store.list_tasks()]
        else:
            selected = list(
                dict.fromkeys(
                    str(task_id).strip()
                    for task_id in task_ids
                    if str(task_id).strip()
                )
            )
            for task_id in selected:
                self.store.get_task(task_id)

        with_accounting = 0
        without_accounting = 0
        malformed = 0
        vetted_sources = 0
        supplied_sources = 0
        vetted_chars = 0
        supplied_chars = 0

        required_keys = {
            "context_recall_proxy_kind",
            "context_recall_proxy_scope",
            "synthesis_vetted_source_count",
            "synthesis_supplied_source_count",
            "synthesis_vetted_source_text_chars",
            "synthesis_supplied_source_text_chars",
            "context_recall_proxy",
        }

        for task_id in selected:
            path = self.artifacts.find_latest_task_artifact(
                "research", task_id, suffix="_handoff.json"
            )
            if path is None:
                without_accounting += 1
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                malformed += 1
                without_accounting += 1
                continue
            if not isinstance(payload, dict):
                malformed += 1
                without_accounting += 1
                continue
            quality = payload.get("quality_metrics")
            if not isinstance(quality, dict):
                without_accounting += 1
                continue
            present = required_keys.intersection(quality)
            if not present:
                without_accounting += 1
                continue
            if present != required_keys:
                malformed += 1
                without_accounting += 1
                continue

            task_vetted_sources = self._count(quality.get("synthesis_vetted_source_count"))
            task_supplied_sources = self._count(quality.get("synthesis_supplied_source_count"))
            task_vetted_chars = self._count(quality.get("synthesis_vetted_source_text_chars"))
            task_supplied_chars = self._count(quality.get("synthesis_supplied_source_text_chars"))
            valid = (
                quality.get("context_recall_proxy_kind") == _CONTEXT_RECALL_PROXY_KIND
                and quality.get("context_recall_proxy_scope") == _CONTEXT_RECALL_PROXY_SCOPE
                and task_vetted_sources is not None
                and task_supplied_sources is not None
                and task_vetted_chars is not None
                and task_supplied_chars is not None
                and task_supplied_sources <= task_vetted_sources
                and task_supplied_chars <= task_vetted_chars
            )
            if valid:
                valid = self._proxy_is_valid(
                    quality.get("context_recall_proxy"),
                    task_vetted_chars,
                    task_supplied_chars,
                )
            if not valid:
                malformed += 1
                without_accounting += 1
                continue

            with_accounting += 1
            vetted_sources += task_vetted_sources
            supplied_sources += task_supplied_sources
            vetted_chars += task_vetted_chars
            supplied_chars += task_supplied_chars

        proxy = round(supplied_chars / vetted_chars, 6) if vetted_chars else None
        return ContextRecallProxyMetrics(
            selected_tasks=len(selected),
            tasks_with_recall_accounting=with_accounting,
            tasks_without_recall_accounting=without_accounting,
            malformed_handoffs=malformed,
            synthesis_vetted_source_count=vetted_sources,
            synthesis_supplied_source_count=supplied_sources,
            synthesis_vetted_source_text_chars=vetted_chars,
            synthesis_supplied_source_text_chars=supplied_chars,
            context_recall_proxy=proxy,
        )
