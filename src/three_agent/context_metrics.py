from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable

from .artifacts import ArtifactManager
from .store import TaskStore

_CONTEXT_PROXY_KIND = "source_level_citation_char_proxy"
_CONTEXT_PROXY_SCOPE = "research_synthesis_only"


@dataclass(frozen=True)
class ContextPrecisionProxyMetrics:
    selected_tasks: int
    tasks_with_context_accounting: int
    tasks_without_context_accounting: int
    malformed_handoffs: int
    synthesis_supplied_source_count: int
    synthesis_cited_source_count: int
    synthesis_supplied_source_text_chars: int
    synthesis_cited_source_text_chars: int
    context_precision_proxy: float | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "workspace-context-precision-proxy/v1",
            "proxy_kind": _CONTEXT_PROXY_KIND,
            "proxy_scope": _CONTEXT_PROXY_SCOPE,
            "selected_tasks": self.selected_tasks,
            "tasks_with_context_accounting": self.tasks_with_context_accounting,
            "tasks_without_context_accounting": self.tasks_without_context_accounting,
            "malformed_handoffs": self.malformed_handoffs,
            "synthesis_supplied_source_count": self.synthesis_supplied_source_count,
            "synthesis_cited_source_count": self.synthesis_cited_source_count,
            "synthesis_supplied_source_text_chars": self.synthesis_supplied_source_text_chars,
            "synthesis_cited_source_text_chars": self.synthesis_cited_source_text_chars,
            "context_precision_proxy": self.context_precision_proxy,
            "true_span_precision": None,
        }


class ContextPrecisionProxyAggregator:
    """Aggregate D3-06 without reinterpreting research prose.

    Research handoffs are authoritative for per-task source-level accounting. The
    aggregator validates their typed counters, sums cited/supplied characters and
    computes one ratio. It never averages task percentages and never claims token
    or span precision.
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
    def _proxy_is_valid(value: Any, supplied: int, cited: int) -> bool:
        expected = round(cited / supplied, 6) if supplied else None
        if expected is None:
            return value is None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        return abs(float(value) - expected) <= 0.0000005

    def snapshot(self, task_ids: Iterable[str] | None = None) -> ContextPrecisionProxyMetrics:
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
        supplied_sources = 0
        cited_sources = 0
        supplied_chars = 0
        cited_chars = 0

        required_keys = {
            "context_precision_proxy_kind",
            "context_precision_proxy_scope",
            "synthesis_supplied_source_count",
            "synthesis_cited_source_count",
            "synthesis_supplied_source_text_chars",
            "synthesis_cited_source_text_chars",
            "context_precision_proxy",
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

            task_supplied_sources = self._count(quality.get("synthesis_supplied_source_count"))
            task_cited_sources = self._count(quality.get("synthesis_cited_source_count"))
            task_supplied_chars = self._count(quality.get("synthesis_supplied_source_text_chars"))
            task_cited_chars = self._count(quality.get("synthesis_cited_source_text_chars"))
            valid = (
                quality.get("context_precision_proxy_kind") == _CONTEXT_PROXY_KIND
                and quality.get("context_precision_proxy_scope") == _CONTEXT_PROXY_SCOPE
                and task_supplied_sources is not None
                and task_cited_sources is not None
                and task_supplied_chars is not None
                and task_cited_chars is not None
                and task_cited_sources <= task_supplied_sources
                and task_cited_chars <= task_supplied_chars
            )
            if valid:
                valid = self._proxy_is_valid(
                    quality.get("context_precision_proxy"),
                    task_supplied_chars,
                    task_cited_chars,
                )
            if not valid:
                malformed += 1
                without_accounting += 1
                continue

            with_accounting += 1
            supplied_sources += task_supplied_sources
            cited_sources += task_cited_sources
            supplied_chars += task_supplied_chars
            cited_chars += task_cited_chars

        proxy = round(cited_chars / supplied_chars, 6) if supplied_chars else None
        return ContextPrecisionProxyMetrics(
            selected_tasks=len(selected),
            tasks_with_context_accounting=with_accounting,
            tasks_without_context_accounting=without_accounting,
            malformed_handoffs=malformed,
            synthesis_supplied_source_count=supplied_sources,
            synthesis_cited_source_count=cited_sources,
            synthesis_supplied_source_text_chars=supplied_chars,
            synthesis_cited_source_text_chars=cited_chars,
            context_precision_proxy=proxy,
        )
