from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from .context_metrics import ContextPrecisionProxyAggregator
from .evidence_metrics import EvidenceCoverageAggregator
from .metric_registry import DEFAULT_METRIC_REGISTRY
from .recall_metrics import ContextRecallProxyAggregator
from .resource_metrics import ResourcePerVerifiedTaskAggregator
from .token_metrics import TokenPerVerifiedTaskAggregator
from .verified_metrics import VerifiedWorkMetricAggregator


class MetricsSnapshotService:
    """Compose D3 metrics with one authoritative task scope and metric registry.

    The service does not reimplement any metric formula. It resolves the selected
    task IDs once, passes the same IDs to each existing aggregator, and binds the
    resulting snapshot to a versioned metric registry so semantic/formula drift is
    visible in benchmark lineage instead of silently reusing the same metric name.
    """

    def __init__(
        self,
        store,
        artifacts,
        inference_telemetry_path: Path,
        resource_telemetry_path: Path,
    ):
        self.store = store
        self.artifacts = artifacts
        self.inference_telemetry_path = Path(inference_telemetry_path)
        self.resource_telemetry_path = Path(resource_telemetry_path)

    @classmethod
    def from_orchestrator(cls, orchestrator: Any) -> "MetricsSnapshotService":
        return cls(
            orchestrator.store,
            orchestrator.artifacts,
            Path(orchestrator.inference_telemetry_path),
            Path(orchestrator.resource_telemetry_path),
        )

    def _resolve_scope(
        self,
        *,
        task_ids: Iterable[str] | None = None,
        date: str | None = None,
    ) -> list[str]:
        if task_ids is not None and date is not None:
            raise ValueError("date and task_ids are mutually exclusive metrics scopes")
        if date is not None:
            return [str(row["task_id"]) for row in self.store.tasks_for_date(date)]
        if task_ids is None:
            return [task.task_id for task in self.store.list_tasks()]

        selected = list(
            dict.fromkeys(
                str(task_id).strip()
                for task_id in task_ids
                if str(task_id).strip()
            )
        )
        for task_id in selected:
            self.store.get_task(task_id)
        return selected

    def snapshot(
        self,
        *,
        task_ids: Iterable[str] | None = None,
        date: str | None = None,
    ) -> dict[str, Any]:
        selected = self._resolve_scope(task_ids=task_ids, date=date)
        verified = VerifiedWorkMetricAggregator(self.store).snapshot(selected)
        tokens = TokenPerVerifiedTaskAggregator(
            self.store, self.inference_telemetry_path
        ).snapshot(selected)
        resources = ResourcePerVerifiedTaskAggregator(
            self.store, self.resource_telemetry_path
        ).snapshot(selected)
        evidence = EvidenceCoverageAggregator(
            self.store, self.artifacts
        ).snapshot(selected)
        precision = ContextPrecisionProxyAggregator(
            self.store, self.artifacts
        ).snapshot(selected)
        recall = ContextRecallProxyAggregator(
            self.store, self.artifacts
        ).snapshot(selected)
        registry = DEFAULT_METRIC_REGISTRY.to_dict()

        return {
            "schema_version": "workspace-unified-metrics/v1",
            "scope": {
                "date": date,
                "selected_task_count": len(selected),
                "task_ids": selected,
            },
            "metric_registry": registry,
            "metric_map": DEFAULT_METRIC_REGISTRY.metric_map(),
            "verified_work": verified.to_dict(),
            "token_efficiency": tokens.to_dict(),
            "resource_efficiency": resources.to_dict(),
            "evidence_coverage": evidence.to_dict(),
            "context_precision_proxy": precision.to_dict(),
            "context_recall_proxy": recall.to_dict(),
        }
