from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Any

from .resource_events import RESOURCE_EVENT_TYPES
from .store import TaskStore
from .verified_metrics import VerifiedWorkMetricAggregator


@dataclass(frozen=True)
class ResourcePerVerifiedMetrics:
    attempted_tasks: int
    verified_tasks: int
    telemetry_events: int
    attributed_events: int
    unattributed_events: int
    out_of_scope_events: int
    malformed_events: int
    tool_calls: int
    model_retries: int
    model_escalations: int
    tool_calls_per_verified_task: float | None
    model_retries_per_verified_task: float | None
    model_escalations_per_verified_task: float | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "workspace-resource-per-verified-task/v1",
            "attempted_tasks": self.attempted_tasks,
            "verified_tasks": self.verified_tasks,
            "telemetry_events": self.telemetry_events,
            "attributed_events": self.attributed_events,
            "unattributed_events": self.unattributed_events,
            "out_of_scope_events": self.out_of_scope_events,
            "malformed_events": self.malformed_events,
            "tool_calls": self.tool_calls,
            "model_retries": self.model_retries,
            "model_escalations": self.model_escalations,
            "tool_calls_per_verified_task": self.tool_calls_per_verified_task,
            "model_retries_per_verified_task": self.model_retries_per_verified_task,
            "model_escalations_per_verified_task": self.model_escalations_per_verified_task,
        }


class ResourcePerVerifiedTaskAggregator:
    """Aggregate D3-04 from typed metadata-only resource events.

    All events attributed to selected attempted tasks remain in the numerator,
    including calls/retries incurred by failed or ultimately unverified tasks.
    The denominator is contract-verified success only. Unknown/unscoped events are
    surfaced separately rather than guessed from log text.
    """

    def __init__(self, store: TaskStore, telemetry_path: Path):
        self.store = store
        self.telemetry_path = Path(telemetry_path)
        self.verified = VerifiedWorkMetricAggregator(store)

    @staticmethod
    def _per_verified(count: int, verified_tasks: int) -> float | None:
        if verified_tasks <= 0:
            return None
        return round(count / verified_tasks, 6)

    def snapshot(self, task_ids: Iterable[str] | None = None) -> ResourcePerVerifiedMetrics:
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
        selected_set = set(selected)
        known = {task.task_id for task in self.store.list_tasks()}
        verified_snapshot = self.verified.snapshot(selected)

        telemetry_events = 0
        attributed_events = 0
        unattributed_events = 0
        out_of_scope_events = 0
        malformed_events = 0
        counts = {kind: 0 for kind in RESOURCE_EVENT_TYPES}

        if self.telemetry_path.exists():
            with self.telemetry_path.open("r", encoding="utf-8") as handle:
                for raw in handle:
                    line = raw.strip()
                    if not line:
                        continue
                    telemetry_events += 1
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        malformed_events += 1
                        continue
                    if not isinstance(event, dict):
                        malformed_events += 1
                        continue
                    kind = str(event.get("event_type") or "")
                    if kind not in RESOURCE_EVENT_TYPES:
                        malformed_events += 1
                        continue
                    task_id = str(event.get("task_id") or "").strip()
                    if not task_id or task_id not in known:
                        unattributed_events += 1
                        continue
                    if task_id not in selected_set:
                        out_of_scope_events += 1
                        continue
                    attributed_events += 1
                    counts[kind] += 1

        verified_tasks = verified_snapshot.verified_tasks
        return ResourcePerVerifiedMetrics(
            attempted_tasks=verified_snapshot.attempted_tasks,
            verified_tasks=verified_tasks,
            telemetry_events=telemetry_events,
            attributed_events=attributed_events,
            unattributed_events=unattributed_events,
            out_of_scope_events=out_of_scope_events,
            malformed_events=malformed_events,
            tool_calls=counts["tool_call"],
            model_retries=counts["model_retry"],
            model_escalations=counts["model_escalation"],
            tool_calls_per_verified_task=self._per_verified(counts["tool_call"], verified_tasks),
            model_retries_per_verified_task=self._per_verified(counts["model_retry"], verified_tasks),
            model_escalations_per_verified_task=self._per_verified(counts["model_escalation"], verified_tasks),
        )
