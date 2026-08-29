from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Any

from .store import TaskStore
from .verified_metrics import VerifiedWorkMetricAggregator


@dataclass(frozen=True)
class TokenPerVerifiedMetrics:
    attempted_tasks: int
    verified_tasks: int
    telemetry_events: int
    attributed_events: int
    unattributed_events: int
    out_of_scope_events: int
    malformed_events: int
    events_missing_token_usage: int
    attributed_input_tokens: int
    attributed_output_tokens: int
    attributed_total_tokens: int
    unattributed_input_tokens: int
    unattributed_output_tokens: int
    unattributed_total_tokens: int
    input_tokens_per_verified_task: float | None
    output_tokens_per_verified_task: float | None
    total_tokens_per_verified_task: float | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "workspace-token-per-verified-task/v1",
            "attempted_tasks": self.attempted_tasks,
            "verified_tasks": self.verified_tasks,
            "telemetry_events": self.telemetry_events,
            "attributed_events": self.attributed_events,
            "unattributed_events": self.unattributed_events,
            "out_of_scope_events": self.out_of_scope_events,
            "malformed_events": self.malformed_events,
            "events_missing_token_usage": self.events_missing_token_usage,
            "attributed_input_tokens": self.attributed_input_tokens,
            "attributed_output_tokens": self.attributed_output_tokens,
            "attributed_total_tokens": self.attributed_total_tokens,
            "unattributed_input_tokens": self.unattributed_input_tokens,
            "unattributed_output_tokens": self.unattributed_output_tokens,
            "unattributed_total_tokens": self.unattributed_total_tokens,
            "input_tokens_per_verified_task": self.input_tokens_per_verified_task,
            "output_tokens_per_verified_task": self.output_tokens_per_verified_task,
            "total_tokens_per_verified_task": self.total_tokens_per_verified_task,
        }


class TokenPerVerifiedTaskAggregator:
    """Compute D3-03 from trusted task-scoped inference telemetry.

    Numerator = all attributable model tokens spent on the selected attempted
    tasks, including failed/unverified attempts. Denominator = tasks that satisfy
    every required TaskContract validator. This prevents failed work from being
    hidden simply because it did not become a verified success.

    Events without authoritative task scope are reported separately and never
    guessed from prompt text, timestamps, model output, or task status.
    """

    def __init__(self, store: TaskStore, telemetry_path: Path):
        self.store = store
        self.telemetry_path = Path(telemetry_path)
        self.verified = VerifiedWorkMetricAggregator(store)

    @staticmethod
    def _non_negative_int(value: Any) -> int | None:
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        return None

    @staticmethod
    def _per_verified(tokens: int, verified_tasks: int) -> float | None:
        if verified_tasks <= 0:
            return None
        return round(tokens / verified_tasks, 6)

    @classmethod
    def _tokens(cls, event: dict[str, Any]) -> tuple[int, int, bool]:
        usage = event.get("usage")
        if not isinstance(usage, dict):
            return 0, 0, False
        prompt = cls._non_negative_int(usage.get("prompt_eval_count"))
        output = cls._non_negative_int(usage.get("eval_count"))
        complete = prompt is not None and output is not None
        return prompt or 0, output or 0, complete

    def _known_task_ids(self) -> set[str]:
        return {task.task_id for task in self.store.list_tasks()}

    def snapshot(self, task_ids: Iterable[str] | None = None) -> TokenPerVerifiedMetrics:
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
        known = self._known_task_ids()
        verified_snapshot = self.verified.snapshot(selected)

        telemetry_events = 0
        attributed_events = 0
        unattributed_events = 0
        out_of_scope_events = 0
        malformed_events = 0
        missing_usage = 0
        attributed_input = 0
        attributed_output = 0
        unattributed_input = 0
        unattributed_output = 0

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

                    input_tokens, output_tokens, complete = self._tokens(event)
                    if not complete:
                        missing_usage += 1

                    scope = event.get("task_scope")
                    task_id = (
                        str(scope.get("task_id") or "").strip()
                        if isinstance(scope, dict)
                        else ""
                    )
                    if not task_id or task_id not in known:
                        unattributed_events += 1
                        unattributed_input += input_tokens
                        unattributed_output += output_tokens
                        continue
                    if task_id not in selected_set:
                        out_of_scope_events += 1
                        continue

                    attributed_events += 1
                    attributed_input += input_tokens
                    attributed_output += output_tokens

        attributed_total = attributed_input + attributed_output
        unattributed_total = unattributed_input + unattributed_output
        verified_tasks = verified_snapshot.verified_tasks
        return TokenPerVerifiedMetrics(
            attempted_tasks=verified_snapshot.attempted_tasks,
            verified_tasks=verified_tasks,
            telemetry_events=telemetry_events,
            attributed_events=attributed_events,
            unattributed_events=unattributed_events,
            out_of_scope_events=out_of_scope_events,
            malformed_events=malformed_events,
            events_missing_token_usage=missing_usage,
            attributed_input_tokens=attributed_input,
            attributed_output_tokens=attributed_output,
            attributed_total_tokens=attributed_total,
            unattributed_input_tokens=unattributed_input,
            unattributed_output_tokens=unattributed_output,
            unattributed_total_tokens=unattributed_total,
            input_tokens_per_verified_task=self._per_verified(attributed_input, verified_tasks),
            output_tokens_per_verified_task=self._per_verified(attributed_output, verified_tasks),
            total_tokens_per_verified_task=self._per_verified(attributed_total, verified_tasks),
        )
