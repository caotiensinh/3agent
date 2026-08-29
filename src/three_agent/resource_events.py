from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .inference_scope import current_inference_scope

RESOURCE_EVENT_TYPES = {"tool_call", "model_retry", "model_escalation"}


class ResourceEventError(ValueError):
    """A resource metric event is malformed or contains unsafe free-form data."""


def _compact(value: str | None, *, field: str, max_len: int, required: bool = True) -> str | None:
    if value is None:
        if required:
            raise ResourceEventError(f"{field} is required")
        return None
    text = str(value).strip()
    if not text:
        if required:
            raise ResourceEventError(f"{field} is required")
        return None
    if len(text) > max_len or any(ch.isspace() for ch in text):
        raise ResourceEventError(f"{field} must be a compact identifier")
    return text


@dataclass(frozen=True)
class ResourceEvent:
    event_type: str
    task_id: str | None
    actor_id: str
    action: str
    reason_code: str
    model: str | None = None
    target: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "workspace-resource-event/v1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": self.event_type,
            "task_id": self.task_id,
            "actor_id": self.actor_id,
            "action": self.action,
            "reason_code": self.reason_code,
            "model": self.model,
            "target": self.target,
        }


class ResourceEventRecorder:
    """Metadata-only task resource telemetry.

    Events intentionally contain no prompt, response, URL, command argv, evidence,
    exception message, credential, or business text. They measure invocation/retry/
    escalation counts only. A missing explicit task ID may use trusted inference
    scope; it is never inferred from model text or timing.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def record(
        self,
        event_type: str,
        *,
        task_id: str | None,
        actor_id: str,
        action: str,
        reason_code: str,
        model: str | None = None,
        target: str | None = None,
    ) -> None:
        kind = _compact(event_type, field="event_type", max_len=32)
        if kind not in RESOURCE_EVENT_TYPES:
            raise ResourceEventError(f"unsupported resource event type: {kind}")

        scope = current_inference_scope()
        resolved_task = task_id
        if resolved_task is None and scope is not None:
            resolved_task = scope.task_id
        normalized_task = _compact(
            resolved_task,
            field="task_id",
            max_len=128,
            required=False,
        )
        event = ResourceEvent(
            event_type=kind,
            task_id=normalized_task,
            actor_id=_compact(actor_id, field="actor_id", max_len=64),
            action=_compact(action, field="action", max_len=64),
            reason_code=_compact(reason_code.upper(), field="reason_code", max_len=128),
            model=_compact(model, field="model", max_len=160, required=False),
            target=_compact(target, field="target", max_len=160, required=False),
        )
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
