from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class TaskStatus(StrEnum):
    NEW = "NEW"
    RESEARCHING = "RESEARCHING"
    RESEARCH_COMPLETED = "RESEARCH_COMPLETED"
    RESEARCH_READY = "RESEARCH_READY"
    RESEARCH_BLOCKED = "RESEARCH_BLOCKED"
    PRESENTATION_CREATING = "PRESENTATION_CREATING"
    PRESENTATION_COMPLETED = "PRESENTATION_COMPLETED"
    DONE = "DONE"
    FAILED = "FAILED"
    WAITING_HUMAN = "WAITING_HUMAN"


@dataclass(frozen=True)
class Task:
    task_id: str
    title: str
    request: str
    status: TaskStatus
    created_at: str
    updated_at: str
