from __future__ import annotations

from typing import Any

DAILY_REPORT_SCHEMA_ID = "workspace.daily-report/v1"

_REPORT_ITEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["text", "evidence_ids"],
    "properties": {
        "task_id": {"type": "string", "minLength": 1, "maxLength": 80},
        "text": {"type": "string", "minLength": 1, "maxLength": 1600},
        "evidence_ids": {
            "type": "array",
            "minItems": 1,
            "maxItems": 32,
            "items": {"type": "string", "minLength": 1, "maxLength": 32},
        },
    },
}

DAILY_REPORT_SCHEMA_V1: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "summary_points",
        "work_items",
        "achievements",
        "blockers",
        "tomorrow_plan",
        "manager_attention",
    ],
    "properties": {
        "summary_points": {"type": "array", "maxItems": 6, "items": _REPORT_ITEM_SCHEMA},
        "work_items": {"type": "array", "maxItems": 24, "items": _REPORT_ITEM_SCHEMA},
        "achievements": {"type": "array", "maxItems": 24, "items": _REPORT_ITEM_SCHEMA},
        "blockers": {"type": "array", "maxItems": 16, "items": _REPORT_ITEM_SCHEMA},
        "tomorrow_plan": {"type": "array", "maxItems": 24, "items": _REPORT_ITEM_SCHEMA},
        "manager_attention": {"type": "array", "maxItems": 12, "items": _REPORT_ITEM_SCHEMA},
    },
}
