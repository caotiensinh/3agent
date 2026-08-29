from __future__ import annotations

from typing import Any

PRESENTATION_PLAN_SCHEMA_ID = "workspace.presentation.plan/v1"

PRESENTATION_PLAN_SCHEMA_V1: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["title", "subtitle", "slides"],
    "properties": {
        "title": {"type": "string", "minLength": 1, "maxLength": 300},
        "subtitle": {"type": "string", "maxLength": 500},
        "slides": {
            "type": "array",
            "minItems": 1,
            "maxItems": 20,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "kind",
                    "title",
                    "claim_refs",
                    "proposal_points",
                    "context_points",
                    "speaker_notes",
                ],
                "properties": {
                    "kind": {
                        "type": "string",
                        "enum": [
                            "title",
                            "content",
                            "comparison",
                            "risks",
                            "decision",
                            "timeline",
                            "summary",
                        ],
                    },
                    "title": {"type": "string", "minLength": 1, "maxLength": 240},
                    "claim_refs": {
                        "type": "array",
                        "maxItems": 4,
                        "items": {"type": "string", "minLength": 1, "maxLength": 64},
                    },
                    "proposal_points": {
                        "type": "array",
                        "maxItems": 2,
                        "items": {"type": "string", "minLength": 1, "maxLength": 800},
                    },
                    "context_points": {
                        "type": "array",
                        "maxItems": 2,
                        "items": {"type": "string", "minLength": 1, "maxLength": 800},
                    },
                    "speaker_notes": {"type": "string", "maxLength": 1200},
                },
            },
        },
    },
}
