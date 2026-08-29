from __future__ import annotations

from typing import Any

RESEARCH_PLAN_SCHEMA_ID = "workspace.research.plan/v1"
SOURCE_ASSESSMENT_SCHEMA_ID = "workspace.research.source-assessment/v1"
RESEARCH_SYNTHESIS_SCHEMA_ID = "workspace.research.synthesis/v1"

RESEARCH_PLAN_SCHEMA_V1: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["objective", "queries", "focus"],
    "properties": {
        "objective": {"type": "string", "minLength": 1, "maxLength": 1200},
        "queries": {
            "type": "array",
            "minItems": 1,
            "maxItems": 4,
            "items": {"type": "string", "minLength": 1, "maxLength": 500},
        },
        "focus": {
            "type": "array",
            "maxItems": 8,
            "items": {"type": "string", "minLength": 1, "maxLength": 300},
        },
    },
}

SOURCE_ASSESSMENT_SCHEMA_V1: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["sources"],
    "properties": {
        "sources": {
            "type": "array",
            "maxItems": 12,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "source_id",
                    "relevance",
                    "scope_match",
                    "time_match",
                    "authority",
                    "reason",
                ],
                "properties": {
                    "source_id": {"type": "string", "minLength": 1, "maxLength": 32},
                    "relevance": {"type": "string", "enum": ["high", "medium", "low"]},
                    "scope_match": {"type": "boolean"},
                    "time_match": {"type": ["boolean", "null"]},
                    "authority": {"type": "string", "enum": ["primary", "secondary", "unknown"]},
                    "reason": {"type": "string", "minLength": 1, "maxLength": 800},
                },
            },
        }
    },
}

_EVIDENCE_QUOTE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["source_id", "quote"],
    "properties": {
        "source_id": {"type": "string", "minLength": 1, "maxLength": 32},
        "quote": {"type": "string", "minLength": 1, "maxLength": 500},
    },
}

_CLAIM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["claim", "source_ids"],
    "properties": {
        "claim": {"type": "string", "minLength": 1, "maxLength": 2000},
        "source_ids": {
            "type": "array",
            "minItems": 1,
            "maxItems": 8,
            "items": {"type": "string", "minLength": 1, "maxLength": 32},
        },
        "evidence_quotes": {
            "type": "array",
            "maxItems": 8,
            "items": _EVIDENCE_QUOTE_SCHEMA,
        },
    },
}

_CONFLICT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["topic", "description", "severity", "source_ids"],
    "properties": {
        "topic": {"type": "string", "minLength": 1, "maxLength": 500},
        "description": {"type": "string", "minLength": 1, "maxLength": 1600},
        "severity": {"type": "string", "enum": ["low", "medium", "critical"]},
        "source_ids": {
            "type": "array",
            "minItems": 2,
            "maxItems": 8,
            "items": {"type": "string", "minLength": 1, "maxLength": 32},
        },
    },
}

RESEARCH_SYNTHESIS_SCHEMA_V1: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "verified_facts",
        "inferences",
        "conflicts",
        "unresolved",
        "conclusion",
        "recommended_next_actions",
    ],
    "properties": {
        "verified_facts": {
            "type": "array",
            "maxItems": 18,
            "items": _CLAIM_SCHEMA,
        },
        "inferences": {
            "type": "array",
            "maxItems": 6,
            "items": _CLAIM_SCHEMA,
        },
        "conflicts": {
            "type": "array",
            "maxItems": 6,
            "items": _CONFLICT_SCHEMA,
        },
        "unresolved": {
            "type": "array",
            "maxItems": 10,
            "items": {"type": "string", "minLength": 1, "maxLength": 1200},
        },
        "conclusion": {"type": "string", "maxLength": 2400},
        "recommended_next_actions": {
            "type": "array",
            "maxItems": 8,
            "items": {"type": "string", "minLength": 1, "maxLength": 800},
        },
    },
}
