from __future__ import annotations

from typing import Any

from .research_schemas import (
    RESEARCH_PLAN_SCHEMA_ID,
    RESEARCH_PLAN_SCHEMA_V1,
    RESEARCH_SYNTHESIS_SCHEMA_ID,
    RESEARCH_SYNTHESIS_SCHEMA_V1,
    SOURCE_ASSESSMENT_SCHEMA_ID,
    SOURCE_ASSESSMENT_SCHEMA_V1,
)


class StructuredOutputPolicyError(RuntimeError):
    """A schema-governed agent attempted an unknown structured-output path."""


_RESEARCH_ROUTES: tuple[tuple[str, dict[str, Any], str], ...] = (
    (
        "Create a concise web-research plan for this task.",
        RESEARCH_PLAN_SCHEMA_V1,
        RESEARCH_PLAN_SCHEMA_ID,
    ),
    (
        "You are a source suitability gate, not a research answer generator.",
        SOURCE_ASSESSMENT_SCHEMA_V1,
        SOURCE_ASSESSMENT_SCHEMA_ID,
    ),
    (
        "You are completing an evidence-bounded research task using sources that already passed a suitability gate.",
        RESEARCH_SYNTHESIS_SCHEMA_V1,
        RESEARCH_SYNTHESIS_SCHEMA_ID,
    ),
)


class StructuredOutputPolicyClient:
    """Deterministic schema policy wrapper around the configured local LLM client.

    The agent owns *what* operation it is performing; this harness layer owns the
    structural contract. Research is fail-closed: every structured generation path
    currently present in ResearchAgent must match one registered schema route.
    Other agents remain pass-through until their D2 checklist item is implemented.
    """

    def __init__(self, client: Any, *, agent_id: str):
        self._client = client
        self.agent_id = str(agent_id)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)

    def _research_schema(self, user_prompt: str) -> tuple[dict[str, Any], str]:
        for marker, schema, schema_id in _RESEARCH_ROUTES:
            if marker in user_prompt:
                return schema, schema_id
        raise StructuredOutputPolicyError(
            "Research structured-output call has no registered schema route"
        )

    def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        if self.agent_id == "research":
            schema, schema_id = self._research_schema(user_prompt)
            kwargs = dict(kwargs)
            kwargs["schema"] = schema
            kwargs["schema_id"] = schema_id
        return self._client.generate_json(system_prompt, user_prompt, **kwargs)
