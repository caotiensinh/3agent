from __future__ import annotations

from typing import Any

from .daily_report_schemas import DAILY_REPORT_SCHEMA_ID, DAILY_REPORT_SCHEMA_V1
from .presentation_schemas import PRESENTATION_PLAN_SCHEMA_ID, PRESENTATION_PLAN_SCHEMA_V1
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

_AGENT_SINGLE_ROUTES: dict[str, tuple[str, dict[str, Any], str]] = {
    "presentation": (
        "Plan an evidence-bounded professional presentation.",
        PRESENTATION_PLAN_SCHEMA_V1,
        PRESENTATION_PLAN_SCHEMA_ID,
    ),
    "daily_report": (
        "Create a concise Japanese R&D daily report using ONLY the JSON evidence below.",
        DAILY_REPORT_SCHEMA_V1,
        DAILY_REPORT_SCHEMA_ID,
    ),
}


class StructuredOutputPolicyClient:
    """Schema policy plus metadata-only receipts for structured generation.

    Receipts contain no prompt, response, evidence, business text, or chain of
    thought. They exist so artifacts can prove which deterministic structural
    contract was applied and whether the constrained call validated or failed.
    """

    def __init__(self, client: Any, *, agent_id: str):
        self._client = client
        self.agent_id = str(agent_id)
        self._receipts: list[dict[str, Any]] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)

    def _schema_route(self, user_prompt: str) -> tuple[dict[str, Any], str] | None:
        if self.agent_id == "research":
            for marker, schema, schema_id in _RESEARCH_ROUTES:
                if marker in user_prompt:
                    return schema, schema_id
            raise StructuredOutputPolicyError(
                "Research structured-output call has no registered schema route"
            )

        route = _AGENT_SINGLE_ROUTES.get(self.agent_id)
        if route is None:
            return None
        marker, schema, schema_id = route
        if marker not in user_prompt:
            raise StructuredOutputPolicyError(
                f"{self.agent_id} structured-output call has no registered schema route"
            )
        return schema, schema_id

    def structured_output_receipts(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self._receipts]

    def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        route = self._schema_route(user_prompt)
        schema_id: str | None = None
        if route is not None:
            schema, schema_id = route
            kwargs = dict(kwargs)
            kwargs["schema"] = schema
            kwargs["schema_id"] = schema_id

        try:
            result = self._client.generate_json(system_prompt, user_prompt, **kwargs)
        except Exception as exc:
            if schema_id is not None:
                self._receipts.append(
                    {
                        "agent_id": self.agent_id,
                        "schema_id": schema_id,
                        "validator": "local-json-schema-subset",
                        "status": "failed",
                        "error_type": type(exc).__name__,
                        "raw_content_logged": False,
                    }
                )
            raise

        if schema_id is not None:
            self._receipts.append(
                {
                    "agent_id": self.agent_id,
                    "schema_id": schema_id,
                    "validator": "local-json-schema-subset",
                    "status": "validated",
                    "error_type": None,
                    "raw_content_logged": False,
                }
            )
        return result
