from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any

METRIC_REGISTRY_SCHEMA = "workspace-metric-registry/v1"
METRIC_REGISTRY_ID = "workspace-d3-core-metrics-v1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class MetricDefinition:
    metric_id: str
    name: str
    version: str
    output_path: str
    source_schema: str
    semantics: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


_DEFINITIONS = (
    MetricDefinition("D3-01", "Verified Task Success Rate", "v1", "verified_work.verified_task_success_rate", "workspace-verified-work-metrics/v1", "verified_tasks / attempted_tasks; verification requires immutable TaskContract and all required validators passing"),
    MetricDefinition("D3-02", "First-Pass Verified Success Rate", "v1", "verified_work.first_pass_verified_success_rate", "workspace-verified-work-metrics/v1", "tasks whose first recorded outcome for every required validator passed / attempted_tasks"),
    MetricDefinition("D3-03", "Total Tokens per Verified Task", "v1", "token_efficiency.total_tokens_per_verified_task", "workspace-token-per-verified-task/v1", "all attributable input+output tokens for selected attempted tasks / verified_tasks; failed and unverified task spend remains in numerator"),
    MetricDefinition("D3-04", "Resource Events per Verified Task", "v1", "resource_efficiency.tool_calls_per_verified_task + retries/escalations", "workspace-resource-per-verified-task/v1", "typed attributable tool calls, model retries and model escalations divided separately by verified_tasks"),
    MetricDefinition("D3-05", "Evidence Coverage", "v1", "evidence_coverage.evidence_coverage", "workspace-evidence-coverage/v1", "evidence_supported_material_claims / material_claims_requiring_evidence after aggregate claim-count summation"),
    MetricDefinition("D3-06", "Context Precision Proxy", "v1", "context_precision_proxy.context_precision_proxy", "workspace-context-precision-proxy/v1", "synthesis_cited_source_text_chars / synthesis_supplied_source_text_chars; source-level citation-character proxy, not true span precision"),
    MetricDefinition("D3-07", "Context Recall Proxy", "v1", "context_recall_proxy.context_recall_proxy", "workspace-context-recall-proxy/v1", "synthesis_supplied_source_text_chars / synthesis_vetted_source_text_chars; vetted-source character retention proxy, not semantic recall"),
)


def _canonical_sha256(payload: Any) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def validate_metric_registry_payload(payload: dict[str, Any]) -> str:
    if not isinstance(payload, dict) or payload.get("schema_version") != METRIC_REGISTRY_SCHEMA:
        raise ValueError(f"metric registry schema must be {METRIC_REGISTRY_SCHEMA}")
    if payload.get("registry_id") != METRIC_REGISTRY_ID:
        raise ValueError("metric registry_id is not recognized")
    metrics = payload.get("metrics")
    if not isinstance(metrics, list) or not metrics:
        raise ValueError("metric registry requires metric definitions")
    ids: list[str] = []
    required = {"metric_id", "name", "version", "output_path", "source_schema", "semantics"}
    for raw in metrics:
        if not isinstance(raw, dict) or set(raw) != required:
            raise ValueError("metric registry definition is incomplete")
        if any(not isinstance(raw[key], str) or not raw[key].strip() for key in required):
            raise ValueError("metric registry definition fields must be non-empty strings")
        ids.append(raw["metric_id"])
    if len(ids) != len(set(ids)):
        raise ValueError("metric registry contains duplicate metric_id values")
    expected = payload.get("registry_sha256")
    if not isinstance(expected, str) or not _SHA256_RE.fullmatch(expected):
        raise ValueError("metric registry_sha256 is invalid")
    canonical = dict(payload)
    canonical.pop("registry_sha256", None)
    actual = _canonical_sha256(canonical)
    if expected != actual:
        raise ValueError("metric registry_sha256 does not match registry content")
    return actual


class MetricRegistry:
    """Versioned identities for metrics used in optimization/promotion evidence."""

    def __init__(self, definitions: tuple[MetricDefinition, ...] = _DEFINITIONS):
        self.definitions = tuple(definitions)
        ids = [item.metric_id for item in self.definitions]
        if len(ids) != len(set(ids)):
            raise ValueError("metric registry contains duplicate metric_id values")
        if not self.definitions:
            raise ValueError("metric registry must not be empty")
        for item in self.definitions:
            if not item.metric_id or not item.version or not item.source_schema:
                raise ValueError("metric definitions require id, version and source schema")

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": METRIC_REGISTRY_SCHEMA,
            "registry_id": METRIC_REGISTRY_ID,
            "metrics": [item.to_dict() for item in self.definitions],
        }
        payload["registry_sha256"] = _canonical_sha256(payload)
        validate_metric_registry_payload(payload)
        return payload

    @property
    def sha256(self) -> str:
        return str(self.to_dict()["registry_sha256"])

    def metric_map(self) -> dict[str, str]:
        return {item.metric_id: item.output_path for item in self.definitions}


DEFAULT_METRIC_REGISTRY = MetricRegistry()
