from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import AppConfig
from .evidence_packing import resolve_evidence_packing_policy
from .metric_registry import validate_metric_registry_payload

BENCHMARK_SCHEMA = "workspace-benchmark-snapshot/v1"
METRICS_SCHEMA = "workspace-unified-metrics/v1"
_SOURCE_REF_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_VARIANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _task_scope(metrics: dict[str, Any]) -> list[str]:
    if metrics.get("schema_version") != METRICS_SCHEMA:
        raise ValueError(f"metrics schema must be {METRICS_SCHEMA}")
    scope = metrics.get("scope")
    if not isinstance(scope, dict):
        raise ValueError("metrics.scope is required")
    raw_ids = scope.get("task_ids")
    if not isinstance(raw_ids, list) or any(
        not isinstance(item, str) or not item.strip() for item in raw_ids
    ):
        raise ValueError("metrics.scope.task_ids must contain non-empty strings")
    ids = [item.strip() for item in raw_ids]
    if len(set(ids)) != len(ids):
        raise ValueError("metrics.scope.task_ids must not contain duplicates")
    count = scope.get("selected_task_count")
    if isinstance(count, bool) or not isinstance(count, int) or count != len(ids):
        raise ValueError("metrics.scope.selected_task_count does not match task_ids")
    if not ids:
        raise ValueError("benchmark capture requires a non-empty fixed task set")
    return sorted(ids)


def _metric_registry_hash(metrics: dict[str, Any]) -> str | None:
    payload = metrics.get("metric_registry")
    if payload is None:
        return None  # legacy unified-metrics/v1 snapshot
    if not isinstance(payload, dict):
        raise ValueError("metrics.metric_registry must be an object")
    return validate_metric_registry_payload(payload)


def effective_config_fingerprint(config: AppConfig) -> str:
    """Hash effective optimization/security controls without serializing raw config."""
    internet = config.internet_gateway
    execution = config.execution_gateway
    evidence_packing = resolve_evidence_packing_policy()
    payload = {
        "environment": config.environment,
        "confidentiality_mode": config.confidentiality_mode,
        "test_mode_full_access": config.test_mode_full_access,
        "llm": asdict(config.llm),
        "model_policy": asdict(config.model_policy) if config.model_policy else None,
        "evidence_packing": evidence_packing.to_fingerprint_dict(),
        "internet_gateway": {
            "enabled": internet.enabled,
            "allow_all": internet.allow_all,
            "mode": internet.mode,
            "public_search_enabled": internet.public_search_enabled,
            "allowed_search_hosts": list(internet.allowed_search_hosts),
            "allowed_content_hosts": list(internet.allowed_content_hosts),
            "max_response_bytes": internet.max_response_bytes,
            "max_query_chars": internet.max_query_chars,
            "grant_ttl_seconds": internet.grant_ttl_seconds,
            "direct_egress": internet.direct_egress,
            "broker_timeout_seconds": internet.broker_timeout_seconds,
            "broker_enabled": internet.broker_socket is not None,
        },
        "execution_gateway": {
            "enabled": execution.enabled,
            "allow_all": execution.allow_all,
            "mode": execution.mode,
        },
    }
    return _canonical_sha256(payload)


def build_benchmark_manifest(
    metrics: dict[str, Any],
    config: AppConfig,
    *,
    variant_label: str,
    source_ref: str,
    captured_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(metrics, dict):
        raise ValueError("metrics must be a JSON object")
    task_ids = _task_scope(metrics)
    registry_hash = _metric_registry_hash(metrics)
    label = str(variant_label or "").strip()
    if not _VARIANT_RE.fullmatch(label):
        raise ValueError(
            "variant_label must be 1-80 characters using letters, digits, '.', '_' or '-'"
        )
    source = str(source_ref or "").strip().lower()
    if not _SOURCE_REF_RE.fullmatch(source):
        raise ValueError("source_ref must be an exact 40-hex Git commit SHA")
    timestamp = captured_at or datetime.now(timezone.utc).isoformat()
    if not isinstance(timestamp, str) or not timestamp.strip():
        raise ValueError("captured_at must be a non-empty timestamp string")

    lineage = {
        "variant_label": label,
        "source_ref": source,
        "configuration_sha256": effective_config_fingerprint(config),
        "task_scope_sha256": _canonical_sha256(task_ids),
        "metrics_sha256": _canonical_sha256(metrics),
        "captured_at": timestamp,
    }
    if registry_hash is not None:
        lineage["metric_registry_sha256"] = registry_hash
    return {
        "schema_version": BENCHMARK_SCHEMA,
        "lineage": lineage,
        "metrics": metrics,
    }


def unpack_metrics_payload(
    payload: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Return a validated unified metrics object and optional benchmark lineage."""
    if not isinstance(payload, dict):
        raise ValueError("metrics payload must be a JSON object")
    schema = payload.get("schema_version")
    if schema == METRICS_SCHEMA:
        _task_scope(payload)
        _metric_registry_hash(payload)
        return payload, None
    if schema != BENCHMARK_SCHEMA:
        raise ValueError(
            f"metrics payload schema must be {METRICS_SCHEMA} or {BENCHMARK_SCHEMA}"
        )

    lineage = payload.get("lineage")
    metrics = payload.get("metrics")
    if not isinstance(lineage, dict) or not isinstance(metrics, dict):
        raise ValueError("benchmark manifest requires lineage and metrics objects")
    task_ids = _task_scope(metrics)
    registry_hash = _metric_registry_hash(metrics)

    label = lineage.get("variant_label")
    source_ref = lineage.get("source_ref")
    config_hash = lineage.get("configuration_sha256")
    scope_hash = lineage.get("task_scope_sha256")
    metrics_hash = lineage.get("metrics_sha256")
    captured_at = lineage.get("captured_at")
    if not isinstance(label, str) or not _VARIANT_RE.fullmatch(label):
        raise ValueError("benchmark lineage variant_label is invalid")
    if not isinstance(source_ref, str) or not _SOURCE_REF_RE.fullmatch(source_ref):
        raise ValueError("benchmark lineage source_ref is invalid")
    if not isinstance(config_hash, str) or not _SHA256_RE.fullmatch(config_hash):
        raise ValueError("benchmark lineage configuration_sha256 is invalid")
    if not isinstance(scope_hash, str) or scope_hash != _canonical_sha256(task_ids):
        raise ValueError("benchmark lineage task_scope_sha256 does not match metrics scope")
    if not isinstance(metrics_hash, str) or metrics_hash != _canonical_sha256(metrics):
        raise ValueError("benchmark lineage metrics_sha256 does not match metrics payload")
    if not isinstance(captured_at, str) or not captured_at.strip():
        raise ValueError("benchmark lineage captured_at is invalid")
    recorded_registry = lineage.get("metric_registry_sha256")
    if registry_hash is not None:
        if recorded_registry != registry_hash:
            raise ValueError("benchmark lineage metric_registry_sha256 does not match metrics registry")
    elif recorded_registry is not None:
        raise ValueError("legacy metrics cannot claim a metric registry fingerprint")
    return metrics, dict(lineage)


def write_benchmark_manifest(
    path: Path,
    manifest: dict[str, Any],
    *,
    overwrite: bool = False,
) -> Path:
    destination = Path(path)
    if destination.exists() and not overwrite:
        raise FileExistsError(f"benchmark output already exists: {destination}")
    unpack_metrics_payload(manifest)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)
    return destination
