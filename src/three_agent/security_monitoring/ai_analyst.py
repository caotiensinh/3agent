from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from ..runtime_efficiency import StructuredOutputValidationError, validate_json_schema_subset
from .contracts import MonitoringContractError, SEVERITIES
from .correlation_graph import STAGE_ORDER
from .enterprise_truth import map_analyst_finding
from .network_triage import (
    CONFIDENCE_LEVELS,
    INVESTIGATION_PRIORITIES,
    NETWORK_TRIAGE_SCHEMA,
    SUPPORTED_RULES,
    TRIAGE_KINDS,
    NetworkIncidentTriage,
)
from .reporting import DeterministicReport, PeriodSummary

AI_ANALYSIS_SCHEMA_VERSION = "workspace-security-monitoring/ai-analysis-v1"
AI_ENTERPRISE_ANALYSIS_SCHEMA_VERSION = "workspace-security-monitoring/enterprise-ai-analysis-v1"
AI_EVIDENCE_PACK_SCHEMA_VERSION = "workspace-security-monitoring/ai-evidence-pack-v1"
AI_ANALYSIS_SCHEMA_ID = "workspace-security-monitoring/ai-analysis-schema-v1"
MAX_EVIDENCE_PACK_BYTES = 16 * 1024
MAX_FINDINGS_IN_PACK = 32
MAX_EVIDENCE_REFS_PER_FINDING = 8
MAX_NETWORK_TRIAGE_IN_PACK = 16
MAX_TRIAGE_EVIDENCE_REFS = 8
MAX_METRICS_PER_PERIOD = 6
MAX_ANALYSIS_ITEMS = 16
MAX_ALLOWED_EVIDENCE_IDS = 512
ANALYSIS_LABELS = ("FACT", "CORRELATION", "HYPOTHESIS", "RISK", "ACTION", "DATA GAP")

_SAFE_MODEL_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,255}$")
_TRIAGE_ID_RE = re.compile(r"^triage-[0-9a-f]{24}$")
_GRAPH_ID_RE = re.compile(r"^incident-[0-9a-f]{24}$")
_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TYPED_ENTITY_RE = re.compile(r"^entity:(ip|dns|user|process|service):sha256:[0-9a-f]{64}$")
_ASSET_REF_RE = re.compile(r"^asset:[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,127}$")
_TRIAGE_REASON_CODES = {
    "exact_dns_flow",
    "exact_flow_auth",
    "exact_auth_process",
    "ids_exact_entity_corroboration",
    "complete_exact_multistage_chain",
    "exact_post_connection_execution_chain",
    "exact_resolution_connection_auth_chain",
    "independent_ids_corroboration",
    "upstream_high_priority_evidence",
}

AI_ANALYSIS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["summary", "items"],
    "properties": {
        "summary": {"type": "string", "minLength": 1, "maxLength": 1200},
        "items": {
            "type": "array",
            "maxItems": MAX_ANALYSIS_ITEMS,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["label", "text", "evidence_refs"],
                "properties": {
                    "label": {"type": "string", "enum": list(ANALYSIS_LABELS)},
                    "text": {"type": "string", "minLength": 1, "maxLength": 500},
                    "evidence_refs": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 8,
                        "items": {"type": "string", "minLength": 1, "maxLength": 256},
                    },
                },
            },
        },
    },
}


class AnalystValidationError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code)
        super().__init__(self.reason_code)


@dataclass(frozen=True)
class AnalystEvidencePack:
    payload: dict[str, Any]
    canonical_json: str
    sha256: str
    byte_count: int
    allowed_evidence_ids: tuple[str, ...]
    omitted_findings: int


@dataclass(frozen=True)
class AIAnalysisResult:
    report_id: str
    status: str
    summary: str
    items: tuple[dict[str, Any], ...]
    evidence_pack_sha256: str
    model_calls: int
    retry_count: int
    failure_code: str | None = None
    schema_version: str = AI_ANALYSIS_SCHEMA_VERSION
    allowed_evidence_ids: tuple[str, ...] = ()

    def validate(self) -> "AIAnalysisResult":
        if self.status not in {"valid", "fallback", "not_requested"}:
            raise MonitoringContractError("unsupported AI analysis status")
        if not self.report_id or len(self.report_id) > 128:
            raise MonitoringContractError("invalid AI analysis report_id")
        if not self.summary or len(self.summary) > 1600:
            raise MonitoringContractError("invalid AI analysis summary")
        if self.model_calls < 0 or self.model_calls > 2:
            raise MonitoringContractError("AI analyst model_calls must be within 0..2")
        if self.retry_count < 0 or self.retry_count > 1:
            raise MonitoringContractError("AI analyst retry_count must be within 0..1")
        if self.retry_count > 0 and self.model_calls != 2:
            raise MonitoringContractError("AI analyst retry requires exactly two model calls")
        if self.status == "valid" and self.model_calls not in {1, 2}:
            raise MonitoringContractError("valid AI analysis requires a bounded model call")
        if self.status != "valid" and self.items:
            raise MonitoringContractError("fallback/not-requested AI analysis cannot carry model items")
        if self.failure_code is not None and len(self.failure_code) > 96:
            raise MonitoringContractError("AI analysis failure_code is too long")
        if not self.evidence_pack_sha256.startswith("sha256:") or len(self.evidence_pack_sha256) != 71:
            raise MonitoringContractError("AI evidence pack SHA-256 is invalid")
        if not isinstance(self.allowed_evidence_ids, tuple):
            raise MonitoringContractError("AI allowed evidence IDs must be a tuple")
        if len(self.allowed_evidence_ids) > MAX_ALLOWED_EVIDENCE_IDS:
            raise MonitoringContractError("AI allowed evidence IDs exceed bounds")
        if any(
            not isinstance(value, str) or not value or len(value) > 256
            for value in self.allowed_evidence_ids
        ):
            raise MonitoringContractError("AI allowed evidence ID is invalid")
        if len(set(self.allowed_evidence_ids)) != len(self.allowed_evidence_ids):
            raise MonitoringContractError("AI allowed evidence IDs must be unique")
        if self.status == "valid":
            try:
                _validate_model_analysis(
                    {"summary": self.summary, "items": [dict(item) for item in self.items]},
                    allowed_evidence_ids=self.allowed_evidence_ids,
                )
            except AnalystValidationError as exc:
                raise MonitoringContractError(
                    f"AI analysis result failed evidence validation: {exc.reason_code}"
                ) from exc
        return self

    def enterprise_findings(self) -> tuple[dict[str, object], ...]:
        """Return the public three-state analyst boundary without internal labels."""

        self.validate()
        if self.status != "valid":
            return ()
        return tuple(
            map_analyst_finding(
                label=str(item["label"]),
                statement=str(item["text"]),
                evidence_ids=tuple(item["evidence_refs"]),
                allowed_evidence_ids=self.allowed_evidence_ids,
            ).public_dict()
            for item in self.items
        )

    def public_dict(self) -> dict[str, object]:
        """Serialize only the enterprise truth-state boundary for external consumers."""

        self.validate()
        return {
            "schema_version": AI_ENTERPRISE_ANALYSIS_SCHEMA_VERSION,
            "report_id": self.report_id,
            "status": self.status,
            "summary": self.summary,
            "findings": list(self.enterprise_findings()),
            "evidence_pack_sha256": self.evidence_pack_sha256,
            "model_calls": self.model_calls,
            "retry_count": self.retry_count,
            "failure_code": self.failure_code,
        }


def _compact_metric(metric: Any) -> dict[str, Any]:
    return {
        "metric": str(metric.metric),
        "sample_count": int(metric.sample_count),
        "minimum": float(metric.minimum),
        "maximum": float(metric.maximum),
        "average": float(metric.average),
    }


def _compact_period(period: PeriodSummary) -> dict[str, Any]:
    return {
        "label": period.label,
        "starts_at": period.starts_at,
        "ends_at": period.ends_at,
        "hourly_runs": period.hourly_runs,
        "average_coverage_pct": period.average_coverage_pct,
        "event_count": period.event_count,
        "finding_count": period.finding_count,
        "open_high_critical": period.open_high_critical,
        "data_gap_count": period.data_gap_count,
        "severity_counts": dict(period.severity_counts),
        "finding_status_counts": dict(period.finding_status_counts),
        "metric_summaries": [
            _compact_metric(metric)
            for metric in period.metric_summaries[:MAX_METRICS_PER_PERIOD]
        ],
    }


def _finding_priority(finding: dict[str, Any]) -> tuple[int, int, str]:
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return (
        severity_rank.get(str(finding.get("severity")), 9),
        1 if finding.get("status") == "resolved" else 0,
        str(finding.get("finding_id") or ""),
    )


def _finding_view(finding: dict[str, Any]) -> dict[str, Any]:
    finding_id = str(finding.get("finding_id") or "")
    evidence_refs = tuple(
        str(ref)
        for ref in finding.get("evidence_refs", ())
        if isinstance(ref, str) and ref
    )[:MAX_EVIDENCE_REFS_PER_FINDING]
    return {
        "finding_ref": f"finding:{finding_id}",
        "category": str(finding.get("category") or "unknown"),
        "severity": str(finding.get("severity") or "unknown"),
        "status": str(finding.get("status") or "unknown"),
        "first_seen": str(finding.get("first_seen") or ""),
        "last_seen": str(finding.get("last_seen") or ""),
        "rule_id": str(finding.get("rule_id") or ""),
        "evidence_refs": list(evidence_refs),
    }


def _triage_priority(item: NetworkIncidentTriage) -> tuple[int, int, int, str]:
    priority_rank = {"high": 0, "elevated": 1, "normal": 2}
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    confidence_rank = {"high": 0, "medium": 1, "low": 2}
    return (
        priority_rank.get(item.investigation_priority, 9),
        severity_rank.get(item.severity, 9),
        confidence_rank.get(item.confidence, 9),
        item.triage_id,
    )


def _safe_model_token(value: object, field_name: str) -> str:
    text = str(value or "").strip()
    if not text or not _SAFE_MODEL_TOKEN_RE.fullmatch(text) or "://" in text:
        raise MonitoringContractError(f"network triage {field_name} is not a safe compact token")
    return text


def _safe_iso_timestamp(value: object, field_name: str) -> str:
    text = str(value or "").strip()
    if len(text) > 64 or _SAFE_MODEL_TOKEN_RE.fullmatch(text) is None:
        raise MonitoringContractError(f"network triage {field_name} is invalid")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"network triage {field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise MonitoringContractError(f"network triage {field_name} must include timezone")
    return text


def _triage_view(item: NetworkIncidentTriage) -> dict[str, Any]:
    if not isinstance(item, NetworkIncidentTriage):
        raise MonitoringContractError("AI analyst accepts NetworkIncidentTriage inputs only")
    if item.schema_version != NETWORK_TRIAGE_SCHEMA:
        raise MonitoringContractError("unsupported network triage schema for AI analyst")
    if item.authority != "advisory":
        raise MonitoringContractError("network triage must remain advisory before AI analysis")
    if item.triage_kind not in TRIAGE_KINDS:
        raise MonitoringContractError("network triage kind is unsupported")
    if item.confidence not in CONFIDENCE_LEVELS:
        raise MonitoringContractError("network triage confidence is unsupported")
    if item.investigation_priority not in INVESTIGATION_PRIORITIES:
        raise MonitoringContractError("network triage investigation priority is unsupported")
    if item.severity not in SEVERITIES:
        raise MonitoringContractError("network triage severity is unsupported")
    if _TRIAGE_ID_RE.fullmatch(item.triage_id) is None:
        raise MonitoringContractError("network triage_id is invalid")
    if _GRAPH_ID_RE.fullmatch(item.graph_id) is None:
        raise MonitoringContractError("network triage graph_id is invalid")
    if _FINGERPRINT_RE.fullmatch(item.graph_fingerprint) is None:
        raise MonitoringContractError("network triage graph_fingerprint is invalid")

    reason_codes = tuple(_safe_model_token(value, "reason_code") for value in item.reason_codes)
    stage_types = tuple(_safe_model_token(value, "stage_type") for value in item.stage_types)
    rule_ids = tuple(_safe_model_token(value, "rule_id") for value in item.rule_ids)
    event_ids = tuple(_safe_model_token(value, "event_id") for value in item.event_ids)
    evidence_refs = tuple(_safe_model_token(value, "evidence_ref") for value in item.evidence_refs)
    entity_refs = tuple(str(value or "").strip() for value in item.entity_refs)
    first_seen = _safe_iso_timestamp(item.first_seen, "first_seen")
    last_seen = _safe_iso_timestamp(item.last_seen, "last_seen")

    if not event_ids:
        raise MonitoringContractError("network triage must retain at least one event reference")
    if any(reason not in _TRIAGE_REASON_CODES for reason in reason_codes):
        raise MonitoringContractError("network triage reason code is unsupported")
    if any(stage not in STAGE_ORDER for stage in stage_types):
        raise MonitoringContractError("network triage stage is unsupported")
    if any(rule not in SUPPORTED_RULES for rule in rule_ids):
        raise MonitoringContractError("network triage rule is unsupported")
    if any(
        _ASSET_REF_RE.fullmatch(value) is None and _TYPED_ENTITY_RE.fullmatch(value) is None
        for value in entity_refs
    ):
        raise MonitoringContractError("network triage contains an invalid entity reference")
    if len(reason_codes) > 16 or len(stage_types) > 8 or len(rule_ids) > 8:
        raise MonitoringContractError("network triage analyst metadata exceeds bounds")

    # Deliberately omit event_ids and entity_refs from the model view. Event IDs are
    # preserved in deterministic triage storage, while raw/hashed identities never
    # need to enter the generative analyst prompt.
    return {
        "triage_ref": f"triage:{item.triage_id}",
        "graph_ref": f"graph:{item.graph_id}",
        "graph_fingerprint": item.graph_fingerprint,
        "triage_kind": item.triage_kind,
        "confidence": item.confidence,
        "severity": item.severity,
        "investigation_priority": item.investigation_priority,
        "reason_codes": list(reason_codes),
        "stage_types": list(stage_types),
        "rule_ids": list(rule_ids),
        "evidence_refs": list(evidence_refs[:MAX_TRIAGE_EVIDENCE_REFS]),
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


def _canonical_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def build_ai_evidence_pack(
    report: DeterministicReport,
    network_triage: Iterable[NetworkIncidentTriage] = (),
) -> AnalystEvidencePack:
    """Build a bounded model view; never include raw logs, packets, hosts or identities.

    With no network triage supplied, the payload and canonical SHA remain byte-for-byte
    compatible with the pre-v0.0.4 evidence-pack path.
    """

    ordered_findings = sorted((dict(item) for item in report.findings), key=_finding_priority)
    selected_findings = ordered_findings[:MAX_FINDINGS_IN_PACK]

    triage_items: list[NetworkIncidentTriage] = []
    for item in network_triage:
        # Validate before sorting so malformed direct construction fails closed rather
        # than entering priority or prompt logic.
        _triage_view(item)
        triage_items.append(item)
    ordered_triage = sorted(triage_items, key=_triage_priority)
    selected_triage = ordered_triage[:MAX_NETWORK_TRIAGE_IN_PACK]

    periods = {
        "today": _compact_period(report.today),
        "rolling_7d": _compact_period(report.rolling_7d),
        "rolling_30d": _compact_period(report.rolling_30d),
    }

    def assemble(
        findings: list[dict[str, Any]],
        triage: list[NetworkIncidentTriage],
    ) -> tuple[dict[str, Any], tuple[str, ...]]:
        finding_views = [_finding_view(item) for item in findings]
        triage_views = [_triage_view(item) for item in triage]
        allowed: list[str] = []
        for view in finding_views:
            allowed.append(view["finding_ref"])
            allowed.extend(view["evidence_refs"])
        for view in triage_views:
            allowed.append(view["triage_ref"])
            allowed.append(view["graph_ref"])
            allowed.extend(view["evidence_refs"])
        for key, period in periods.items():
            if int(period["data_gap_count"]) > 0:
                allowed.append(f"data-gap:{key}")
        allowed_ids = tuple(dict.fromkeys(allowed))
        payload = {
            "schema_version": AI_EVIDENCE_PACK_SCHEMA_VERSION,
            "report_id": report.report_id,
            "cutoff_at": report.cutoff_at,
            "periods": periods,
            "findings": finding_views,
            "allowed_evidence_ids": list(allowed_ids),
            "omitted_findings": len(ordered_findings) - len(findings),
            "authority": "advisory_only",
        }
        # Additive extension only when triage exists. The legacy report-only payload
        # remains exactly unchanged, including canonical JSON and evidence-pack SHA.
        if ordered_triage:
            payload["network_triage"] = triage_views
            payload["omitted_network_triage"] = len(ordered_triage) - len(triage)
        return payload, allowed_ids

    while True:
        payload, allowed_ids = assemble(selected_findings, selected_triage)
        canonical = _canonical_payload(payload)
        byte_count = len(canonical.encode("utf-8"))
        if byte_count <= MAX_EVIDENCE_PACK_BYTES:
            return AnalystEvidencePack(
                payload=payload,
                canonical_json=canonical,
                sha256="sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                byte_count=byte_count,
                allowed_evidence_ids=allowed_ids,
                omitted_findings=len(ordered_findings) - len(selected_findings),
            )
        # Preserve the highest-priority correlated network incidents under pressure.
        # Existing behavior is unchanged when no network triage was supplied.
        if selected_findings:
            selected_findings.pop()
            continue
        if selected_triage:
            selected_triage.pop()
            continue
        raise MonitoringContractError("AI_EVIDENCE_PACK_BUDGET_EXCEEDED")


def _validate_model_analysis(payload: Any, *, allowed_evidence_ids: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise AnalystValidationError("AI_SCHEMA_INVALID")
    try:
        validate_json_schema_subset(payload, AI_ANALYSIS_SCHEMA)
    except StructuredOutputValidationError as exc:
        raise AnalystValidationError("AI_SCHEMA_INVALID") from exc

    allowed = set(allowed_evidence_ids)
    for item in payload.get("items", []):
        for evidence_ref in item.get("evidence_refs", []):
            if evidence_ref not in allowed:
                raise AnalystValidationError("AI_EVIDENCE_REF_UNKNOWN")
    return payload


def _fallback_summary(report: DeterministicReport, reason_code: str) -> str:
    today = report.today
    coverage = "DATA GAP" if today.average_coverage_pct is None else f"{today.average_coverage_pct:.3f}%"
    return (
        f"Deterministic report retained: coverage={coverage}; events={today.event_count}; "
        f"findings={today.finding_count}; open_high_critical={today.open_high_critical}; "
        f"data_gaps={today.data_gap_count}; AI={reason_code}."
    )


class LocalAIAnalyst:
    """Advisory-only local analyzer with no tool/capability interface.

    The client is expected to provide ``generate_json``. This class supplies no
    network tool, shell, inventory mutation, severity mutation or remediation API.
    One normal call is used. Only deterministic output-validation failure can trigger
    one retry; transport/model exceptions fall back immediately to NS-4 truth.
    """

    def __init__(self, client: Any):
        self.client = client

    def analyze(
        self,
        report: DeterministicReport,
        *,
        enabled: bool = True,
        network_triage: Iterable[NetworkIncidentTriage] = (),
    ) -> AIAnalysisResult:
        pack = build_ai_evidence_pack(report, network_triage)
        if not enabled:
            return AIAnalysisResult(
                report_id=report.report_id,
                status="not_requested",
                summary=_fallback_summary(report, "NOT_REQUESTED"),
                items=(),
                evidence_pack_sha256=pack.sha256,
                model_calls=0,
                retry_count=0,
            ).validate()

        # Skip inference only when there is no material finding, correlated network
        # triage record, or explicit data gap.
        has_network_triage = bool(pack.payload.get("network_triage"))
        if (
            not pack.payload["findings"]
            and not has_network_triage
            and all(int(period["data_gap_count"]) == 0 for period in pack.payload["periods"].values())
        ):
            return AIAnalysisResult(
                report_id=report.report_id,
                status="not_requested",
                summary=_fallback_summary(report, "NO_MATERIAL_EVIDENCE"),
                items=(),
                evidence_pack_sha256=pack.sha256,
                model_calls=0,
                retry_count=0,
            ).validate()

        if has_network_triage:
            system_prompt = (
                "You are the local WorkSpace Security Analyst. You are advisory only. "
                "Use only supplied evidence IDs. Deterministic network_triage is correlated "
                "review context, not proof of compromise and never authorization to act. "
                "Never claim authority, change severity, change inventory, execute tools, "
                "or claim remediation occurred."
            )
            base_prompt = (
                "Analyze this compact validated evidence pack. Label every item exactly as "
                "FACT, CORRELATION, HYPOTHESIS, RISK, ACTION, or DATA GAP. Every item must "
                "cite one or more IDs from allowed_evidence_ids. Treat network_triage as "
                "bounded advisory context only. Return only schema JSON.\n"
                + pack.canonical_json
            )
        else:
            # Preserve the pre-v0.0.4 prompt exactly for report-only callers.
            system_prompt = (
                "You are the local WorkSpace Security Analyst. You are advisory only. "
                "Use only supplied evidence IDs. Never claim authority, change severity, "
                "change inventory, execute tools, or claim remediation occurred."
            )
            base_prompt = (
                "Analyze this compact validated evidence pack. Label every item exactly as "
                "FACT, CORRELATION, HYPOTHESIS, RISK, ACTION, or DATA GAP. Every item must "
                "cite one or more IDs from allowed_evidence_ids. Return only schema JSON.\n"
                + pack.canonical_json
            )

        model_calls = 0
        retry_count = 0
        reason_code: str | None = None

        for attempt in range(2):
            prompt = base_prompt
            if attempt == 1:
                retry_count = 1
                prompt = (
                    "Previous output failed deterministic validation. Correct only the "
                    f"following reason code: {reason_code}. Do not expand scope.\n" + base_prompt
                )
            try:
                model_calls += 1
                candidate = self.client.generate_json(
                    system_prompt,
                    prompt,
                    schema=AI_ANALYSIS_SCHEMA,
                    schema_id=AI_ANALYSIS_SCHEMA_ID,
                    think=False,
                    num_predict=1200,
                    trust_domain="security-analyst-confidential",
                    template_version="workspace.security-analyst.v1",
                )
            except Exception:
                return AIAnalysisResult(
                    report_id=report.report_id,
                    status="fallback",
                    summary=_fallback_summary(report, "AI_UNAVAILABLE"),
                    items=(),
                    evidence_pack_sha256=pack.sha256,
                    model_calls=model_calls,
                    retry_count=retry_count,
                    failure_code="AI_UNAVAILABLE",
                ).validate()

            try:
                validated = _validate_model_analysis(
                    candidate,
                    allowed_evidence_ids=pack.allowed_evidence_ids,
                )
            except AnalystValidationError as exc:
                reason_code = exc.reason_code
                if attempt == 0:
                    continue
                return AIAnalysisResult(
                    report_id=report.report_id,
                    status="fallback",
                    summary=_fallback_summary(report, reason_code),
                    items=(),
                    evidence_pack_sha256=pack.sha256,
                    model_calls=model_calls,
                    retry_count=retry_count,
                    failure_code=reason_code,
                ).validate()

            return AIAnalysisResult(
                report_id=report.report_id,
                status="valid",
                summary=str(validated["summary"]),
                items=tuple(dict(item) for item in validated["items"]),
                evidence_pack_sha256=pack.sha256,
                model_calls=model_calls,
                retry_count=retry_count,
                allowed_evidence_ids=pack.allowed_evidence_ids,
            ).validate()

        raise AssertionError("unreachable")


def write_ai_analysis_sidecar(result: AIAnalysisResult, *, root: Path) -> Path:
    """Write optional AI output outside the canonical NS-4 report bundle/manifest."""

    result.validate()
    base = Path(root)
    if not base.is_absolute() or base.is_symlink():
        raise MonitoringContractError("AI analysis root must be an absolute non-symlink path")
    destination_dir = base / "ai-analysis"
    destination_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    final = destination_dir / f"{result.report_id}.json"
    temp = destination_dir / f".{result.report_id}.{os.getpid()}.tmp"
    payload = json.dumps(result.public_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    temp.write_text(payload, encoding="utf-8")
    os.replace(temp, final)
    return final
