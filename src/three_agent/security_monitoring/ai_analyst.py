from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..runtime_efficiency import StructuredOutputValidationError, validate_json_schema_subset
from .contracts import MonitoringContractError
from .reporting import DeterministicReport, PeriodSummary

AI_ANALYSIS_SCHEMA_VERSION = "workspace-security-monitoring/ai-analysis-v1"
AI_EVIDENCE_PACK_SCHEMA_VERSION = "workspace-security-monitoring/ai-evidence-pack-v1"
AI_ANALYSIS_SCHEMA_ID = "workspace-security-monitoring/ai-analysis-schema-v1"
MAX_EVIDENCE_PACK_BYTES = 16 * 1024
MAX_FINDINGS_IN_PACK = 32
MAX_EVIDENCE_REFS_PER_FINDING = 8
MAX_METRICS_PER_PERIOD = 6
MAX_ANALYSIS_ITEMS = 16
ANALYSIS_LABELS = ("FACT", "CORRELATION", "HYPOTHESIS", "RISK", "ACTION", "DATA GAP")

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
        return self


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


def _canonical_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def build_ai_evidence_pack(report: DeterministicReport) -> AnalystEvidencePack:
    """Build a small, validated-ID-only model view; never include raw logs/packets/hosts."""

    ordered_findings = sorted((dict(item) for item in report.findings), key=_finding_priority)
    selected = ordered_findings[:MAX_FINDINGS_IN_PACK]
    periods = {
        "today": _compact_period(report.today),
        "rolling_7d": _compact_period(report.rolling_7d),
        "rolling_30d": _compact_period(report.rolling_30d),
    }

    def assemble(findings: list[dict[str, Any]]) -> tuple[dict[str, Any], tuple[str, ...]]:
        views = [_finding_view(item) for item in findings]
        allowed: list[str] = []
        for view in views:
            allowed.append(view["finding_ref"])
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
            "findings": views,
            "allowed_evidence_ids": list(allowed_ids),
            "omitted_findings": len(ordered_findings) - len(findings),
            "authority": "advisory_only",
        }
        return payload, allowed_ids

    while True:
        payload, allowed_ids = assemble(selected)
        canonical = _canonical_payload(payload)
        byte_count = len(canonical.encode("utf-8"))
        if byte_count <= MAX_EVIDENCE_PACK_BYTES:
            return AnalystEvidencePack(
                payload=payload,
                canonical_json=canonical,
                sha256="sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                byte_count=byte_count,
                allowed_evidence_ids=allowed_ids,
                omitted_findings=len(ordered_findings) - len(selected),
            )
        if selected:
            selected.pop()
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

    def analyze(self, report: DeterministicReport, *, enabled: bool = True) -> AIAnalysisResult:
        pack = build_ai_evidence_pack(report)
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

        # Skip inference when there is no material finding or explicit data gap.
        if not pack.payload["findings"] and all(
            int(period["data_gap_count"]) == 0 for period in pack.payload["periods"].values()
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
    payload = json.dumps(asdict(result), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    temp.write_text(payload, encoding="utf-8")
    os.replace(temp, final)
    return final
