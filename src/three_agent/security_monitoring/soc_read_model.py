from __future__ import annotations

from typing import Any

from .ai_analyst import AIAnalysisResult
from .contracts import MonitoringContractError, SEVERITIES
from .enterprise_truth import ENTERPRISE_TRUTH_STATES
from .reporting import DeterministicReport, PeriodSummary

SOC_READ_MODEL_SCHEMA_VERSION = "workspace-security-monitoring/soc-read-model-v1"
MAX_SOC_FINDINGS = 100
MAX_SOC_EVIDENCE_REFS = 512
MAX_SOC_EVIDENCE_REFS_PER_FINDING = 16
MAX_SOC_ANALYST_FINDINGS = 32
MAX_SOC_TOKEN_CHARS = 256

_FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "asset_refs",
        "allowed_evidence_ids",
        "authority",
        "command",
        "execute",
        "inventory",
        "label",
        "mutation",
        "policy",
        "raw_log",
        "raw_message",
        "remediation",
        "tool",
    }
)


def _token(value: object, field_name: str, *, max_len: int = MAX_SOC_TOKEN_CHARS) -> str:
    if not isinstance(value, str):
        raise MonitoringContractError(f"SOC {field_name} must be a string")
    text = value.strip()
    if not text or len(text) > max_len:
        raise MonitoringContractError(f"SOC {field_name} is invalid")
    return text


def _bounded_refs(values: object, field_name: str, *, limit: int) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise MonitoringContractError(f"SOC {field_name} must be a sequence")
    try:
        refs = tuple(values)  # type: ignore[arg-type]
    except TypeError as exc:
        raise MonitoringContractError(f"SOC {field_name} must be iterable") from exc
    normalized = tuple(dict.fromkeys(_token(value, field_name) for value in refs))
    return normalized[:limit]


def _period_view(period: PeriodSummary) -> dict[str, object]:
    if not isinstance(period, PeriodSummary):
        raise MonitoringContractError("SOC period must be PeriodSummary")
    return {
        "period": _token(period.label, "period label", max_len=32),
        "starts_at": _token(period.starts_at, "period starts_at", max_len=64),
        "ends_at": _token(period.ends_at, "period ends_at", max_len=64),
        "hourly_runs": int(period.hourly_runs),
        "average_coverage_pct": period.average_coverage_pct,
        "event_count": int(period.event_count),
        "finding_count": int(period.finding_count),
        "open_high_critical": int(period.open_high_critical),
        "data_gap_count": int(period.data_gap_count),
        "severity_counts": {
            _token(key, "severity", max_len=32): int(value)
            for key, value in sorted(period.severity_counts.items())
        },
    }


def _finding_view(finding: object) -> dict[str, object]:
    if not isinstance(finding, dict):
        raise MonitoringContractError("SOC finding must be an object")
    severity = _token(finding.get("severity"), "finding severity", max_len=32)
    if severity not in SEVERITIES:
        raise MonitoringContractError("SOC finding severity is unsupported")
    evidence_refs = _bounded_refs(
        finding.get("evidence_refs", ()),
        "finding evidence_refs",
        limit=MAX_SOC_EVIDENCE_REFS_PER_FINDING,
    )
    return {
        "finding_id": _token(finding.get("finding_id"), "finding_id"),
        "category": _token(finding.get("category"), "finding category", max_len=96),
        "severity": severity,
        "status": _token(finding.get("status"), "finding status", max_len=32),
        "first_seen": _token(finding.get("first_seen"), "finding first_seen", max_len=64),
        "last_seen": _token(finding.get("last_seen"), "finding last_seen", max_len=64),
        "rule_id": _token(finding.get("rule_id"), "finding rule_id"),
        "evidence_refs": list(evidence_refs),
    }


def _analyst_view(analysis: AIAnalysisResult | None) -> tuple[dict[str, object], ...]:
    if analysis is None:
        return ()
    if not isinstance(analysis, AIAnalysisResult):
        raise MonitoringContractError("SOC analyst input must be AIAnalysisResult")
    findings = analysis.enterprise_findings()
    if len(findings) > MAX_SOC_ANALYST_FINDINGS:
        findings = findings[:MAX_SOC_ANALYST_FINDINGS]
    result: list[dict[str, object]] = []
    for finding in findings:
        if set(finding) != {"truth_state", "statement", "evidence_ids"}:
            raise MonitoringContractError("SOC enterprise finding shape is invalid")
        truth_state = _token(finding["truth_state"], "truth_state", max_len=32)
        if truth_state not in ENTERPRISE_TRUTH_STATES:
            raise MonitoringContractError("SOC enterprise truth state is unsupported")
        statement = _token(finding["statement"], "analyst statement", max_len=2000)
        evidence_ids = _bounded_refs(
            finding["evidence_ids"],
            "analyst evidence_ids",
            limit=8,
        )
        if truth_state == "VERIFIED FACT" and not evidence_ids:
            raise MonitoringContractError("SOC VERIFIED FACT requires evidence")
        result.append(
            {
                "truth_state": truth_state,
                "statement": statement,
                "evidence_ids": list(evidence_ids),
            }
        )
    return tuple(result)


def _assert_public_shape(payload: dict[str, object]) -> None:
    stack: list[object] = [payload]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            forbidden = _FORBIDDEN_PUBLIC_KEYS.intersection(current)
            if forbidden:
                raise MonitoringContractError("SOC read model contains a forbidden public field")
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)


def build_soc_read_model(
    report: DeterministicReport,
    *,
    analysis: AIAnalysisResult | None = None,
) -> dict[str, object]:
    """Project validated monitoring truth into a bounded, read-only SOC view."""

    if not isinstance(report, DeterministicReport):
        raise MonitoringContractError("SOC source must be DeterministicReport")

    selected_findings = tuple(report.findings[:MAX_SOC_FINDINGS])
    finding_views = tuple(_finding_view(finding) for finding in selected_findings)

    evidence: list[str] = []
    for finding in finding_views:
        evidence.extend(str(ref) for ref in finding["evidence_refs"])
    evidence.extend(
        _bounded_refs(
            report.evidence_refs,
            "report evidence_refs",
            limit=MAX_SOC_EVIDENCE_REFS,
        )
    )
    evidence_refs = tuple(dict.fromkeys(evidence))[:MAX_SOC_EVIDENCE_REFS]

    payload: dict[str, object] = {
        "schema_version": SOC_READ_MODEL_SCHEMA_VERSION,
        "report_id": _token(report.report_id, "report_id"),
        "cutoff_at": _token(report.cutoff_at, "cutoff_at", max_len=64),
        "generated_at": _token(report.generated_at, "generated_at", max_len=64),
        "overview": {
            "today": _period_view(report.today),
            "rolling_7d": _period_view(report.rolling_7d),
            "rolling_30d": _period_view(report.rolling_30d),
        },
        "risk_summary": {
            "today_open_high_critical": int(report.today.open_high_critical),
            "rolling_7d_open_high_critical": int(report.rolling_7d.open_high_critical),
            "rolling_30d_open_high_critical": int(report.rolling_30d.open_high_critical),
            "today_data_gaps": int(report.today.data_gap_count),
        },
        "findings": list(finding_views),
        "omitted_findings": max(0, len(report.findings) - len(selected_findings)),
        "evidence_refs": list(evidence_refs),
        "analyst_findings": list(_analyst_view(analysis)),
    }
    _assert_public_shape(payload)
    return payload
