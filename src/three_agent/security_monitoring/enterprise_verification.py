from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Mapping

from .advanced_benchmark import AdvancedBenchmarkResult
from .contracts import MonitoringContractError, sha256_fingerprint
from .reporting import DeterministicReport

ENTERPRISE_VERIFICATION_SCHEMA = "workspace-security-monitoring/enterprise-verification-v1"
REPORT_EVIDENCE_COVERAGE_TARGET_PCT = 100.0
REQUIRED_ENTERPRISE_CHECKS = tuple(f"EV-{index:02d}" for index in range(1, 11))
_EVIDENCE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,255}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class EvidenceReferenceCoverage:
    material_findings: int
    fully_referenced_findings: int
    coverage_pct: float
    target_pct: float = REPORT_EVIDENCE_COVERAGE_TARGET_PCT

    @property
    def passed(self) -> bool:
        return self.coverage_pct >= self.target_pct


@dataclass(frozen=True)
class ResourceBenchmarkSnapshot:
    dataset_fingerprint: str
    baseline_detector: str
    candidate_detector: str
    baseline_wall_ms: float
    candidate_wall_ms: float
    baseline_cpu_ms: float
    candidate_cpu_ms: float
    baseline_peak_allocated_bytes: int
    candidate_peak_allocated_bytes: int
    baseline_state_bytes: int
    candidate_state_bytes: int
    baseline_llm_calls: int
    candidate_llm_calls: int
    candidate_external_dependencies: int
    decision: str
    production_promotion_authorized: bool


@dataclass(frozen=True)
class EnterpriseVerificationReceipt:
    source_sha: str
    checks: tuple[tuple[str, tuple[str, ...]], ...]
    report_evidence_coverage: EvidenceReferenceCoverage
    resource_benchmark: ResourceBenchmarkSnapshot
    real_lan_exercised: bool = False
    schema_version: str = ENTERPRISE_VERIFICATION_SCHEMA

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict(include_fingerprint=False))

    def to_dict(self, *, include_fingerprint: bool = True) -> dict:
        payload = {
            "schema_version": self.schema_version,
            "source_sha": self.source_sha,
            "checks": [
                {"check_id": check_id, "status": "pass", "evidence_refs": list(refs)}
                for check_id, refs in self.checks
            ],
            "report_evidence_coverage": {
                **asdict(self.report_evidence_coverage),
                "passed": self.report_evidence_coverage.passed,
            },
            "resource_benchmark": asdict(self.resource_benchmark),
            "real_lan_exercised": self.real_lan_exercised,
        }
        if include_fingerprint:
            payload["fingerprint"] = sha256_fingerprint(payload)
        return payload


def measure_report_evidence_coverage(report: DeterministicReport) -> EvidenceReferenceCoverage:
    """Require every material finding to reference evidence present in the report set."""
    report_refs = set(report.evidence_refs)
    material = 0
    referenced = 0
    for finding in report.findings:
        if not isinstance(finding, dict):
            raise MonitoringContractError("report finding must be an object")
        material += 1
        refs = finding.get("evidence_refs")
        if not isinstance(refs, (list, tuple)):
            continue
        normalized = tuple(str(ref) for ref in refs if str(ref))
        if normalized and all(ref in report_refs for ref in normalized):
            referenced += 1
    coverage = 100.0 if material == 0 else (referenced / material) * 100.0
    return EvidenceReferenceCoverage(
        material_findings=material,
        fully_referenced_findings=referenced,
        coverage_pct=coverage,
    )


def resource_benchmark_snapshot(result: AdvancedBenchmarkResult) -> ResourceBenchmarkSnapshot:
    """Record quality/resource observations without granting benchmark promotion authority."""
    return ResourceBenchmarkSnapshot(
        dataset_fingerprint=result.dataset_fingerprint,
        baseline_detector=result.baseline.detector_id,
        candidate_detector=result.candidate.detector_id,
        baseline_wall_ms=result.baseline.wall_ms,
        candidate_wall_ms=result.candidate.wall_ms,
        baseline_cpu_ms=result.baseline.cpu_ms,
        candidate_cpu_ms=result.candidate.cpu_ms,
        baseline_peak_allocated_bytes=result.baseline.peak_allocated_bytes,
        candidate_peak_allocated_bytes=result.candidate.peak_allocated_bytes,
        baseline_state_bytes=result.baseline.state_bytes,
        candidate_state_bytes=result.candidate.state_bytes,
        baseline_llm_calls=result.baseline.llm_calls,
        candidate_llm_calls=result.candidate.llm_calls,
        candidate_external_dependencies=result.candidate.external_dependencies,
        decision=result.decision,
        production_promotion_authorized=result.production_promotion_authorized,
    )


def build_enterprise_verification_receipt(
    *,
    source_sha: str,
    evidence: Mapping[str, tuple[str, ...] | list[str]],
    report: DeterministicReport,
    benchmark: AdvancedBenchmarkResult,
) -> EnterpriseVerificationReceipt:
    source = str(source_sha or "").strip().lower()
    if not _SHA_RE.fullmatch(source):
        raise MonitoringContractError("source_sha must be an exact 40-character Git SHA")
    if set(evidence) != set(REQUIRED_ENTERPRISE_CHECKS):
        raise MonitoringContractError("enterprise verification requires exactly EV-01..EV-10")

    checks: list[tuple[str, tuple[str, ...]]] = []
    for check_id in REQUIRED_ENTERPRISE_CHECKS:
        refs = tuple(dict.fromkeys(str(ref).strip() for ref in evidence[check_id] if str(ref).strip()))
        if not refs or any(not _EVIDENCE_REF_RE.fullmatch(ref) for ref in refs):
            raise MonitoringContractError(f"{check_id} requires compact evidence references")
        checks.append((check_id, refs))

    coverage = measure_report_evidence_coverage(report)
    if not coverage.passed:
        raise MonitoringContractError("EV-07 report evidence-reference coverage target not met")
    resources = resource_benchmark_snapshot(benchmark)
    if resources.baseline_llm_calls != 0 or resources.candidate_llm_calls != 0:
        raise MonitoringContractError("EV-10 anomaly benchmark must use zero LLM calls")
    if resources.candidate_external_dependencies != 0:
        raise MonitoringContractError("EV-10 benchmark candidate added an external dependency")
    if resources.production_promotion_authorized:
        raise MonitoringContractError("benchmark receipt cannot self-authorize production promotion")

    return EnterpriseVerificationReceipt(
        source_sha=source,
        checks=tuple(checks),
        report_evidence_coverage=coverage,
        resource_benchmark=resources,
        real_lan_exercised=False,
    )


def receipt_json(receipt: EnterpriseVerificationReceipt) -> str:
    return json.dumps(receipt.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
