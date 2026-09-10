from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint
from .forensic_evidence import (
    CaseAuthorization,
    CustodyEvent,
    EvidenceObject,
    EvidenceProvenance,
    ForensicEventTime,
    verify_custody_chain,
)

DFIR_CONFORMANCE_SCHEMA = "workspace-security-forensics/conformance-v1"
DFIR_CONFORMANCE_CASES = (
    "C1_VALID_EVIDENCE",
    "C2_TAMPERED_CONTENT_HASH",
    "T1_EVIDENCE_SCOPE_ESCAPE",
    "P1_PERMISSION_ESCALATION",
    "B1_BROKEN_CUSTODY_CHAIN",
)


@dataclass(frozen=True)
class DFIRConformanceResult:
    case_id: str
    expected: str
    actual: str
    passed: bool
    reason_code: str
    schema_version: str = DFIR_CONFORMANCE_SCHEMA

    def public_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "expected": self.expected,
            "actual": self.actual,
            "passed": self.passed,
            "reason_code": self.reason_code,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


def _baseline_evidence() -> EvidenceObject:
    return EvidenceObject(
        evidence_id="evidence:conformance-c1",
        evidence_type="dns",
        content_sha256=sha256_fingerprint({"fixture": "dns-content"}),
        byte_size=128,
        data_class="confidential",
        provenance=EvidenceProvenance(
            source_id="asset-conformance-01",
            source_type="fixture",
            collected_at="2026-09-03T00:00:10+09:00",
            producer_id="dfir-conformance",
            producer_version="v1",
            source_content_sha256=sha256_fingerprint({"fixture": "source-record"}),
        ).validate(),
        event_time=ForensicEventTime(
            original_timestamp="2026-09-03T00:00:05+09:00",
            normalized_utc="2026-09-02T15:00:05Z",
            source_clock_ref="clock:fixture",
            uncertainty_ms=0,
        ).validate(),
    ).validate()


def _baseline_authorization() -> CaseAuthorization:
    return CaseAuthorization(
        case_scope_id="dfir-conformance-scope",
        approved_asset_refs=("asset-conformance-01",),
        allowed_evidence_types=("dns",),
    ).validate()


def _run_case(case_id: str) -> tuple[str, str]:
    evidence = _baseline_evidence()
    authorization = _baseline_authorization()

    if case_id == "C1_VALID_EVIDENCE":
        evidence.validate()
        authorization.validate()
        return "accept", "VALID_CANONICAL_EVIDENCE"

    if case_id == "C2_TAMPERED_CONTENT_HASH":
        replace(evidence, content_sha256="sha256:" + "g" * 64).validate()
        return "accept", "UNEXPECTED_ACCEPT"

    if case_id == "T1_EVIDENCE_SCOPE_ESCAPE":
        escaped = replace(evidence, evidence_type="host_log").validate()
        if escaped.evidence_type not in authorization.allowed_evidence_types:
            raise MonitoringContractError("EVIDENCE_TYPE_OUTSIDE_CASE_SCOPE")
        return "accept", "UNEXPECTED_ACCEPT"

    if case_id == "P1_PERMISSION_ESCALATION":
        replace(authorization, case_grants_network_access=True).validate()
        return "accept", "UNEXPECTED_ACCEPT"

    if case_id == "B1_BROKEN_CUSTODY_CHAIN":
        actor = "actor:" + sha256_fingerprint({"actor": "analyst"})
        first = CustodyEvent.build(
            event_index=1,
            evidence_id=evidence.evidence_id,
            action="registered",
            actor_ref=actor,
            occurred_at="2026-09-03T00:01:00+09:00",
            previous_event_sha256=None,
        )
        second = CustodyEvent.build(
            event_index=2,
            evidence_id=evidence.evidence_id,
            action="verified",
            actor_ref=actor,
            occurred_at="2026-09-03T00:02:00+09:00",
            previous_event_sha256=sha256_fingerprint({"wrong": "previous"}),
        )
        verify_custody_chain((first, second))
        return "accept", "UNEXPECTED_ACCEPT"

    raise MonitoringContractError("UNKNOWN_DFIR_CONFORMANCE_CASE")


def run_dfir_conformance(case_ids: Iterable[str] = DFIR_CONFORMANCE_CASES) -> tuple[DFIRConformanceResult, ...]:
    rows: list[DFIRConformanceResult] = []
    seen: set[str] = set()
    for case_id in case_ids:
        if case_id in seen or case_id not in DFIR_CONFORMANCE_CASES:
            raise MonitoringContractError("DFIR_CONFORMANCE_CASE_SET_INVALID")
        seen.add(case_id)
        expected = "accept" if case_id == "C1_VALID_EVIDENCE" else "reject"
        try:
            actual, reason = _run_case(case_id)
        except MonitoringContractError as exc:
            actual, reason = "reject", str(exc)
        rows.append(
            DFIRConformanceResult(
                case_id=case_id,
                expected=expected,
                actual=actual,
                passed=actual == expected,
                reason_code=reason,
            )
        )
    return tuple(rows)


def conformance_fingerprint(results: Iterable[DFIRConformanceResult]) -> str:
    rows = tuple(results)
    if not rows or any(not row.passed for row in rows):
        raise MonitoringContractError("DFIR_CONFORMANCE_NOT_PASSING")
    return sha256_fingerprint([row.public_dict() for row in rows])
