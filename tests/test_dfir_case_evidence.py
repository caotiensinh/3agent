from dataclasses import replace

import pytest

from three_agent.security_monitoring.dfir_case_evidence import (
    CaseAuthorization,
    CaseRecord,
    CustodyChain,
    CustodyEvent,
    DFIRCaseEvidenceError,
    ForensicEvidenceObject,
    ForensicTimeProvenance,
    admit_case_evidence,
)
from three_agent.security_monitoring.normalized_evidence import (
    EvidenceIntegrity,
    EvidenceObservationWindow,
    EvidenceProvenance,
    EvidenceQuality,
    NormalizedEvidence,
)


def _sha(ch: str) -> str:
    return "sha256:" + ch * 64


def _authorization() -> CaseAuthorization:
    return CaseAuthorization(
        authorization_ref_sha256=_sha("a"),
        task_ref_sha256=_sha("b"),
        approved_asset_refs=("asset-1",),
        allowed_sensitivities=("internal", "confidential"),
    ).validate()


def _normalized(*, asset_ref: str = "asset-1", content_sha: str | None = None) -> NormalizedEvidence:
    return NormalizedEvidence.create(
        evidence_type="network_flow",
        source_type="zeek",
        asset_ref=asset_ref,
        task_ref_sha256=_sha("b"),
        authorization_ref_sha256=_sha("a"),
        collected_at="2026-09-02T12:00:10+09:00",
        observation_window=EvidenceObservationWindow(
            "2026-09-02T12:00:00+09:00",
            "2026-09-02T12:00:05+09:00",
        ),
        integrity=EvidenceIntegrity(content_sha or _sha("c"), _sha("d")),
        sensitivity="internal",
        quality=EvidenceQuality(1.0, 1.0),
        raw_ref="monitoring:flow:1",
        provenance=EvidenceProvenance("zeek-adapter", "v1", (_sha("d"),)),
    )


def _time() -> ForensicTimeProvenance:
    return ForensicTimeProvenance(
        original_timestamp="2026-09-02T12:00:00+09:00",
        original_timezone="Asia/Tokyo",
        clock_source="sensor-clock",
        clock_uncertainty_ms=250,
        normalized_utc="2026-09-02T03:00:00Z",
    ).validate()


def test_case_identity_is_deterministic_and_authority_is_read_only():
    auth = _authorization()
    first = CaseRecord.create(title_ref="incident-2026-09-02", created_at="2026-09-02T12:05:00+09:00", authorization=auth)
    second = CaseRecord.create(title_ref="incident-2026-09-02", created_at="2026-09-02T03:05:00Z", authorization=auth)

    assert first.case_id == second.case_id
    assert first.authority == "advisory"
    assert auth.read_only is True
    assert auth.remediation_allowed is False
    assert auth.network_execution_allowed is False


def test_case_authorization_rejects_execution_authority():
    with pytest.raises(DFIRCaseEvidenceError, match="cannot grant execution/remediation"):
        replace(_authorization(), network_execution_allowed=True).validate()


def test_forensic_time_preserves_original_and_requires_exact_utc_projection():
    value = _time()
    assert value.original_timestamp.endswith("+09:00")
    assert value.original_timezone == "Asia/Tokyo"
    assert value.normalized_utc == "2026-09-02T03:00:00Z"
    assert value.clock_uncertainty_ms == 250

    with pytest.raises(DFIRCaseEvidenceError, match="normalized_utc"):
        replace(value, normalized_utc="2026-09-02T03:00:01Z").validate()


def test_normalized_evidence_is_admitted_without_replacing_existing_evidence_contract():
    case = CaseRecord.create(title_ref="incident-1", created_at="2026-09-02T12:05:00+09:00", authorization=_authorization())
    normalized = _normalized()
    item = ForensicEvidenceObject.from_normalized(
        case_id=case.case_id,
        evidence=normalized,
        evidence_kind="raw",
        acquisition_sha256=_sha("e"),
        transport_sha256=_sha("f"),
        time_provenance=_time(),
    )

    admitted = admit_case_evidence(case, item, normalized)

    assert admitted.evidence_ids == (normalized.evidence_id,)
    assert item.normalized_evidence_sha256 == normalized.identity_sha256
    assert item.content_sha256 == normalized.integrity.content_sha256


def test_hash_or_case_scope_mismatch_fails_closed():
    case = CaseRecord.create(title_ref="incident-1", created_at="2026-09-02T12:05:00+09:00", authorization=_authorization())
    normalized = _normalized()
    item = ForensicEvidenceObject.from_normalized(
        case_id=case.case_id,
        evidence=normalized,
        evidence_kind="raw",
        acquisition_sha256=_sha("e"),
        transport_sha256=_sha("f"),
        time_provenance=_time(),
    )

    with pytest.raises(DFIRCaseEvidenceError, match="evidence hash mismatch"):
        admit_case_evidence(case, replace(item, content_sha256=_sha("9")), normalized)

    out_of_scope = _normalized(asset_ref="asset-2")
    out_item = ForensicEvidenceObject.from_normalized(
        case_id=case.case_id,
        evidence=out_of_scope,
        evidence_kind="raw",
        acquisition_sha256=_sha("e"),
        transport_sha256=_sha("f"),
        time_provenance=_time(),
    )
    with pytest.raises(DFIRCaseEvidenceError, match="outside approved case scope"):
        admit_case_evidence(case, out_item, out_of_scope)


def test_derived_evidence_requires_explicit_source_evidence_refs():
    case = CaseRecord.create(title_ref="incident-1", created_at="2026-09-02T12:05:00+09:00", authorization=_authorization())
    normalized = _normalized()

    with pytest.raises(DFIRCaseEvidenceError, match="derived evidence requires"):
        ForensicEvidenceObject.from_normalized(
            case_id=case.case_id,
            evidence=normalized,
            evidence_kind="derived",
            acquisition_sha256=_sha("e"),
            transport_sha256=_sha("f"),
            time_provenance=_time(),
        )


def test_custody_chain_is_hash_chained_append_only_and_deterministic():
    case = CaseRecord.create(title_ref="incident-1", created_at="2026-09-02T12:05:00+09:00", authorization=_authorization())
    normalized = _normalized()
    item = ForensicEvidenceObject.from_normalized(
        case_id=case.case_id,
        evidence=normalized,
        evidence_kind="raw",
        acquisition_sha256=_sha("e"),
        transport_sha256=_sha("f"),
        time_provenance=_time(),
    )
    first = CustodyEvent.build(
        event_index=1,
        case_id=case.case_id,
        evidence_id=item.evidence_id,
        event_type="REGISTERED",
        occurred_at="2026-09-02T03:05:10Z",
        actor_ref_sha256=_sha("1"),
        evidence_fingerprint=item.fingerprint,
        previous_event_sha256=None,
    )
    second = CustodyEvent.build(
        event_index=2,
        case_id=case.case_id,
        evidence_id=item.evidence_id,
        event_type="VERIFIED",
        occurred_at="2026-09-02T03:05:20Z",
        actor_ref_sha256=_sha("2"),
        evidence_fingerprint=item.fingerprint,
        previous_event_sha256=first.event_sha256,
    )

    chain = CustodyChain.from_events((first, second))
    same = CustodyChain.from_events((first, second))

    assert chain.fingerprint == same.fingerprint
    assert chain.canonical_json() == same.canonical_json()

    with pytest.raises(DFIRCaseEvidenceError, match="previous hash mismatch"):
        CustodyChain.from_events((first, replace(second, previous_event_sha256=_sha("8"))))
