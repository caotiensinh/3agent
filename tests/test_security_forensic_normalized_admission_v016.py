from __future__ import annotations

import unittest

from three_agent.security_monitoring.contracts import MonitoringContractError, sha256_fingerprint
from three_agent.security_monitoring.forensic_evidence import CaseAuthorization
from three_agent.security_monitoring.forensic_normalized_admission import (
    NormalizedEvidenceAdmissionScope,
    normalized_to_forensic_evidence,
)
from three_agent.security_monitoring.normalized_evidence import (
    EvidenceIntegrity,
    EvidenceObservationWindow,
    EvidenceProvenance,
    EvidenceQuality,
    NormalizedEvidence,
)


def _normalized(*, evidence_type: str = "dns_event", asset_ref: str = "asset-dfir-01", sensitivity: str = "confidential") -> NormalizedEvidence:
    return NormalizedEvidence.create(
        evidence_type=evidence_type,
        source_type="suricata_eve",
        asset_ref=asset_ref,
        task_ref_sha256=sha256_fingerprint({"task": "dfir-01"}),
        authorization_ref_sha256=sha256_fingerprint({"authorization": "dfir-01"}),
        collected_at="2026-09-03T00:00:10+09:00",
        observation_window=EvidenceObservationWindow(
            start_at="2026-09-03T00:00:00+09:00",
            end_at="2026-09-03T00:00:05+09:00",
        ),
        integrity=EvidenceIntegrity(
            content_sha256=sha256_fingerprint({"content": "dns"}),
            source_record_sha256=sha256_fingerprint({"source": "dns"}),
        ),
        sensitivity=sensitivity,
        quality=EvidenceQuality(confidence=1.0, completeness=1.0),
        raw_ref="raw-ref:private-spool-object-01",
        provenance=EvidenceProvenance(
            producer="suricata-parser",
            parser_version="v1",
            lineage_refs=(sha256_fingerprint({"lineage": "source"}),),
        ),
    )


def _authorization(*, evidence_types: tuple[str, ...] = ("dns", "flow", "host_log", "authentication", "process", "pcap", "other_metadata")) -> CaseAuthorization:
    return CaseAuthorization(
        case_scope_id="dfir-case-scope-01",
        approved_asset_refs=("asset-dfir-01",),
        allowed_evidence_types=evidence_types,
    ).validate()


def _scope(auth: CaseAuthorization, *, sensitivities: tuple[str, ...] = ("confidential",)) -> NormalizedEvidenceAdmissionScope:
    return NormalizedEvidenceAdmissionScope(
        task_ref_sha256=sha256_fingerprint({"task": "dfir-01"}),
        authorization_ref_sha256=sha256_fingerprint({"authorization": "dfir-01"}),
        case_authorization_fingerprint=auth.fingerprint,
        allowed_sensitivities=sensitivities,
        source_clock_ref="clock:suricata-sensor-01",
        clock_uncertainty_ms=25,
    ).validate()


class SecurityForensicNormalizedAdmissionV016Tests(unittest.TestCase):
    def test_admission_is_deterministic_scope_bound_and_metadata_only(self) -> None:
        normalized = _normalized()
        auth = _authorization()
        scope = _scope(auth)
        first = normalized_to_forensic_evidence(normalized, case_authorization=auth, admission_scope=scope)
        second = normalized_to_forensic_evidence(normalized, case_authorization=auth, admission_scope=scope)
        self.assertEqual(first.public_dict(), second.public_dict())
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.evidence_id, normalized.evidence_id)
        self.assertEqual(first.evidence_type, "dns")
        self.assertEqual(first.content_sha256, normalized.integrity.content_sha256)
        self.assertEqual(first.provenance.source_content_sha256, normalized.integrity.source_record_sha256)
        self.assertEqual(first.data_class, "confidential")
        self.assertEqual(first.event_time.uncertainty_ms, 25)
        rendered = str(first.public_dict())
        self.assertNotIn(normalized.raw_ref, rendered)
        self.assertFalse(first.payload_embedded)
        self.assertTrue(first.immutable)

    def test_admission_rejects_task_authorization_asset_and_sensitivity_scope_escape(self) -> None:
        normalized = _normalized()
        auth = _authorization()
        scope = _scope(auth)
        wrong_task = NormalizedEvidenceAdmissionScope(
            task_ref_sha256=sha256_fingerprint({"task": "wrong"}),
            authorization_ref_sha256=scope.authorization_ref_sha256,
            case_authorization_fingerprint=auth.fingerprint,
            allowed_sensitivities=scope.allowed_sensitivities,
            source_clock_ref=scope.source_clock_ref,
        ).validate()
        with self.assertRaisesRegex(MonitoringContractError, "task lineage mismatch"):
            normalized_to_forensic_evidence(normalized, case_authorization=auth, admission_scope=wrong_task)

        wrong_authorization = NormalizedEvidenceAdmissionScope(
            task_ref_sha256=scope.task_ref_sha256,
            authorization_ref_sha256=sha256_fingerprint({"authorization": "wrong"}),
            case_authorization_fingerprint=auth.fingerprint,
            allowed_sensitivities=scope.allowed_sensitivities,
            source_clock_ref=scope.source_clock_ref,
        ).validate()
        with self.assertRaisesRegex(MonitoringContractError, "authorization lineage mismatch"):
            normalized_to_forensic_evidence(normalized, case_authorization=auth, admission_scope=wrong_authorization)

        with self.assertRaisesRegex(MonitoringContractError, "outside forensic case scope"):
            normalized_to_forensic_evidence(_normalized(asset_ref="asset-other"), case_authorization=auth, admission_scope=scope)
        with self.assertRaisesRegex(MonitoringContractError, "sensitivity is outside admission scope"):
            normalized_to_forensic_evidence(_normalized(sensitivity="restricted"), case_authorization=auth, admission_scope=scope)

    def test_admission_rejects_case_authorization_mismatch_and_disallowed_mapped_type(self) -> None:
        normalized = _normalized()
        auth = _authorization()
        scope = _scope(auth)
        other_auth = CaseAuthorization(
            case_scope_id="dfir-case-scope-02",
            approved_asset_refs=("asset-dfir-01",),
            allowed_evidence_types=("dns",),
        ).validate()
        with self.assertRaisesRegex(MonitoringContractError, "case authorization fingerprint mismatch"):
            normalized_to_forensic_evidence(normalized, case_authorization=other_auth, admission_scope=scope)

        dns_disallowed = _authorization(evidence_types=("flow",))
        with self.assertRaisesRegex(MonitoringContractError, "outside case authorization"):
            normalized_to_forensic_evidence(normalized, case_authorization=dns_disallowed, admission_scope=_scope(dns_disallowed))

    def test_closed_type_mapping_reuses_existing_normalized_evidence_types(self) -> None:
        expected = {
            "snmp_observation": "other_metadata",
            "log_event": "host_log",
            "pcap_summary": "pcap",
            "dns_event": "dns",
            "network_flow": "flow",
            "authentication_event": "authentication",
            "process_event": "process",
            "correlation_result": "other_metadata",
        }
        auth = _authorization()
        scope = _scope(auth)
        for source_type, target_type in expected.items():
            with self.subTest(source_type=source_type):
                output = normalized_to_forensic_evidence(
                    _normalized(evidence_type=source_type),
                    case_authorization=auth,
                    admission_scope=scope,
                )
                self.assertEqual(output.evidence_type, target_type)


if __name__ == "__main__":
    unittest.main()
