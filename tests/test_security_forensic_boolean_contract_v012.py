from __future__ import annotations

import unittest
from dataclasses import replace

from three_agent.security_monitoring.contracts import MonitoringContractError, sha256_fingerprint
from three_agent.security_monitoring.forensic_evidence import (
    CaseAuthorization,
    CaseRecord,
    CollectionFootprint,
    EvidenceObject,
    EvidenceProvenance,
)


def _sha(marker: str) -> str:
    return sha256_fingerprint({"marker": marker})


def _evidence() -> EvidenceObject:
    provenance = EvidenceProvenance(
        source_id="sensor-dfir-01",
        source_type="suricata_eve",
        collected_at="2026-09-02T14:30:00Z",
        producer_id="workspace-parser",
        producer_version="v0.12",
        source_content_sha256=_sha("source"),
    ).validate()
    return EvidenceObject(
        evidence_id="evidence:boolean-contract",
        evidence_type="network_event",
        content_sha256=_sha("evidence"),
        byte_size=128,
        data_class="confidential",
        provenance=provenance,
    ).validate()


class SecurityForensicBooleanContractV012Tests(unittest.TestCase):
    def test_evidence_security_flags_require_exact_bool(self) -> None:
        evidence = _evidence()
        for field_name in ("derived", "immutable", "payload_embedded"):
            with self.subTest(field_name=field_name):
                with self.assertRaisesRegex(MonitoringContractError, "must be a boolean"):
                    replace(evidence, **{field_name: 1}).validate()

    def test_case_authority_flags_require_exact_bool(self) -> None:
        authorization = CaseAuthorization(
            case_scope_id="scope:boolean-contract",
            approved_asset_refs=("asset:one",),
            allowed_evidence_types=("network_event",),
        ).validate()
        for field_name in (
            "read_only",
            "advisory_only",
            "case_grants_network_access",
            "case_grants_collection",
            "case_grants_remediation",
        ):
            with self.subTest(field_name=field_name):
                with self.assertRaisesRegex(MonitoringContractError, "must be a boolean"):
                    replace(authorization, **{field_name: 1}).validate()

    def test_collection_flags_require_exact_bool(self) -> None:
        footprint = CollectionFootprint(
            collector_id="monitoring:suricata-ingest",
            collected_at="2026-09-02T14:30:00Z",
            object_count=1,
            byte_count=128,
            network_read_used=False,
            active_probe_used=False,
        ).validate()
        for field_name in ("network_read_used", "active_probe_used"):
            with self.subTest(field_name=field_name):
                with self.assertRaisesRegex(MonitoringContractError, "must be a boolean"):
                    replace(footprint, **{field_name: 1}).validate()

    def test_case_human_review_flag_requires_exact_bool(self) -> None:
        authorization = CaseAuthorization(
            case_scope_id="scope:boolean-contract",
            approved_asset_refs=("asset:one",),
            allowed_evidence_types=("network_event",),
        ).validate()
        case = CaseRecord(
            case_id="case:boolean-contract",
            status="open",
            created_at="2026-09-02T14:30:00Z",
            updated_at="2026-09-02T14:30:00Z",
            authorization_fingerprint=authorization.fingerprint,
            evidence_refs=(),
        ).validate()
        with self.assertRaisesRegex(MonitoringContractError, "must be a boolean"):
            replace(case, human_review_required=1).validate()


if __name__ == "__main__":
    unittest.main()
