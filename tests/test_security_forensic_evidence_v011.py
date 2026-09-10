from __future__ import annotations

import unittest
from dataclasses import replace

from three_agent.security_monitoring.contracts import MonitoringContractError, sha256_fingerprint
from three_agent.security_monitoring.forensic_evidence import (
    CaseAuthorization,
    CaseRecord,
    CollectionFootprint,
    CustodyEvent,
    DerivedEvidence,
    EvidenceObject,
    EvidenceProvenance,
    EvidenceReference,
    ForensicEventTime,
    verify_custody_chain,
)


def _sha(marker: str) -> str:
    return sha256_fingerprint({"marker": marker})


def _provenance(*, upstream: tuple[str, ...] = ()) -> EvidenceProvenance:
    return EvidenceProvenance(
        source_id="sensor-dfir-01",
        source_type="suricata_eve",
        collected_at="2026-09-02T14:30:00+00:00",
        producer_id="workspace-parser",
        producer_version="v0.11",
        source_content_sha256=_sha("source-content"),
        upstream_evidence_refs=upstream,
    ).validate()


def _event_time() -> ForensicEventTime:
    return ForensicEventTime(
        original_timestamp="2026-09-02T23:29:59+09:00",
        normalized_utc="2026-09-02T14:29:59Z",
        source_clock_ref="clock:asset-dfir-01",
        uncertainty_ms=250,
    ).validate()


def _source_evidence(evidence_id: str = "evidence:source-01") -> EvidenceObject:
    return EvidenceObject(
        evidence_id=evidence_id,
        evidence_type="network_event",
        content_sha256=_sha(evidence_id),
        byte_size=512,
        data_class="confidential",
        provenance=_provenance(),
        event_time=_event_time(),
    ).validate()


class SecurityForensicEvidenceV011Tests(unittest.TestCase):
    def test_source_evidence_is_metadata_only_immutable_and_deterministic(self) -> None:
        first = _source_evidence()
        second = _source_evidence()

        self.assertEqual(first.public_dict(), second.public_dict())
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertFalse(first.derived)
        self.assertTrue(first.immutable)
        self.assertFalse(first.payload_embedded)
        self.assertEqual(first.event_time.normalized_utc, "2026-09-02T14:29:59Z")
        rendered = str(first.public_dict())
        self.assertNotIn("payload", rendered.lower().replace("payload_embedded", ""))
        self.assertNotIn("/var/", rendered)
        self.assertNotIn("C:\\", rendered)

    def test_source_evidence_rejects_payload_embedding_mutability_and_derivation_parents(self) -> None:
        source = _source_evidence()
        with self.assertRaisesRegex(MonitoringContractError, "raw evidence payload"):
            replace(source, payload_embedded=True).validate()
        with self.assertRaisesRegex(MonitoringContractError, "must remain immutable"):
            replace(source, immutable=False).validate()
        with self.assertRaisesRegex(MonitoringContractError, "source evidence cannot declare"):
            replace(source, parent_evidence_refs=("evidence:parent-01",)).validate()

    def test_provenance_rejects_url_like_source_and_preserves_sorted_upstream_lineage(self) -> None:
        provenance = _provenance(upstream=("evidence:z-parent", "evidence:a-parent"))
        self.assertEqual(provenance.upstream_evidence_refs, ("evidence:a-parent", "evidence:z-parent"))
        with self.assertRaises(MonitoringContractError):
            replace(provenance, source_id="https://sensor.invalid/log").validate()

    def test_event_time_requires_same_instant_and_records_uncertainty(self) -> None:
        event_time = _event_time()
        self.assertEqual(event_time.uncertainty_ms, 250)
        with self.assertRaisesRegex(MonitoringContractError, "same instant"):
            replace(event_time, normalized_utc="2026-09-02T14:30:59Z").validate()
        with self.assertRaisesRegex(MonitoringContractError, "uncertainty_ms"):
            replace(event_time, uncertainty_ms=-1).validate()

    def test_derived_evidence_requires_exact_parent_and_provenance_lineage(self) -> None:
        left = _source_evidence("evidence:source-left")
        right = _source_evidence("evidence:source-right")
        refs = (right.reference("derived_from"), left.reference("derived_from"))
        parents = tuple(sorted((left.evidence_id, right.evidence_id)))
        output = EvidenceObject(
            evidence_id="evidence:derived-timeline-01",
            evidence_type="timeline",
            content_sha256=_sha("derived-timeline"),
            byte_size=1024,
            data_class="confidential",
            provenance=_provenance(upstream=parents),
            parent_evidence_refs=parents,
            derived=True,
        ).validate()
        derived = DerivedEvidence(
            evidence=output,
            derivation_id="incident-timeline-v0.10",
            input_evidence_refs=refs,
        ).validate()

        self.assertEqual(
            tuple(ref.evidence_id for ref in derived.input_evidence_refs),
            ("evidence:source-left", "evidence:source-right"),
        )
        self.assertEqual(derived.evidence.parent_evidence_refs, parents)
        self.assertEqual(derived.authority, "advisory")

        broken = replace(output, provenance=_provenance(upstream=("evidence:source-left",)))
        with self.assertRaisesRegex(MonitoringContractError, "provenance must preserve exact upstream lineage"):
            replace(derived, evidence=broken).validate()

    def test_derived_evidence_rejects_self_reference(self) -> None:
        with self.assertRaisesRegex(MonitoringContractError, "cannot derive from itself"):
            EvidenceObject(
                evidence_id="evidence:self-derived",
                evidence_type="timeline",
                content_sha256=_sha("self-derived"),
                byte_size=10,
                data_class="confidential",
                provenance=_provenance(upstream=("evidence:self-derived",)),
                parent_evidence_refs=("evidence:self-derived",),
                derived=True,
            ).validate()

    def test_custody_chain_is_hash_chained_and_tamper_evident(self) -> None:
        actor = "actor:" + _sha("analyst")
        first = CustodyEvent.build(
            event_index=1,
            evidence_id="evidence:source-01",
            action="registered",
            actor_ref=actor,
            occurred_at="2026-09-02T14:31:00Z",
            previous_event_sha256=None,
        )
        second = CustodyEvent.build(
            event_index=2,
            evidence_id="evidence:source-01",
            action="verified",
            actor_ref=actor,
            occurred_at="2026-09-02T14:32:00Z",
            previous_event_sha256=first.record_sha256,
            note_sha256=_sha("verified-note"),
        )

        self.assertEqual(verify_custody_chain((first, second)), second.record_sha256)
        with self.assertRaisesRegex(MonitoringContractError, "record_sha256"):
            replace(second, action="reviewed").validate()
        broken_link = CustodyEvent.build(
            event_index=2,
            evidence_id="evidence:source-01",
            action="verified",
            actor_ref=actor,
            occurred_at="2026-09-02T14:32:00Z",
            previous_event_sha256=_sha("wrong-parent"),
        )
        with self.assertRaisesRegex(MonitoringContractError, "hash chain is broken"):
            verify_custody_chain((first, broken_link))

    def test_case_authorization_is_exact_read_only_advisory_and_order_invariant(self) -> None:
        first = CaseAuthorization(
            case_scope_id="scope:incident-01",
            approved_asset_refs=("asset:two", "asset:one"),
            allowed_evidence_types=("flow", "dns", "authentication"),
        ).validate()
        second = CaseAuthorization(
            case_scope_id="scope:incident-01",
            approved_asset_refs=("asset:one", "asset:two"),
            allowed_evidence_types=("authentication", "dns", "flow"),
        ).validate()

        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertTrue(first.read_only)
        self.assertTrue(first.advisory_only)
        self.assertFalse(first.case_grants_network_access)
        self.assertFalse(first.case_grants_collection)
        self.assertFalse(first.case_grants_remediation)

        with self.assertRaisesRegex(MonitoringContractError, "cannot grant"):
            replace(first, case_grants_collection=True).validate()
        with self.assertRaisesRegex(MonitoringContractError, "read-only and advisory"):
            replace(first, read_only=False).validate()

    def test_collection_footprint_records_network_read_without_granting_active_probe(self) -> None:
        footprint = CollectionFootprint(
            collector_id="monitoring:suricata-ingest",
            collected_at="2026-09-02T14:33:00Z",
            object_count=12,
            byte_count=4096,
            network_read_used=True,
            active_probe_used=False,
            authority_fingerprint=_sha("monitoring-authority"),
        ).validate()
        self.assertTrue(footprint.network_read_used)
        self.assertFalse(footprint.active_probe_used)
        self.assertTrue(footprint.fingerprint.startswith("sha256:"))

        with self.assertRaisesRegex(MonitoringContractError, "does not admit active probing"):
            replace(footprint, active_probe_used=True).validate()
        with self.assertRaisesRegex(MonitoringContractError, "requires an authority fingerprint"):
            replace(footprint, authority_fingerprint=None).validate()

    def test_case_record_is_deterministic_evidence_bound_and_human_reviewed(self) -> None:
        authorization = CaseAuthorization(
            case_scope_id="scope:incident-01",
            approved_asset_refs=("asset:one",),
            allowed_evidence_types=("network_event", "timeline"),
        ).validate()
        source = _source_evidence()
        timeline_ref = EvidenceReference(
            evidence_id="evidence:timeline-01",
            content_sha256=_sha("timeline-01"),
            relation="timeline",
        ).validate()
        actor = "actor:" + _sha("analyst")
        custody = CustodyEvent.build(
            event_index=1,
            evidence_id=source.evidence_id,
            action="registered",
            actor_ref=actor,
            occurred_at="2026-09-02T14:31:00Z",
            previous_event_sha256=None,
        )
        first = CaseRecord(
            case_id="case:incident-01",
            status="investigating",
            created_at="2026-09-02T14:30:00+00:00",
            updated_at="2026-09-02T14:35:00+00:00",
            authorization_fingerprint=authorization.fingerprint,
            evidence_refs=(timeline_ref, source.reference("source")),
            custody_head_sha256=custody.record_sha256,
            timeline_fingerprint=_sha("timeline-fingerprint"),
        ).validate()
        second = CaseRecord(
            case_id="case:incident-01",
            status="investigating",
            created_at="2026-09-02T14:30:00Z",
            updated_at="2026-09-02T14:35:00Z",
            authorization_fingerprint=authorization.fingerprint,
            evidence_refs=(source.reference("source"), timeline_ref),
            custody_head_sha256=custody.record_sha256,
            timeline_fingerprint=_sha("timeline-fingerprint"),
        ).validate()

        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(tuple(ref.evidence_id for ref in first.evidence_refs), ("evidence:source-01", "evidence:timeline-01"))
        self.assertTrue(first.human_review_required)
        self.assertEqual(first.authority, "advisory")

        with self.assertRaisesRegex(MonitoringContractError, "require human review"):
            replace(first, human_review_required=False).validate()
        with self.assertRaisesRegex(MonitoringContractError, "unique evidence_id"):
            replace(first, evidence_refs=(source.reference("source"), source.reference("supports"))).validate()

    def test_contracts_do_not_accept_raw_secret_or_filesystem_locator_fields(self) -> None:
        with self.assertRaises(MonitoringContractError):
            EvidenceProvenance(
                source_id="C:\\forensics\\evidence.evtx",
                source_type="windows_evtx",
                collected_at="2026-09-02T14:30:00Z",
                producer_id="workspace-parser",
                producer_version="v0.11",
                source_content_sha256=_sha("secret-test"),
            ).validate()
        with self.assertRaises(MonitoringContractError):
            CaseAuthorization(
                case_scope_id="scope:incident-01",
                approved_asset_refs=("https://192.168.11.52",),
                allowed_evidence_types=("host_log",),
            ).validate()


if __name__ == "__main__":
    unittest.main()
