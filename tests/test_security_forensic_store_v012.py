from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from three_agent.security_monitoring.contracts import MonitoringContractError, sha256_fingerprint
from three_agent.security_monitoring.forensic_evidence import (
    CaseAuthorization,
    CaseRecord,
    CustodyEvent,
    EvidenceObject,
    EvidenceProvenance,
)
from three_agent.security_monitoring.forensic_store import ForensicMetadataStore
from three_agent.security_monitoring.storage import MonitoringStore


def _sha(marker: str) -> str:
    return sha256_fingerprint({"marker": marker})


def _evidence(evidence_id: str) -> EvidenceObject:
    return EvidenceObject(
        evidence_id=evidence_id,
        evidence_type="network_event",
        content_sha256=_sha(evidence_id),
        byte_size=128,
        data_class="confidential",
        provenance=EvidenceProvenance(
            source_id="sensor-store-01",
            source_type="suricata_eve",
            collected_at="2026-09-02T14:30:00Z",
            producer_id="workspace-parser",
            producer_version="v0.12",
            source_content_sha256=_sha("source:" + evidence_id),
        ).validate(),
    ).validate()


def _authorization() -> CaseAuthorization:
    return CaseAuthorization(
        case_scope_id="scope:store-01",
        approved_asset_refs=("asset:one",),
        allowed_evidence_types=("network_event",),
    ).validate()


class SecurityForensicStoreV012Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "monitoring.sqlite3"
        self.monitoring = MonitoringStore(self.db_path)
        self.monitoring.initialize()
        self.store = ForensicMetadataStore(self.monitoring)
        self.store.initialize()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_store_reuses_monitoring_sqlite_and_has_independent_extension_schema_version(self) -> None:
        self.assertEqual(self.monitoring.schema_version(), 1)
        self.assertEqual(self.store.schema_version(), 1)
        self.assertEqual(Path(self.store.monitoring_store.path), self.db_path)
        self.assertTrue(self.db_path.exists())

    def test_evidence_put_is_round_trip_idempotent_and_immutable_by_evidence_id(self) -> None:
        evidence = _evidence("evidence:store-01")
        first = self.store.put_evidence(evidence)
        second = self.store.put_evidence(evidence)

        self.assertFalse(first.idempotent)
        self.assertTrue(second.idempotent)
        self.assertEqual(first.object_fingerprint, evidence.fingerprint)
        self.assertEqual(self.store.get_evidence(evidence.evidence_id), evidence)
        self.assertEqual(self.store.count("forensic_evidence"), 1)

        conflict = replace(evidence, content_sha256=_sha("conflicting-content"))
        with self.assertRaisesRegex(MonitoringContractError, "immutable and conflicts"):
            self.store.put_evidence(conflict)
        self.assertEqual(self.store.count("forensic_evidence"), 1)

    def test_case_snapshot_requires_existing_exact_content_hash_evidence(self) -> None:
        authorization = _authorization()
        evidence = _evidence("evidence:store-02")
        case = CaseRecord(
            case_id="case:store-02",
            status="open",
            created_at="2026-09-02T14:30:00Z",
            updated_at="2026-09-02T14:30:00Z",
            authorization_fingerprint=authorization.fingerprint,
            evidence_refs=(evidence.reference(),),
        ).validate()

        with self.assertRaisesRegex(MonitoringContractError, "unknown forensic evidence"):
            self.store.put_case_snapshot(case)

        self.store.put_evidence(evidence)
        wrong_ref_case = replace(
            case,
            evidence_refs=(replace(evidence.reference(), content_sha256=_sha("wrong-ref")),),
        )
        with self.assertRaisesRegex(MonitoringContractError, "content hash mismatch"):
            self.store.put_case_snapshot(wrong_ref_case)

        receipt = self.store.put_case_snapshot(case)
        self.assertFalse(receipt.idempotent)
        self.assertTrue(self.store.put_case_snapshot(case).idempotent)
        self.assertEqual(self.store.get_latest_case(case.case_id), case)

    def test_case_snapshots_are_append_only_monotonic_and_evidence_set_cannot_shrink(self) -> None:
        authorization = _authorization()
        first_evidence = _evidence("evidence:case-first")
        second_evidence = _evidence("evidence:case-second")
        self.store.put_evidence(first_evidence)
        self.store.put_evidence(second_evidence)

        first = CaseRecord(
            case_id="case:snapshots",
            status="open",
            created_at="2026-09-02T14:30:00Z",
            updated_at="2026-09-02T14:30:00Z",
            authorization_fingerprint=authorization.fingerprint,
            evidence_refs=(first_evidence.reference(),),
        ).validate()
        second = CaseRecord(
            case_id="case:snapshots",
            status="investigating",
            created_at="2026-09-02T14:30:00Z",
            updated_at="2026-09-02T14:31:00Z",
            authorization_fingerprint=authorization.fingerprint,
            evidence_refs=(second_evidence.reference(), first_evidence.reference()),
        ).validate()

        self.store.put_case_snapshot(first)
        self.store.put_case_snapshot(second)
        self.assertEqual(self.store.count("forensic_case_snapshots"), 2)
        self.assertEqual(self.store.get_latest_case("case:snapshots"), second)

        shrinking = replace(
            second,
            status="closed",
            updated_at="2026-09-02T14:32:00Z",
            evidence_refs=(second_evidence.reference(),),
        )
        with self.assertRaisesRegex(MonitoringContractError, "evidence set cannot shrink"):
            self.store.put_case_snapshot(shrinking)

        changed_auth = replace(
            second,
            updated_at="2026-09-02T14:32:00Z",
            authorization_fingerprint=_sha("different-authorization"),
        )
        with self.assertRaisesRegex(MonitoringContractError, "authorization fingerprint is immutable"):
            self.store.put_case_snapshot(changed_auth)

        reopened = replace(second, status="open", updated_at="2026-09-02T14:32:00Z")
        with self.assertRaisesRegex(MonitoringContractError, "status transition is not monotonic"):
            self.store.put_case_snapshot(reopened)

    def test_custody_append_is_contiguous_hash_chained_and_case_head_can_be_snapshotted(self) -> None:
        authorization = _authorization()
        evidence = _evidence("evidence:custody-01")
        self.store.put_evidence(evidence)
        case = CaseRecord(
            case_id="case:custody-01",
            status="open",
            created_at="2026-09-02T14:30:00Z",
            updated_at="2026-09-02T14:30:00Z",
            authorization_fingerprint=authorization.fingerprint,
            evidence_refs=(evidence.reference(),),
        ).validate()
        self.store.put_case_snapshot(case)

        actor = "actor:" + _sha("forensic-analyst")
        first = CustodyEvent.build(
            event_index=1,
            evidence_id=evidence.evidence_id,
            action="registered",
            actor_ref=actor,
            occurred_at="2026-09-02T14:31:00Z",
            previous_event_sha256=None,
        )
        second = CustodyEvent.build(
            event_index=2,
            evidence_id=evidence.evidence_id,
            action="verified",
            actor_ref=actor,
            occurred_at="2026-09-02T14:32:00Z",
            previous_event_sha256=first.record_sha256,
        )

        self.assertFalse(self.store.append_custody_event(case.case_id, first).idempotent)
        self.assertTrue(self.store.append_custody_event(case.case_id, first).idempotent)
        self.assertFalse(self.store.append_custody_event(case.case_id, second).idempotent)
        self.assertEqual(self.store.custody_head(case.case_id), second.record_sha256)
        self.assertEqual(self.store.count("forensic_custody_events"), 2)

        case_with_head = replace(
            case,
            status="investigating",
            updated_at="2026-09-02T14:33:00Z",
            custody_head_sha256=second.record_sha256,
        ).validate()
        self.store.put_case_snapshot(case_with_head)
        self.assertEqual(self.store.get_latest_case(case.case_id), case_with_head)

        gap = CustodyEvent.build(
            event_index=4,
            evidence_id=evidence.evidence_id,
            action="reviewed",
            actor_ref=actor,
            occurred_at="2026-09-02T14:34:00Z",
            previous_event_sha256=second.record_sha256,
        )
        with self.assertRaisesRegex(MonitoringContractError, "append contiguously"):
            self.store.append_custody_event(case.case_id, gap)

        broken = CustodyEvent.build(
            event_index=3,
            evidence_id=evidence.evidence_id,
            action="reviewed",
            actor_ref=actor,
            occurred_at="2026-09-02T14:34:00Z",
            previous_event_sha256=_sha("wrong-custody-head"),
        )
        with self.assertRaisesRegex(MonitoringContractError, "hash chain is broken"):
            self.store.append_custody_event(case.case_id, broken)

    def test_store_contains_only_metadata_contract_json_not_raw_payload_or_locator(self) -> None:
        evidence = _evidence("evidence:metadata-only")
        self.store.put_evidence(evidence)
        with self.monitoring.connect() as conn:
            row = conn.execute(
                "SELECT evidence_json FROM forensic_evidence WHERE evidence_id=?",
                (evidence.evidence_id,),
            ).fetchone()
        payload = json.loads(row["evidence_json"])
        self.assertEqual(payload["payload_embedded"], False)
        rendered = json.dumps(payload, sort_keys=True)
        self.assertNotIn("raw_payload", rendered)
        self.assertNotIn("filesystem_path", rendered)
        self.assertNotIn("credential", rendered)

    def test_unknown_case_or_evidence_cannot_receive_custody_event(self) -> None:
        actor = "actor:" + _sha("analyst")
        event = CustodyEvent.build(
            event_index=1,
            evidence_id="evidence:unknown",
            action="registered",
            actor_ref=actor,
            occurred_at="2026-09-02T14:31:00Z",
            previous_event_sha256=None,
        )
        with self.assertRaisesRegex(MonitoringContractError, "existing forensic case"):
            self.store.append_custody_event("case:unknown", event)


if __name__ == "__main__":
    unittest.main()
