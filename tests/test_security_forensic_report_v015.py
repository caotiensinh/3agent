from __future__ import annotations

import unittest
from dataclasses import replace

from three_agent.security_monitoring.contracts import MonitoringContractError, sha256_fingerprint
from three_agent.security_monitoring.forensic_evidence import (
    CaseAuthorization,
    CaseRecord,
    EvidenceObject,
    EvidenceProvenance,
)
from three_agent.security_monitoring.forensic_hypothesis import (
    HumanHypothesisConfirmation,
    confirm_hypothesis,
    evaluate_hypothesis,
)
from three_agent.security_monitoring.forensic_report import build_forensic_case_report


def _sha(marker: str) -> str:
    return sha256_fingerprint({"marker": marker})


def _evidence(evidence_id: str, evidence_type: str, *, data_class: str, content_sha256: str | None = None):
    return EvidenceObject(
        evidence_id=evidence_id,
        evidence_type=evidence_type,
        content_sha256=content_sha256 or _sha(evidence_id),
        byte_size=100,
        data_class=data_class,
        provenance=EvidenceProvenance(
            source_id="sensor-report-01",
            source_type="suricata_eve" if evidence_type != "timeline" else "incident_timeline",
            collected_at="2026-09-02T14:00:00Z",
            producer_id="workspace-report-source",
            producer_version="v0.15",
            source_content_sha256=content_sha256 or _sha("source:" + evidence_id),
            upstream_evidence_refs=(),
        ).validate(),
    ).validate()


def _case_and_evidence():
    source = _evidence("evidence:report-source", "network_event", data_class="internal")
    timeline_fingerprint = _sha("timeline-content")
    timeline = _evidence(
        "evidence:report-timeline",
        "timeline",
        data_class="confidential",
        content_sha256=timeline_fingerprint,
    )
    authorization = CaseAuthorization(
        case_scope_id="scope:report-01",
        approved_asset_refs=("asset:report-01",),
        allowed_evidence_types=("network_event", "timeline"),
    ).validate()
    case = CaseRecord(
        case_id="case:report-01",
        status="investigating",
        created_at="2026-09-02T14:00:00Z",
        updated_at="2026-09-02T14:10:00Z",
        authorization_fingerprint=authorization.fingerprint,
        evidence_refs=(timeline.reference("timeline"), source.reference("source")),
        timeline_fingerprint=timeline_fingerprint,
    ).validate()
    return case, source, timeline


class SecurityForensicReportV015Tests(unittest.TestCase):
    def test_report_is_deterministic_order_invariant_and_metadata_only(self) -> None:
        case, source, timeline = _case_and_evidence()
        hypothesis = evaluate_hypothesis(
            hypothesis_id="hypothesis:report-01",
            statement_sha256=_sha("possible credential abuse"),
            created_at="2026-09-02T14:05:00Z",
            updated_at="2026-09-02T14:05:00Z",
            supporting=(source.reference("supports"),),
            missing_evidence_codes=("PROCESS_LOG_NOT_AVAILABLE",),
        )

        first = build_forensic_case_report(
            case,
            (timeline, source),
            (hypothesis,),
            generated_at="2026-09-02T14:11:00Z",
            limitation_codes=("CLOCK_UNCERTAINTY_PRESENT",),
        )
        second = build_forensic_case_report(
            case,
            (source, timeline),
            (hypothesis,),
            generated_at="2026-09-02T14:11:00+00:00",
            limitation_codes=("CLOCK_UNCERTAINTY_PRESENT",),
        )

        self.assertEqual(first.public_dict(), second.public_dict())
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.data_class, "confidential")
        self.assertEqual(
            first.limitation_codes,
            ("CLOCK_UNCERTAINTY_PRESENT", "PROCESS_LOG_NOT_AVAILABLE"),
        )
        self.assertFalse(first.narrative_embedded)
        self.assertFalse(first.raw_payload_embedded)
        self.assertTrue(first.human_review_required)
        self.assertEqual(first.authority, "advisory")
        rendered = str(first.public_dict())
        self.assertNotIn("possible credential abuse", rendered)

    def test_builder_deduplicates_same_limitation_from_case_analysis_and_caller(self) -> None:
        case, source, timeline = _case_and_evidence()
        hypothesis = evaluate_hypothesis(
            hypothesis_id="hypothesis:report-dedupe",
            statement_sha256=_sha("hypothesis-dedupe"),
            created_at="2026-09-02T14:05:00Z",
            updated_at="2026-09-02T14:05:00Z",
            missing_evidence_codes=("AUTH_LOG_NOT_AVAILABLE",),
        )
        report = build_forensic_case_report(
            case,
            (source, timeline),
            (hypothesis,),
            generated_at="2026-09-02T14:11:00Z",
            limitation_codes=("AUTH_LOG_NOT_AVAILABLE",),
        )
        self.assertEqual(report.limitation_codes, ("AUTH_LOG_NOT_AVAILABLE",))

    def test_report_requires_exact_case_evidence_set_and_content_hashes(self) -> None:
        case, source, timeline = _case_and_evidence()
        with self.assertRaisesRegex(MonitoringContractError, "exactly match"):
            build_forensic_case_report(
                case,
                (source,),
                (),
                generated_at="2026-09-02T14:11:00Z",
            )

        conflicting_source = replace(source, content_sha256=_sha("wrong-content"))
        with self.assertRaisesRegex(MonitoringContractError, "content hash mismatch"):
            build_forensic_case_report(
                case,
                (conflicting_source, timeline),
                (),
                generated_at="2026-09-02T14:11:00Z",
            )

    def test_case_timeline_fingerprint_requires_exactly_one_matching_timeline_evidence(self) -> None:
        case, source, timeline = _case_and_evidence()
        wrong_timeline = replace(timeline, content_sha256=_sha("wrong-timeline"))
        wrong_case = replace(
            case,
            evidence_refs=(source.reference(), wrong_timeline.reference("timeline")),
        ).validate()
        with self.assertRaisesRegex(MonitoringContractError, "exactly one case-bound timeline"):
            build_forensic_case_report(
                wrong_case,
                (source, wrong_timeline),
                (),
                generated_at="2026-09-02T14:11:00Z",
            )

    def test_hypothesis_evidence_must_stay_inside_case_scope(self) -> None:
        case, source, timeline = _case_and_evidence()
        outside = _evidence("evidence:outside-case", "network_event", data_class="internal")
        hypothesis = evaluate_hypothesis(
            hypothesis_id="hypothesis:outside-scope",
            statement_sha256=_sha("outside scope"),
            created_at="2026-09-02T14:05:00Z",
            updated_at="2026-09-02T14:05:00Z",
            supporting=(outside.reference("supports"),),
        )
        with self.assertRaisesRegex(MonitoringContractError, "outside case scope"):
            build_forensic_case_report(
                case,
                (source, timeline),
                (hypothesis,),
                generated_at="2026-09-02T14:11:00Z",
            )

    def test_human_confirmation_hash_is_preserved_without_identity_or_note_content(self) -> None:
        case, source, timeline = _case_and_evidence()
        hypothesis = evaluate_hypothesis(
            hypothesis_id="hypothesis:confirmed-report",
            statement_sha256=_sha("confirmed statement"),
            created_at="2026-09-02T14:05:00Z",
            updated_at="2026-09-02T14:05:00Z",
            supporting=(source.reference("supports"),),
        )
        confirmation = HumanHypothesisConfirmation.build(
            hypothesis_id=hypothesis.hypothesis_id,
            evidence_fingerprint=hypothesis.evidence.fingerprint,
            human_ref="human:" + _sha("analyst-report"),
            confirmed_at="2026-09-02T14:06:00Z",
            note_sha256=_sha("review note"),
        )
        confirmed = confirm_hypothesis(hypothesis, confirmation)
        report = build_forensic_case_report(
            case,
            (source, timeline),
            (confirmed,),
            generated_at="2026-09-02T14:11:00Z",
        )

        summary = report.hypotheses[0]
        self.assertEqual(summary.human_confirmation_sha256, confirmation.record_sha256)
        rendered = str(report.public_dict())
        self.assertNotIn(confirmation.human_ref, rendered)
        self.assertNotIn("review note", rendered)

    def test_report_id_is_content_derived_and_tamper_evident(self) -> None:
        case, source, timeline = _case_and_evidence()
        report = build_forensic_case_report(
            case,
            (source, timeline),
            (),
            generated_at="2026-09-02T14:11:00Z",
        )
        self.assertTrue(report.report_id.startswith("forensic-report:"))
        with self.assertRaisesRegex(MonitoringContractError, "report_id does not match"):
            replace(report, report_id="forensic-report:" + "0" * 24).validate()


if __name__ == "__main__":
    unittest.main()
