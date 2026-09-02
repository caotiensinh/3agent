from __future__ import annotations

import unittest
from dataclasses import replace

from three_agent.security_monitoring.contracts import CanonicalEvent, MonitoringContractError, sha256_fingerprint
from three_agent.security_monitoring.correlation_graph import CorrelationEvent
from three_agent.security_monitoring.entity_context import EventEntityContext, EventEntityReference
from three_agent.security_monitoring.forensic_evidence import EvidenceObject, EvidenceProvenance
from three_agent.security_monitoring.incident_timeline import build_incident_timeline
from three_agent.security_monitoring.incident_timeline_evidence import (
    INCIDENT_TIMELINE_DERIVATION_ID,
    timeline_to_derived_evidence,
)


def _event(
    event_id: str,
    *,
    category: str,
    observed_at: str,
    source_ip: str = "10.44.0.10",
    destination_ip: str = "10.44.0.20",
    dns_answer: str | None = None,
    evidence_ref: str,
) -> CorrelationEvent:
    refs = [
        EventEntityReference.approved_asset(role="asset", asset_id="asset-dfir-timeline-01"),
        EventEntityReference.opaque(kind="ip", role="source_ip", value=source_ip),
    ]
    if category == "suricata.flow":
        refs.append(EventEntityReference.opaque(kind="ip", role="destination_ip", value=destination_ip))
    if dns_answer is not None:
        refs.append(EventEntityReference.opaque(kind="ip", role="dns_answer", value=dns_answer))
    canonical = CanonicalEvent(
        event_id=event_id,
        source_id="sensor-dfir-timeline-01",
        source_type="suricata_eve",
        observed_at=observed_at,
        category=category,
        severity="medium",
        message_sha256=sha256_fingerprint({"event": event_id}),
        parser_version="parser-v1",
        evidence_ref=evidence_ref,
    ).validate()
    return CorrelationEvent(
        event=canonical,
        context=EventEntityContext(event_id=event_id, references=tuple(refs)).validate(),
    ).validate()


def _timeline():
    dns = _event(
        "evt-dfir-timeline-dns",
        category="suricata.dns",
        observed_at="2026-09-02T14:00:00Z",
        dns_answer="10.44.0.20",
        evidence_ref="evidence:dns-source",
    )
    flow = _event(
        "evt-dfir-timeline-flow",
        category="suricata.flow",
        observed_at="2026-09-02T14:00:05Z",
        destination_ip="10.44.0.20",
        evidence_ref="evidence:flow-source",
    )
    return build_incident_timeline((flow, dns))


def _source(evidence_id: str, *, data_class: str) -> EvidenceObject:
    return EvidenceObject(
        evidence_id=evidence_id,
        evidence_type="network_event",
        content_sha256=sha256_fingerprint({"evidence": evidence_id}),
        byte_size=256,
        data_class=data_class,
        provenance=EvidenceProvenance(
            source_id="sensor-dfir-timeline-01",
            source_type="suricata_eve",
            collected_at="2026-09-02T14:00:10Z",
            producer_id="workspace-parser",
            producer_version="v1",
            source_content_sha256=sha256_fingerprint({"source": evidence_id}),
        ).validate(),
    ).validate()


class SecurityIncidentTimelineEvidenceV013Tests(unittest.TestCase):
    def test_adapter_is_deterministic_exact_lineage_and_metadata_only(self) -> None:
        timeline = _timeline()
        dns = _source("evidence:dns-source", data_class="internal")
        flow = _source("evidence:flow-source", data_class="confidential")

        first = timeline_to_derived_evidence(
            timeline,
            (flow, dns),
            produced_at="2026-09-02T14:01:00Z",
        )
        second = timeline_to_derived_evidence(
            timeline,
            (dns, flow),
            produced_at="2026-09-02T14:01:00+00:00",
        )

        self.assertEqual(first.public_dict(), second.public_dict())
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.derivation_id, INCIDENT_TIMELINE_DERIVATION_ID)
        self.assertEqual(first.evidence.content_sha256, timeline.fingerprint)
        self.assertEqual(first.evidence.data_class, "confidential")
        self.assertEqual(
            first.evidence.parent_evidence_refs,
            ("evidence:dns-source", "evidence:flow-source"),
        )
        self.assertEqual(
            first.evidence.provenance.upstream_evidence_refs,
            first.evidence.parent_evidence_refs,
        )
        self.assertEqual(
            tuple(ref.relation for ref in first.input_evidence_refs),
            ("derived_from", "derived_from"),
        )
        self.assertFalse(first.evidence.payload_embedded)
        self.assertTrue(first.evidence.immutable)
        self.assertEqual(first.authority, "advisory")

    def test_adapter_rejects_missing_extra_duplicate_or_wrong_source_type(self) -> None:
        timeline = _timeline()
        dns = _source("evidence:dns-source", data_class="internal")
        flow = _source("evidence:flow-source", data_class="internal")
        extra = _source("evidence:extra-source", data_class="internal")

        with self.assertRaisesRegex(MonitoringContractError, "exactly match"):
            timeline_to_derived_evidence(timeline, (dns,), produced_at="2026-09-02T14:01:00Z")
        with self.assertRaisesRegex(MonitoringContractError, "exactly match"):
            timeline_to_derived_evidence(timeline, (dns, flow, extra), produced_at="2026-09-02T14:01:00Z")
        with self.assertRaisesRegex(MonitoringContractError, "IDs must be unique"):
            timeline_to_derived_evidence(timeline, (dns, flow, flow), produced_at="2026-09-02T14:01:00Z")
        with self.assertRaisesRegex(MonitoringContractError, "source evidence type"):
            timeline_to_derived_evidence(timeline, (dns, object()), produced_at="2026-09-02T14:01:00Z")  # type: ignore[arg-type]

    def test_adapter_rejects_invalid_production_time(self) -> None:
        timeline = _timeline()
        dns = _source("evidence:dns-source", data_class="internal")
        flow = _source("evidence:flow-source", data_class="internal")
        with self.assertRaisesRegex(MonitoringContractError, "must include timezone"):
            timeline_to_derived_evidence(timeline, (dns, flow), produced_at="2026-09-02T14:01:00")

    def test_adapter_uses_most_restrictive_source_data_class(self) -> None:
        timeline = _timeline()
        dns = _source("evidence:dns-source", data_class="public")
        flow = _source("evidence:flow-source", data_class="restricted")
        derived = timeline_to_derived_evidence(
            timeline,
            (dns, flow),
            produced_at="2026-09-02T14:01:00Z",
        )
        self.assertEqual(derived.evidence.data_class, "restricted")

    def test_adapter_output_does_not_retain_raw_ip_values(self) -> None:
        timeline = _timeline()
        dns = _source("evidence:dns-source", data_class="confidential")
        flow = _source("evidence:flow-source", data_class="confidential")
        derived = timeline_to_derived_evidence(
            timeline,
            (dns, flow),
            produced_at="2026-09-02T14:01:00Z",
        )
        rendered = str(derived.public_dict())
        self.assertNotIn("10.44.0.10", rendered)
        self.assertNotIn("10.44.0.20", rendered)

    def test_adapter_rejects_structurally_tampered_timeline(self) -> None:
        timeline = _timeline()
        dns = _source("evidence:dns-source", data_class="internal")
        flow = _source("evidence:flow-source", data_class="internal")
        first = timeline_to_derived_evidence(
            timeline,
            (dns, flow),
            produced_at="2026-09-02T14:01:00Z",
        )

        changed_graph = replace(timeline.incident_graphs[0], graph_id="incident-tampered")
        changed = replace(timeline, incident_graphs=(changed_graph,))
        with self.assertRaisesRegex(MonitoringContractError, "graph_ids do not match graph order"):
            timeline_to_derived_evidence(
                changed,
                (dns, flow),
                produced_at="2026-09-02T14:01:00Z",
            )
        self.assertTrue(first.evidence.evidence_id.startswith("evidence:timeline-"))


if __name__ == "__main__":
    unittest.main()
