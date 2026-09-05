from __future__ import annotations

import json
import unittest
from dataclasses import replace

from three_agent.security_monitoring.behavior_intelligence import BehaviorAssessment, RULE_RARE_PEER
from three_agent.security_monitoring.behavior_risk import DeterministicBehaviorRiskScorer
from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.correlation_graph import IncidentGraph
from three_agent.security_monitoring.dns_behavior import extract_dns_behavior_features
from three_agent.security_monitoring.entity_context import opaque_entity_ref


def valid_graph() -> IncidentGraph:
    return IncidentGraph(
        graph_id="incident-boundary",
        event_ids=("evt-a", "evt-b"),
        evidence_refs=("event:evt-a", "event:evt-b"),
        entity_refs=(opaque_entity_ref("ip", "192.0.2.10"),),
        source_types=("zeek_json",),
        stage_types=("DNS", "FLOW"),
        first_seen="2026-09-01T12:00:00+00:00",
        last_seen="2026-09-01T12:00:10+00:00",
        severity="medium",
        priority="normal",
        rule_ids=("DNS_FLOW_EXACT_V1",),
        edge_ids=("edge-a",),
    )


class V004BoundaryTests(unittest.TestCase):
    def test_dns_feature_rejects_non_hex_typed_hash(self):
        feature = extract_dns_behavior_features(
            event_id="evt-dns-boundary",
            source_type="zeek_json",
            raw_line=json.dumps(
                {"_path": "dns", "query": "example.org", "rcode_name": "NOERROR"}
            ),
        )
        with self.assertRaises(MonitoringContractError):
            replace(
                feature,
                query_entity_ref="entity:dns:sha256:" + "z" * 64,
            ).validate()

    def test_risk_rejects_unsupported_graph_stage_schema_and_timestamp(self):
        scorer = DeterministicBehaviorRiskScorer()
        with self.assertRaises(MonitoringContractError):
            scorer.score(
                assessments=(),
                incident_graphs=(replace(valid_graph(), stage_types=("DNS", "MAGIC")),),
            )
        with self.assertRaises(MonitoringContractError):
            scorer.score(
                assessments=(),
                incident_graphs=(replace(valid_graph(), schema_version="tampered"),),
            )
        with self.assertRaises(MonitoringContractError):
            scorer.score(
                assessments=(),
                incident_graphs=(replace(valid_graph(), first_seen="2026-09-01T12:00:00"),),
            )

    def test_risk_output_entity_refs_are_bounded_after_full_identity_binding(self):
        assessments = []
        for index in range(300):
            assessments.append(
                BehaviorAssessment(
                    assessment_id=f"assessment-{index:03d}",
                    rule_id=RULE_RARE_PEER,
                    status="normal",
                    severity="info",
                    event_ids=(f"evt-{index:03d}",),
                    evidence_refs=(f"event:evt-{index:03d}",),
                    entity_refs=(opaque_entity_ref("ip", f"2001:db8::{index + 1}"),),
                ).validate()
            )
        receipt = DeterministicBehaviorRiskScorer().score(assessments=tuple(assessments))
        self.assertEqual(len(receipt.entity_refs), 256)
        self.assertLessEqual(len(receipt.evidence_refs), 512)
        self.assertEqual(receipt.score, 0)
        self.assertEqual(receipt.level, "info")


if __name__ == "__main__":
    unittest.main()
