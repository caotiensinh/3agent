from __future__ import annotations

import inspect
import json
import unittest

import three_agent.security_monitoring.behavior_risk as behavior_risk
from three_agent.security_monitoring.behavior_intelligence import (
    BehaviorAssessment,
    RULE_DNS_CARDINALITY,
    RULE_DNS_ENTROPY,
    RULE_DNS_NXDOMAIN,
    RULE_RARE_PEER,
)
from three_agent.security_monitoring.behavior_risk import DeterministicBehaviorRiskScorer
from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.correlation_graph import IncidentGraph
from three_agent.security_monitoring.entity_context import opaque_entity_ref


SRC = opaque_entity_ref("ip", "192.0.2.10")
OTHER_SRC = opaque_entity_ref("ip", "192.0.2.11")
DST = opaque_entity_ref("ip", "198.51.100.20")
DNS = opaque_entity_ref("dns", "random.example.org")


def assessment(
    rule_id: str,
    *,
    event_id: str = "evt-a",
    entity_ref: str = DNS,
    scope_entity_ref: str = SRC,
) -> BehaviorAssessment:
    entity_refs = tuple(sorted({scope_entity_ref, entity_ref}))
    return BehaviorAssessment(
        assessment_id=f"assessment-{rule_id.lower()}-{event_id}",
        rule_id=rule_id,
        status="signal",
        severity="medium" if rule_id.startswith("DNS_") or rule_id == RULE_DNS_ENTROPY else "low",
        event_ids=(event_id,),
        evidence_refs=("event:" + event_id,),
        entity_refs=entity_refs,
        scope_entity_ref=scope_entity_ref,
        metric_name="test_metric",
        metric_value=1.0,
        threshold=1.0,
    ).validate()


def graph(*, graph_id: str = "incident-a", event_id: str = "evt-a", entity_ref: str = SRC) -> IncidentGraph:
    return IncidentGraph(
        graph_id=graph_id,
        event_ids=(event_id, "evt-flow", "evt-auth"),
        evidence_refs=("event:" + event_id, "event:evt-flow", "event:evt-auth"),
        entity_refs=(entity_ref,),
        source_types=("zeek_json", "workspace_audit"),
        stage_types=("DNS", "FLOW", "AUTH"),
        first_seen="2026-09-01T12:00:00+00:00",
        last_seen="2026-09-01T12:00:10+00:00",
        severity="high",
        priority="high",
        rule_ids=("DNS_FLOW_EXACT_V1", "FLOW_AUTH_EXACT_V1"),
        edge_ids=("edge-a", "edge-b"),
    )


class BehaviorRiskTests(unittest.TestCase):
    def test_single_rare_entity_is_low_not_high(self):
        receipt = DeterministicBehaviorRiskScorer().score(
            assessments=(assessment(RULE_RARE_PEER, entity_ref=DST),)
        )
        self.assertEqual(receipt.score, 10)
        self.assertEqual(receipt.level, "low")
        self.assertFalse(receipt.corroborated)
        self.assertEqual(receipt.scope_entity_ref, SRC)
        self.assertEqual(receipt.authority, "advisory")

    def test_exact_event_overlap_corroborates_entropy_with_multistage_graph(self):
        entropy = assessment(RULE_DNS_ENTROPY, event_id="evt-a", entity_ref=DNS)
        receipt = DeterministicBehaviorRiskScorer().score(
            assessments=(entropy,), incident_graphs=(graph(event_id="evt-a"),)
        )
        self.assertEqual(receipt.score, 60)
        self.assertEqual(receipt.level, "high")
        self.assertTrue(receipt.corroborated)
        self.assertEqual(receipt.scope_entity_ref, SRC)
        rendered = json.dumps(receipt.public_dict(), sort_keys=True)
        self.assertNotIn("random.example.org", rendered)
        self.assertNotIn("192.0.2.10", rendered)

    def test_unrelated_graph_is_excluded_from_scope_and_cannot_raise_score(self):
        entropy = assessment(RULE_DNS_ENTROPY, event_id="evt-a", entity_ref=DNS)
        unrelated = graph(
            graph_id="incident-unrelated",
            event_id="evt-unrelated",
            entity_ref=opaque_entity_ref("ip", "203.0.113.55"),
        )
        receipt = DeterministicBehaviorRiskScorer().score(
            assessments=(entropy,), incident_graphs=(unrelated,)
        )
        self.assertEqual(receipt.score, 25)
        self.assertEqual(receipt.level, "medium")
        self.assertFalse(receipt.corroborated)
        self.assertEqual(receipt.graph_ids, ())

    def test_three_independent_strong_dns_rules_can_reach_high_without_graph(self):
        receipt = DeterministicBehaviorRiskScorer().score(
            assessments=(
                assessment(RULE_DNS_ENTROPY, event_id="evt-e"),
                assessment(RULE_DNS_CARDINALITY, event_id="evt-c", entity_ref=SRC),
                assessment(RULE_DNS_NXDOMAIN, event_id="evt-n", entity_ref=SRC),
            )
        )
        self.assertEqual(receipt.score, 65)
        self.assertEqual(receipt.level, "high")
        self.assertFalse(receipt.corroborated)
        self.assertEqual(receipt.scope_entity_ref, SRC)

    def test_replay_and_same_rule_do_not_inflate_score(self):
        rare_a = assessment(RULE_RARE_PEER, event_id="evt-a", entity_ref=DST)
        other_dst = opaque_entity_ref("ip", "203.0.113.8")
        rare_b = BehaviorAssessment(
            assessment_id="assessment-rare-second",
            rule_id=RULE_RARE_PEER,
            status="signal",
            severity="low",
            event_ids=("evt-b",),
            evidence_refs=("event:evt-b",),
            entity_refs=tuple(sorted((SRC, other_dst))),
            scope_entity_ref=SRC,
        ).validate()
        scorer = DeterministicBehaviorRiskScorer()
        one = scorer.score(assessments=(rare_a,))
        replay = scorer.score(assessments=(rare_a, rare_a, rare_b))
        self.assertEqual(one.score, replay.score)
        self.assertEqual(replay.score, 10)

    def test_multiple_initiators_must_be_scored_independently(self):
        source_a = assessment(RULE_RARE_PEER, event_id="evt-a", entity_ref=DST, scope_entity_ref=SRC)
        source_b = assessment(
            RULE_DNS_ENTROPY,
            event_id="evt-b",
            entity_ref=DNS,
            scope_entity_ref=OTHER_SRC,
        )
        scorer = DeterministicBehaviorRiskScorer()
        with self.assertRaises(MonitoringContractError):
            scorer.score(assessments=(source_a, source_b))

        receipts = scorer.score_by_scope(assessments=(source_a, source_b))
        self.assertEqual(len(receipts), 2)
        self.assertEqual({item.scope_entity_ref for item in receipts}, {SRC, OTHER_SRC})
        self.assertEqual({item.score for item in receipts}, {10, 25})
        self.assertTrue(all(item.level != "high" for item in receipts))

    def test_signal_without_exact_initiator_scope_fails_closed(self):
        unscoped = BehaviorAssessment(
            assessment_id="assessment-unscoped",
            rule_id=RULE_RARE_PEER,
            status="signal",
            severity="low",
            event_ids=("evt-unscoped",),
            evidence_refs=("event:evt-unscoped",),
            entity_refs=(DST,),
        ).validate()
        with self.assertRaisesRegex(MonitoringContractError, "exact initiator scope"):
            DeterministicBehaviorRiskScorer().score(assessments=(unscoped,))

    def test_raw_entity_or_non_advisory_graph_fails_closed(self):
        bad = BehaviorAssessment(
            assessment_id="bad",
            rule_id=RULE_RARE_PEER,
            status="signal",
            severity="low",
            event_ids=("evt-bad",),
            evidence_refs=("event:bad",),
            entity_refs=(SRC, "198.51.100.20"),
            scope_entity_ref=SRC,
        ).validate()
        with self.assertRaises(MonitoringContractError):
            DeterministicBehaviorRiskScorer().score(assessments=(bad,))

        bad_graph = graph()
        object.__setattr__(bad_graph, "authority", "remediate")
        with self.assertRaises(MonitoringContractError):
            DeterministicBehaviorRiskScorer().score(assessments=(), incident_graphs=(bad_graph,))

    def test_scorer_has_no_network_model_or_remediation_authority(self):
        source = inspect.getsource(behavior_risk)
        for forbidden in (
            "import socket",
            "subprocess",
            "urlopen",
            "requests.",
            "OllamaClient",
            "generate_json",
            "firewall",
            "quarantine_host",
            "pcap",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
