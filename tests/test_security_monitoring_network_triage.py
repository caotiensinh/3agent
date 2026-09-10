from __future__ import annotations

from dataclasses import replace
import inspect
import json
import unittest

import three_agent.security_monitoring.network_triage as triage_module
from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.correlation_graph import (
    RULE_AUTH_PROCESS,
    RULE_DNS_FLOW,
    RULE_FLOW_AUTH,
    RULE_IDS_CORROBORATION,
    IncidentGraph,
)
from three_agent.security_monitoring.network_triage import (
    NETWORK_TRIAGE_SCHEMA,
    DeterministicNetworkIncidentTriage,
    NetworkTriageConfig,
    network_triage_plan,
)


def opaque(kind: str, char: str) -> str:
    return f"entity:{kind}:sha256:" + char * 64


def graph(
    *,
    suffix: str = "a",
    stages: tuple[str, ...] = ("DNS", "FLOW", "AUTH", "PROCESS"),
    rules: tuple[str, ...] = (RULE_AUTH_PROCESS, RULE_DNS_FLOW, RULE_FLOW_AUTH),
    severity: str = "high",
    priority: str = "high",
    entity_refs: tuple[str, ...] | None = None,
) -> IncidentGraph:
    return IncidentGraph(
        graph_id="incident-" + suffix * 24,
        event_ids=(f"evt-{suffix}-1", f"evt-{suffix}-2"),
        evidence_refs=(f"event:evt-{suffix}-1", f"event:evt-{suffix}-2"),
        entity_refs=entity_refs or ("asset:server-rd-01", opaque("ip", suffix)),
        source_types=("workspace_audit", "zeek_json"),
        stage_types=stages,
        first_seen="2026-09-01T00:00:00+00:00",
        last_seen="2026-09-01T00:00:12+00:00",
        severity=severity,
        priority=priority,
        rule_ids=rules,
        edge_ids=("edge-" + suffix * 24,),
    )


class NetworkIncidentTriageTests(unittest.TestCase):
    def test_complete_chain_becomes_high_confidence_high_priority_advisory(self):
        record = DeterministicNetworkIncidentTriage().triage((graph(),))[0]
        self.assertEqual(record.schema_version, NETWORK_TRIAGE_SCHEMA)
        self.assertEqual(record.triage_kind, "dns-flow-auth-process")
        self.assertEqual(record.confidence, "high")
        self.assertEqual(record.severity, "high")
        self.assertEqual(record.investigation_priority, "high")
        self.assertEqual(record.authority, "advisory")
        self.assertIn("complete_exact_multistage_chain", record.reason_codes)
        self.assertTrue(record.graph_fingerprint.startswith("sha256:"))
        self.assertRegex(record.triage_id, r"^triage-[0-9a-f]{24}$")

    def test_partial_chains_are_classified_without_inventing_source_severity(self):
        dns_flow = graph(
            stages=("DNS", "FLOW"),
            rules=(RULE_DNS_FLOW,),
            severity="low",
            priority="normal",
        )
        record = DeterministicNetworkIncidentTriage().triage((dns_flow,))[0]
        self.assertEqual(record.triage_kind, "dns-flow")
        self.assertEqual(record.confidence, "medium")
        self.assertEqual(record.investigation_priority, "normal")
        self.assertEqual(record.severity, "low")

        flow_auth = graph(
            suffix="b",
            stages=("FLOW", "AUTH"),
            rules=(RULE_FLOW_AUTH,),
            severity="medium",
            priority="normal",
        )
        record = DeterministicNetworkIncidentTriage().triage((flow_auth,))[0]
        self.assertEqual(record.triage_kind, "flow-auth")
        self.assertEqual(record.investigation_priority, "elevated")
        self.assertEqual(record.severity, "medium")

        auth_process = graph(
            suffix="c",
            stages=("AUTH", "PROCESS"),
            rules=(RULE_AUTH_PROCESS,),
            severity="info",
            priority="normal",
        )
        record = DeterministicNetworkIncidentTriage().triage((auth_process,))[0]
        self.assertEqual(record.triage_kind, "auth-process")
        self.assertEqual(record.investigation_priority, "elevated")
        self.assertEqual(record.severity, "info")

    def test_two_link_chains_receive_high_confidence(self):
        dns_auth = graph(
            stages=("DNS", "FLOW", "AUTH"),
            rules=(RULE_DNS_FLOW, RULE_FLOW_AUTH),
            severity="medium",
            priority="high",
        )
        record = DeterministicNetworkIncidentTriage().triage((dns_auth,))[0]
        self.assertEqual(record.triage_kind, "dns-flow-auth")
        self.assertEqual(record.confidence, "high")
        self.assertEqual(record.investigation_priority, "high")

        post_auth = graph(
            suffix="b",
            stages=("FLOW", "AUTH", "PROCESS"),
            rules=(RULE_AUTH_PROCESS, RULE_FLOW_AUTH),
            severity="medium",
            priority="high",
        )
        record = DeterministicNetworkIncidentTriage().triage((post_auth,))[0]
        self.assertEqual(record.triage_kind, "flow-auth-process")
        self.assertEqual(record.confidence, "high")
        self.assertEqual(record.investigation_priority, "high")

    def test_ids_corroboration_strengthens_investigation_without_mutating_severity(self):
        corroborated = graph(
            stages=("FLOW", "AUTH", "IDS"),
            rules=(RULE_FLOW_AUTH, RULE_IDS_CORROBORATION),
            severity="medium",
            priority="high",
        )
        record = DeterministicNetworkIncidentTriage().triage((corroborated,))[0]
        self.assertEqual(record.triage_kind, "flow-auth")
        self.assertEqual(record.confidence, "high")
        self.assertEqual(record.investigation_priority, "high")
        self.assertEqual(record.severity, "medium")
        self.assertIn("independent_ids_corroboration", record.reason_codes)

        ids_only = graph(
            suffix="b",
            stages=("FLOW", "IDS"),
            rules=(RULE_IDS_CORROBORATION,),
            severity="low",
            priority="normal",
        )
        record = DeterministicNetworkIncidentTriage().triage((ids_only,))[0]
        self.assertEqual(record.triage_kind, "ids-corroborated")
        self.assertEqual(record.confidence, "medium")
        self.assertEqual(record.severity, "low")

    def test_public_output_retains_only_opaque_entities_and_evidence_references(self):
        record = DeterministicNetworkIncidentTriage().triage((graph(),))[0]
        rendered = json.dumps(record.public_dict(), sort_keys=True).lower()
        for forbidden in (
            "192.0.2.10",
            "198.51.100.20",
            "admin.example.internal",
            "alice",
            "/usr/bin/id",
            "password",
            "secret-value",
        ):
            self.assertNotIn(forbidden, rendered)
        self.assertIn("asset:server-rd-01", rendered)
        self.assertIn("entity:ip:sha256:", rendered)

    def test_replay_is_deduplicated_and_order_is_deterministic(self):
        first = graph()
        second = graph(suffix="b")
        engine = DeterministicNetworkIncidentTriage()
        replayed = engine.triage((second, first, first, second))
        normal = engine.triage((first, second))
        self.assertEqual(replayed, normal)
        self.assertEqual(len(replayed), 2)
        self.assertEqual(replayed[0].graph_id, first.graph_id)

    def test_conflicting_duplicate_graph_id_fails_closed(self):
        original = graph()
        conflicting = replace(original, severity="critical")
        with self.assertRaises(MonitoringContractError):
            DeterministicNetworkIncidentTriage().triage((original, conflicting))

    def test_schema_authority_and_rule_stage_inconsistency_fail_closed(self):
        engine = DeterministicNetworkIncidentTriage()
        with self.assertRaises(MonitoringContractError):
            engine.triage((replace(graph(), schema_version="future-v99"),))
        with self.assertRaises(MonitoringContractError):
            engine.triage((replace(graph(), authority="execute"),))
        with self.assertRaises(MonitoringContractError):
            engine.triage((replace(graph(), stage_types=("DNS", "AUTH")),))

    def test_raw_or_malformed_entity_identity_is_rejected(self):
        raw = graph(entity_refs=("asset:server-rd-01", "192.0.2.10"))
        with self.assertRaises(MonitoringContractError):
            DeterministicNetworkIncidentTriage().triage((raw,))

        wrong_hash = graph(entity_refs=("entity:user:sha256:not-a-hash",))
        with self.assertRaises(MonitoringContractError):
            DeterministicNetworkIncidentTriage().triage((wrong_hash,))

    def test_invalid_graph_and_edge_ids_fail_closed(self):
        with self.assertRaises(MonitoringContractError):
            DeterministicNetworkIncidentTriage().triage((replace(graph(), graph_id="incident-user-input"),))
        with self.assertRaises(MonitoringContractError):
            DeterministicNetworkIncidentTriage().triage((replace(graph(), edge_ids=("edge-user-input",)),))

    def test_global_bounds_are_enforced_after_replay_deduplication(self):
        first = graph()
        second = graph(suffix="b")
        with self.assertRaises(MonitoringContractError):
            DeterministicNetworkIncidentTriage(NetworkTriageConfig(max_graphs=1)).triage((first, second))
        with self.assertRaises(MonitoringContractError):
            DeterministicNetworkIncidentTriage(NetworkTriageConfig(max_event_refs=1)).triage((first,))
        with self.assertRaises(MonitoringContractError):
            DeterministicNetworkIncidentTriage(NetworkTriageConfig(max_entity_refs=1)).triage((first,))
        with self.assertRaises(MonitoringContractError):
            DeterministicNetworkIncidentTriage(NetworkTriageConfig(max_evidence_refs=1)).triage((first,))

    def test_plan_and_source_keep_analyst_stage_local_and_advisory(self):
        plan = network_triage_plan()
        self.assertEqual(plan["authority"], "advisory")
        self.assertEqual(plan["execution"], "local_deterministic")
        disabled = set(plan["disabled_capabilities"])
        self.assertTrue(
            {
                "active_discovery",
                "packet_capture",
                "command_execution",
                "network_mutation",
                "credential_retrieval",
                "remediation",
                "external_model_calls",
                "outbound_network",
            }.issubset(disabled)
        )

        source = inspect.getsource(triage_module)
        for forbidden in (
            "import socket",
            "import subprocess",
            "from subprocess",
            "requests.",
            "urlopen(",
            "OllamaClient",
            "generate_json(",
            "Popen(",
            "os.system(",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
