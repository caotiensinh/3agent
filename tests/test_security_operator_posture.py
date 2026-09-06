from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from three_agent.security_monitoring.contracts import CanonicalEvent, MonitoringContractError
from three_agent.security_monitoring.correlation_graph import CorrelationEvent
from three_agent.security_monitoring.entity_context import EventEntityContext, EventEntityReference
from three_agent.security_monitoring.operator_posture import (
    OPERATOR_POSTURE_EVENT_LIMIT,
    OPERATOR_POSTURE_SCHEMA,
    reduce_operator_posture,
)


def _event(
    event_id: str,
    *,
    source_type: str,
    category: str,
    observed_at: str,
    severity: str,
    refs: tuple[EventEntityReference, ...],
) -> CorrelationEvent:
    event = CanonicalEvent(
        event_id=event_id,
        source_id=f"source-secret-{event_id}",
        source_type=source_type,
        observed_at=observed_at,
        category=category,
        severity=severity,
        message_sha256="sha256:" + "a" * 64,
        parser_version="parser-secret-v1",
        evidence_ref=f"evidence://secret/{event_id}",
    ).validate()
    context = EventEntityContext(event_id=event_id, references=refs).validate()
    return CorrelationEvent(event=event, context=context).validate()


class SecurityOperatorPostureTests(unittest.TestCase):
    def setUp(self) -> None:
        source_ip = EventEntityReference.opaque(kind="ip", role="source_ip", value="192.0.2.10")
        destination_ip = EventEntityReference.opaque(
            kind="ip", role="destination_ip", value="203.0.113.20"
        )
        dns_answer = EventEntityReference.opaque(
            kind="ip", role="dns_answer", value="203.0.113.20"
        )
        service = EventEntityReference.opaque(kind="service", role="service", value="ssh")
        asset = EventEntityReference.approved_asset(role="asset", asset_id="asset-secret-core-01")
        user = EventEntityReference.opaque(kind="user", role="auth_user", value="Alice.Secret")
        process = EventEntityReference.opaque(
            kind="process", role="process_image", value="C:/Secret/process.exe"
        )
        self.refs = (source_ip, destination_ip, dns_answer, service, asset, user, process)
        self.events = (
            _event(
                "event-secret-dns",
                source_type="suricata_eve",
                category="suricata.dns",
                observed_at="2026-09-06T03:00:00+00:00",
                severity="low",
                refs=(source_ip, dns_answer),
            ),
            _event(
                "event-secret-flow",
                source_type="suricata_eve",
                category="suricata.flow",
                observed_at="2026-09-06T03:01:00+00:00",
                severity="medium",
                refs=(source_ip, destination_ip, service),
            ),
            _event(
                "event-secret-auth",
                source_type="workspace_audit",
                category="workspace_audit.auth_success",
                observed_at="2026-09-06T03:02:00+00:00",
                severity="high",
                refs=(source_ip, destination_ip, service, asset, user),
            ),
            _event(
                "event-secret-process",
                source_type="workspace_audit",
                category="workspace_audit.process_start",
                observed_at="2026-09-06T03:03:00+00:00",
                severity="high",
                refs=(asset, user, process),
            ),
        )

    def test_projection_combines_risk_health_correlation_flow_and_timeline_without_leaks(self) -> None:
        soc = {
            "report_id": "report-secret-id",
            "risk_summary": {
                "today_open_high_critical": 2,
                "rolling_7d_open_high_critical": 5,
                "rolling_30d_open_high_critical": 9,
                "today_data_gaps": 1,
                "secret-risk-field": "secret-risk-value",
            },
            "overview": {
                "today": {
                    "event_count": 10,
                    "finding_count": 3,
                    "severity_counts": {
                        "info": 1,
                        "low": 2,
                        "medium": 3,
                        "high": 3,
                        "critical": 1,
                        "secret-severity": 999,
                    },
                    "starts_at": "2026-09-06T00:00:00+00:00",
                }
            },
            "evidence_refs": ["evidence://soc-secret"],
        }
        assets = {
            "items": [
                {
                    "asset_id": "asset-secret-healthy",
                    "enabled": True,
                    "role": "secret-role",
                    "observed_state": {"last_status": "ok", "last_observed_at": "secret-time"},
                },
                {
                    "asset_id": "asset-secret-degraded",
                    "enabled": True,
                    "observed_state": {"last_status": "error"},
                },
                {
                    "asset_id": "asset-secret-unreachable",
                    "enabled": True,
                    "observed_state": {"last_status": "timeout"},
                },
                {
                    "asset_id": "asset-secret-unknown",
                    "enabled": True,
                    "observed_state": {"last_status": "secret-status-value"},
                },
                {
                    "asset_id": "asset-secret-disabled",
                    "enabled": False,
                    "observed_state": {"last_status": "ok"},
                },
            ]
        }

        payload = reduce_operator_posture(
            soc=soc,
            assets=assets,
            correlation_events=self.events,
            now=datetime(2026, 9, 6, 3, 10, tzinfo=timezone.utc),
        )

        self.assertEqual(payload["schema_version"], OPERATOR_POSTURE_SCHEMA)
        self.assertEqual(payload["max_correlation_events"], 100)
        self.assertEqual(payload["risk"]["today_open_high_critical"], 2)  # type: ignore[index]
        self.assertEqual(
            payload["asset_health"]["state_counts"],  # type: ignore[index]
            {"healthy": 1, "degraded": 1, "unreachable": 1, "unknown": 1},
        )
        correlation = payload["correlation"]
        assert isinstance(correlation, dict)
        self.assertEqual(correlation["incident_graph_count"], 1)
        self.assertEqual(correlation["correlated_event_count"], 4)
        self.assertEqual(correlation["multi_stage_graph_count"], 1)
        self.assertTrue(correlation["exact_correlation_observed"])

        flow = payload["flow"]
        assert isinstance(flow, dict)
        self.assertTrue(flow["available"])
        self.assertEqual(flow["flow_event_count"], 1)
        self.assertTrue(flow["cross_stage_correlation_observed"])

        timeline = payload["timeline"]
        assert isinstance(timeline, dict)
        self.assertTrue(timeline["available"])
        self.assertEqual(timeline["entry_count"], 4)
        self.assertEqual(timeline["incident_graph_count"], 1)
        self.assertEqual(timeline["recency_counts"]["last_15m"], 4)  # type: ignore[index]

        serialized = json.dumps(payload, sort_keys=True)
        sensitive_values = [
            "report-secret-id",
            "secret-risk-value",
            "secret-severity",
            "asset-secret-healthy",
            "asset-secret-degraded",
            "asset-secret-unreachable",
            "asset-secret-unknown",
            "secret-role",
            "secret-time",
            "secret-status-value",
            "192.0.2.10",
            "203.0.113.20",
            "Alice.Secret",
            "C:/Secret/process.exe",
            "parser-secret-v1",
            "2026-09-06T03:00:00+00:00",
        ]
        sensitive_values.extend(event.event.event_id for event in self.events)
        sensitive_values.extend(str(event.event.evidence_ref) for event in self.events)
        sensitive_values.extend(reference.entity_ref for reference in self.refs)
        for value in sensitive_values:
            self.assertNotIn(value, serialized)

        authority = payload["authority"]
        assert isinstance(authority, dict)
        self.assertTrue(authority["aggregate_only"])
        self.assertTrue(authority["database_read_only"])
        for key in (
            "exact_timestamps_exposed",
            "event_ids_exposed",
            "graph_ids_exposed",
            "entity_refs_exposed",
            "evidence_refs_exposed",
            "rule_ids_exposed",
            "asset_ids_exposed",
            "network_addresses_exposed",
            "raw_values_exposed",
            "browser_filters_exposed",
            "database_write",
            "network_execution",
            "collector_execution",
            "packet_capture_execution",
            "remediation_execution",
        ):
            self.assertFalse(authority[key])

    def test_event_bound_fails_closed(self) -> None:
        with self.assertRaisesRegex(MonitoringContractError, "event bound exceeded"):
            reduce_operator_posture(
                soc={},
                assets={},
                correlation_events=[self.events[0]] * (OPERATOR_POSTURE_EVENT_LIMIT + 1),
                now=datetime(2026, 9, 6, 3, 10, tzinfo=timezone.utc),
            )


if __name__ == "__main__":
    unittest.main()
