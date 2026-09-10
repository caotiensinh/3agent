from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from three_agent.security_monitoring.incident_posture import (
    INCIDENT_POSTURE_SAMPLE_LIMIT,
    safe_incident_posture_summary,
)
from three_agent.security_monitoring.service import SecurityMonitoringService


class _FakeReadModel:
    def __init__(self) -> None:
        self.calls: list[tuple[int, int]] = []

    def findings(self, *, limit: int, offset: int) -> dict[str, object]:
        self.calls.append((limit, offset))
        return {
            "items": [
                {
                    "finding_id": "finding-secret-critical",
                    "category": "credential-leak-secret-category",
                    "severity": "critical",
                    "status": "open",
                    "asset_refs": ["asset-secret-01"],
                    "evidence_refs": ["evidence://secret-critical"],
                    "rule_id": "rule-secret-critical",
                },
                {
                    "finding_id": "finding-secret-high",
                    "category": "network-secret-category",
                    "severity": "high",
                    "status": "investigating",
                    "asset_refs": ["asset-secret-02"],
                    "evidence_refs": ["evidence://secret-high"],
                    "rule_id": "rule-secret-high",
                },
                {
                    "finding_id": "finding-secret-resolved",
                    "category": "resolved-secret-category",
                    "severity": "medium",
                    "status": "resolved",
                    "asset_refs": ["asset-secret-03"],
                    "evidence_refs": ["evidence://secret-resolved"],
                    "rule_id": "rule-secret-resolved",
                },
                {
                    "finding_id": "finding-secret-unknown",
                    "category": "unknown-secret-category",
                    "severity": "secret-severity-value",
                    "status": "secret-status-value",
                    "asset_refs": ["asset-secret-04"],
                    "evidence_refs": ["evidence://secret-unknown"],
                    "rule_id": "rule-secret-unknown",
                },
            ]
        }


class SecurityIncidentPostureTests(unittest.TestCase):
    def test_projection_is_bounded_aggregate_only_and_strips_details(self) -> None:
        read_model = _FakeReadModel()
        config = object()
        with patch(
            "three_agent.security_monitoring.incident_posture.SecurityMonitoringUIReadModel",
            return_value=read_model,
        ) as factory:
            payload = safe_incident_posture_summary(config)  # type: ignore[arg-type]

        factory.assert_called_once_with(config, config_state="configured")
        self.assertEqual(read_model.calls, [(INCIDENT_POSTURE_SAMPLE_LIMIT, 0)])
        self.assertEqual(payload["count_scope"], "recent_bounded_findings")
        self.assertEqual(payload["max_findings"], 100)
        self.assertEqual(payload["sample_count"], 4)
        self.assertEqual(payload["open_sample_count"], 3)
        self.assertEqual(payload["closed_sample_count"], 1)
        self.assertEqual(
            payload["severity_counts"],
            {"critical": 1, "high": 1, "medium": 1, "other": 1},
        )
        self.assertEqual(
            payload["status_counts"],
            {"investigating": 1, "open": 1, "other": 1, "resolved": 1},
        )
        self.assertEqual(payload["attention_level"], "critical")

        serialized = json.dumps(payload, sort_keys=True)
        for sensitive_value in (
            "finding-secret-critical",
            "finding-secret-high",
            "finding-secret-resolved",
            "finding-secret-unknown",
            "credential-leak-secret-category",
            "network-secret-category",
            "resolved-secret-category",
            "unknown-secret-category",
            "secret-severity-value",
            "secret-status-value",
            "asset-secret-01",
            "asset-secret-02",
            "asset-secret-03",
            "asset-secret-04",
            "evidence://secret-critical",
            "evidence://secret-high",
            "evidence://secret-resolved",
            "evidence://secret-unknown",
            "rule-secret-critical",
            "rule-secret-high",
            "rule-secret-resolved",
            "rule-secret-unknown",
        ):
            self.assertNotIn(sensitive_value, serialized)

        authority = payload["authority"]
        assert isinstance(authority, dict)
        self.assertTrue(authority["aggregate_only"])
        self.assertTrue(authority["database_read_only"])
        for key in (
            "finding_ids_exposed",
            "asset_refs_exposed",
            "evidence_refs_exposed",
            "rule_ids_exposed",
            "category_values_exposed",
            "browser_filters_exposed",
            "database_write",
            "network_execution",
            "collector_execution",
            "packet_capture_execution",
            "remediation_execution",
        ):
            self.assertFalse(authority[key])

    def test_attention_level_is_clear_when_sample_has_no_open_findings(self) -> None:
        read_model = _FakeReadModel()
        read_model.findings = lambda *, limit, offset: {  # type: ignore[method-assign]
            "items": [
                {"severity": "critical", "status": "resolved"},
                {"severity": "high", "status": "closed"},
            ]
        }
        with patch(
            "three_agent.security_monitoring.incident_posture.SecurityMonitoringUIReadModel",
            return_value=read_model,
        ):
            payload = safe_incident_posture_summary(object())  # type: ignore[arg-type]

        self.assertEqual(payload["open_sample_count"], 0)
        self.assertEqual(payload["attention_level"], "clear")

    def test_service_uses_constructor_config_and_exposes_no_runtime_selector(self) -> None:
        sentinel_config = object()
        expected = {
            "schema_version": "workspace-security-monitoring/incident-posture-v1",
            "authority": {"aggregate_only": True, "network_execution": False},
        }
        with (
            patch(
                "three_agent.security_monitoring.service.load_runtime_config",
                return_value=sentinel_config,
            ) as load_config,
            patch(
                "three_agent.security_monitoring.service.safe_incident_posture_summary",
                return_value=expected,
            ) as projection,
        ):
            service = SecurityMonitoringService("monitoring.json")
            payload = service.incident_posture()

        load_config.assert_called_once_with(Path("monitoring.json"))
        projection.assert_called_once_with(sentinel_config)
        self.assertEqual(payload, expected)


if __name__ == "__main__":
    unittest.main()
