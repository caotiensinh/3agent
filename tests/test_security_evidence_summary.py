from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from three_agent.security_monitoring.service import (
    RECENT_EVIDENCE_SAMPLE_LIMIT,
    SecurityMonitoringService,
    safe_recent_evidence_summary,
)


class _FakeReadModel:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int, int]] = []

    def summary(self) -> dict[str, object]:
        return {
            "health": "attention",
            "reason_codes": ["HIGH_CRITICAL_FINDINGS"],
            "open_finding_count": 2,
            "high_critical_count": 1,
            "latest_hourly": {
                "run_id": "run-secret-01",
                "status": "completed",
                "coverage_pct": 100.0,
                "expected_assets": 3,
                "observed_assets": 3,
                "observed_at": "2026-09-05T14:00:00+00:00",
                "age_seconds": 120.0,
            },
        }

    def admin_status(self) -> dict[str, object]:
        return {
            "database_available": True,
            "schema_version_db": 1,
            "secret_boundary_configured": True,
        }

    def network(self, *, limit: int, offset: int) -> dict[str, object]:
        self.calls.append(("network", limit, offset))
        return {
            "items": [
                {
                    "id": 7,
                    "asset_id": "asset-secret-01",
                    "value": {"token": "raw-token-secret"},
                    "evidence_ref": "evidence://observation-secret",
                },
                {
                    "id": 8,
                    "asset_id": "asset-secret-02",
                    "evidence_ref": None,
                },
            ]
        }

    def events(self, *, limit: int, offset: int) -> dict[str, object]:
        self.calls.append(("events", limit, offset))
        return {
            "items": [
                {
                    "event_id": "event-secret-01",
                    "source_id": "source-secret-01",
                    "evidence_ref": "evidence://event-secret",
                }
            ]
        }

    def findings(self, *, limit: int, offset: int) -> dict[str, object]:
        self.calls.append(("findings", limit, offset))
        return {
            "items": [
                {
                    "finding_id": "finding-secret-01",
                    "asset_refs": ["asset-secret-01"],
                    "evidence_refs": ["evidence://finding-secret"],
                },
                {
                    "finding_id": "finding-secret-02",
                    "asset_refs": ["asset-secret-02"],
                    "evidence_refs": [],
                },
            ]
        }

    def reports(self, *, limit: int, offset: int) -> dict[str, object]:
        self.calls.append(("reports", limit, offset))
        return {
            "items": [
                {
                    "archive_id": "archive-secret-01",
                    "manifest_sha256": "manifest-secret-hash",
                    "bundle_ref": "bundle://secret",
                }
            ]
        }


class SecurityEvidenceSummaryTests(unittest.TestCase):
    def test_projection_is_bounded_aggregate_only_and_strips_identifiers(self) -> None:
        read_model = _FakeReadModel()
        config = object()
        with patch(
            "three_agent.security_monitoring.service.SecurityMonitoringUIReadModel",
            return_value=read_model,
        ) as factory:
            payload = safe_recent_evidence_summary(config)  # type: ignore[arg-type]

        factory.assert_called_once_with(config, config_state="configured")
        expected_calls = [
            (name, RECENT_EVIDENCE_SAMPLE_LIMIT, 0)
            for name in ("network", "events", "findings", "reports")
        ]
        self.assertEqual(read_model.calls, expected_calls)
        self.assertEqual(payload["count_scope"], "recent_bounded_records")
        self.assertEqual(payload["max_records_per_stream"], 100)
        self.assertTrue(payload["database_available"])
        self.assertEqual(payload["observation_sample_count"], 2)
        self.assertEqual(payload["observation_evidence_linked_count"], 1)
        self.assertEqual(payload["event_sample_count"], 1)
        self.assertEqual(payload["event_evidence_linked_count"], 1)
        self.assertEqual(payload["finding_sample_count"], 2)
        self.assertEqual(payload["finding_evidence_linked_count"], 1)
        self.assertEqual(payload["report_sample_count"], 1)
        self.assertEqual(payload["open_finding_count"], 2)
        self.assertEqual(payload["high_critical_count"], 1)

        latest = payload["latest_hourly"]
        assert isinstance(latest, dict)
        self.assertNotIn("run_id", latest)
        self.assertEqual(latest["status"], "completed")
        self.assertEqual(latest["coverage_pct"], 100.0)

        serialized = json.dumps(payload, sort_keys=True)
        for sensitive_value in (
            "run-secret-01",
            "asset-secret-01",
            "asset-secret-02",
            "event-secret-01",
            "source-secret-01",
            "finding-secret-01",
            "finding-secret-02",
            "evidence://observation-secret",
            "evidence://event-secret",
            "evidence://finding-secret",
            "archive-secret-01",
            "manifest-secret-hash",
            "bundle://secret",
            "raw-token-secret",
        ):
            self.assertNotIn(sensitive_value, serialized)

        authority = payload["authority"]
        assert isinstance(authority, dict)
        self.assertTrue(authority["aggregate_only"])
        self.assertTrue(authority["database_read_only"])
        for key in (
            "raw_evidence_exposed",
            "asset_ids_exposed",
            "source_ids_exposed",
            "finding_ids_exposed",
            "evidence_refs_exposed",
            "bundle_refs_exposed",
            "database_write",
            "network_execution",
            "collector_execution",
            "packet_capture_execution",
            "remediation_execution",
        ):
            self.assertFalse(authority[key])

    def test_service_uses_constructor_config_and_exposes_no_runtime_selector(self) -> None:
        read_model = _FakeReadModel()
        sentinel_config = object()
        with (
            patch(
                "three_agent.security_monitoring.service.load_runtime_config",
                return_value=sentinel_config,
            ) as load_config,
            patch(
                "three_agent.security_monitoring.service.SecurityMonitoringUIReadModel",
                return_value=read_model,
            ) as factory,
        ):
            service = SecurityMonitoringService("monitoring.json")
            payload = service.evidence_summary()

        load_config.assert_called_once_with(Path("monitoring.json"))
        factory.assert_called_once_with(sentinel_config, config_state="configured")
        self.assertEqual(payload["schema_version"], "workspace-security-monitoring/recent-evidence-summary-v1")
        self.assertFalse(payload["authority"]["network_execution"])  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
