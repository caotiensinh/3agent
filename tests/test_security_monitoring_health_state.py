from __future__ import annotations

import unittest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.health_state import (
    HEALTH_STATES,
    HealthPolicyConfig,
    HealthStateRecord,
    HealthTransitionRecord,
)


class HealthStateContractTests(unittest.TestCase):
    def test_required_semantics_are_fixed(self) -> None:
        self.assertEqual(
            HEALTH_STATES,
            {"unknown", "healthy", "degraded", "unreachable", "maintenance", "data_gap"},
        )

    def test_policy_thresholds_are_bounded_and_fingerprinted(self) -> None:
        config = HealthPolicyConfig(
            failure_samples_to_degraded=2,
            failure_samples_to_unreachable=4,
            recovery_samples_to_healthy=3,
            data_gap_after_seconds=600,
        ).validate()
        self.assertEqual(config.fingerprint, HealthPolicyConfig(**config.to_dict()).validate().fingerprint)

    def test_policy_rejects_non_integer_and_ambiguous_failure_thresholds(self) -> None:
        invalid = [
            {"failure_samples_to_degraded": True},
            {"failure_samples_to_degraded": 0},
            {"failure_samples_to_degraded": 3, "failure_samples_to_unreachable": 3},
            {"failure_samples_to_degraded": 5, "failure_samples_to_unreachable": 4},
            {"recovery_samples_to_healthy": 0},
            {"data_gap_after_seconds": 86401},
        ]
        for overrides in invalid:
            with self.subTest(overrides=overrides):
                with self.assertRaises(MonitoringContractError):
                    HealthPolicyConfig(**overrides).validate()

    def test_state_is_interpretation_and_can_exist_without_transition(self) -> None:
        record = HealthStateRecord(
            asset_id="switch-01",
            state="unknown",
            evaluated_at="2026-09-01T14:00:00+00:00",
            reason_code="NO_DURABLE_OBSERVATION",
        ).validate()
        self.assertEqual(record.evaluated_at, "2026-09-01T14:00:00Z")
        self.assertEqual(record.evidence_refs, ())
        self.assertEqual(record.state, "unknown")

    def test_state_rejects_non_utc_and_unknown_semantics(self) -> None:
        with self.assertRaises(MonitoringContractError):
            HealthStateRecord("switch-01", "down", "2026-09-01T14:00:00Z").validate()
        with self.assertRaises(MonitoringContractError):
            HealthStateRecord("switch-01", "healthy", "2026-09-01T23:00:00+09:00").validate()

    def test_state_deduplicates_evidence_deterministically(self) -> None:
        record = HealthStateRecord(
            asset_id="switch-01",
            state="healthy",
            evaluated_at="2026-09-01T14:00:00Z",
            evidence_refs=("obs:2", "obs:1", "obs:2"),
        ).validate()
        self.assertEqual(record.evidence_refs, ("obs:2", "obs:1"))
        self.assertEqual(record.to_json(), HealthStateRecord(**{
            "asset_id": "switch-01",
            "state": "healthy",
            "evaluated_at": "2026-09-01T14:00:00Z",
            "evidence_refs": ("obs:2", "obs:1"),
        }).validate().to_json())

    def test_transition_requires_actual_change_and_evidence_lineage(self) -> None:
        policy = HealthPolicyConfig().validate()
        with self.assertRaises(MonitoringContractError):
            HealthTransitionRecord(
                asset_id="switch-01",
                previous_state="healthy",
                current_state="healthy",
                transitioned_at="2026-09-01T14:01:00Z",
                evidence_refs=("obs:1",),
                reason_code="NO_CHANGE",
                policy_fingerprint=policy.fingerprint,
            ).validate()
        with self.assertRaises(MonitoringContractError):
            HealthTransitionRecord(
                asset_id="switch-01",
                previous_state="healthy",
                current_state="degraded",
                transitioned_at="2026-09-01T14:01:00Z",
                evidence_refs=(),
                reason_code="FAILURE_THRESHOLD_MET",
                policy_fingerprint=policy.fingerprint,
            ).validate()

    def test_transition_is_canonical_and_carries_policy_fingerprint(self) -> None:
        policy = HealthPolicyConfig().validate()
        transition = HealthTransitionRecord(
            asset_id="switch-01",
            previous_state="healthy",
            current_state="degraded",
            transitioned_at="2026-09-01T14:01:00+00:00",
            evidence_refs=("obs:10", "obs:11"),
            reason_code="FAILURE_THRESHOLD_MET",
            policy_fingerprint=policy.fingerprint,
        ).validate()
        self.assertEqual(transition.transitioned_at, "2026-09-01T14:01:00Z")
        self.assertEqual(transition.policy_fingerprint, policy.fingerprint)
        self.assertEqual(transition.fingerprint, transition.fingerprint)


if __name__ == "__main__":
    unittest.main()
