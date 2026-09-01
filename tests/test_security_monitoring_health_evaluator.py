from __future__ import annotations

import unittest

from three_agent.security_monitoring.contracts import MonitoringContractError, ObservationRecord
from three_agent.security_monitoring.health_evaluator import DeterministicHealthEvaluator
from three_agent.security_monitoring.health_state import HealthPolicyConfig, HealthStateRecord


def obs(n: int, status: str, *, at: str | None = None, asset_id: str = "switch-01") -> ObservationRecord:
    return ObservationRecord(
        run_id=f"run-{n}",
        asset_id=asset_id,
        collector="icmp_echo",
        observed_at=at or f"2026-09-01T14:00:{n:02d}Z",
        metric="liveness",
        status=status,
        evidence_ref=f"obs:{n}",
    ).validate()


def previous(state: str, at: str = "2026-09-01T14:00:00Z") -> HealthStateRecord:
    return HealthStateRecord(
        asset_id="switch-01",
        state=state,
        evaluated_at=at,
        evidence_refs=("eval:previous",),
        reason_code="PREVIOUS",
    ).validate()


class HealthHysteresisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = DeterministicHealthEvaluator(
            HealthPolicyConfig(
                failure_samples_to_degraded=2,
                failure_samples_to_unreachable=3,
                recovery_samples_to_healthy=2,
                data_gap_after_seconds=60,
            )
        )

    def evaluate(self, observations, **kwargs):
        return self.engine.evaluate(
            asset_id="switch-01",
            observations=observations,
            evaluated_at=kwargs.pop("evaluated_at", "2026-09-01T14:00:20Z"),
            evaluation_evidence_ref="eval:20",
            **kwargs,
        )

    def test_single_failure_does_not_promote_alert_state(self) -> None:
        result = self.evaluate([obs(1, "ok"), obs(2, "unreachable")], previous=previous("healthy"))
        self.assertEqual(result.state.state, "healthy")
        self.assertIsNone(result.transition)
        self.assertEqual(result.state.reason_code, "HYSTERESIS_PENDING")

    def test_two_failures_promote_to_degraded_not_unreachable(self) -> None:
        result = self.evaluate([obs(1, "ok"), obs(2, "timeout"), obs(3, "unreachable")], previous=previous("healthy"))
        self.assertEqual(result.state.state, "degraded")
        self.assertEqual(result.unhealthy_streak, 2)
        self.assertEqual(result.hard_failure_streak, 2)
        self.assertEqual(result.transition.current_state, "degraded")
        self.assertIn("obs:3", result.transition.evidence_refs)

    def test_three_hard_failures_promote_to_unreachable(self) -> None:
        result = self.evaluate([obs(1, "timeout"), obs(2, "unreachable"), obs(3, "timeout")], previous=previous("healthy"))
        self.assertEqual(result.state.state, "unreachable")
        self.assertEqual(result.transition.reason_code, "UNREACHABLE_THRESHOLD_MET")

    def test_degraded_signal_cannot_escalate_to_unreachable(self) -> None:
        result = self.evaluate([obs(1, "error"), obs(2, "unsupported"), obs(3, "discontinuity")], previous=previous("healthy"))
        self.assertEqual(result.state.state, "degraded")
        self.assertEqual(result.hard_failure_streak, 0)

    def test_one_good_sample_does_not_recover(self) -> None:
        result = self.evaluate([obs(1, "unreachable"), obs(2, "unreachable"), obs(3, "unreachable"), obs(4, "ok")], previous=previous("unreachable"))
        self.assertEqual(result.state.state, "unreachable")
        self.assertIsNone(result.transition)
        self.assertEqual(result.recovery_streak, 1)

    def test_recovery_threshold_moves_to_healthy(self) -> None:
        result = self.evaluate([obs(1, "unreachable"), obs(2, "unreachable"), obs(3, "unreachable"), obs(4, "ok"), obs(5, "ok")], previous=previous("unreachable"))
        self.assertEqual(result.state.state, "healthy")
        self.assertEqual(result.transition.reason_code, "RECOVERY_THRESHOLD_MET")

    def test_unknown_requires_two_good_samples_before_healthy(self) -> None:
        first = self.evaluate([obs(1, "ok")])
        self.assertEqual(first.state.state, "unknown")
        self.assertIsNone(first.transition)
        second = self.evaluate([obs(1, "ok"), obs(2, "ok")])
        self.assertEqual(second.state.state, "healthy")
        self.assertEqual(second.transition.previous_state, "unknown")

    def test_no_observation_becomes_data_gap_with_evaluation_evidence(self) -> None:
        result = self.evaluate([])
        self.assertEqual(result.state.state, "data_gap")
        self.assertEqual(result.transition.evidence_refs, ("eval:20",))

    def test_stale_latest_observation_becomes_data_gap(self) -> None:
        result = self.evaluate([obs(1, "ok", at="2026-09-01T13:58:00Z")])
        self.assertEqual(result.state.state, "data_gap")
        self.assertIn("obs:1", result.transition.evidence_refs)

    def test_maintenance_requires_explicit_evidence_and_overrides_samples(self) -> None:
        with self.assertRaises(MonitoringContractError):
            self.evaluate([obs(1, "unreachable")], maintenance=True)
        result = self.evaluate(
            [obs(1, "unreachable")], maintenance=True, maintenance_evidence_ref="maintenance:ticket-12"
        )
        self.assertEqual(result.state.state, "maintenance")
        self.assertIn("maintenance:ticket-12", result.transition.evidence_refs)

    def test_input_order_does_not_change_result(self) -> None:
        left = self.evaluate([obs(1, "ok"), obs(2, "timeout"), obs(3, "unreachable")], previous=previous("healthy"))
        right = self.evaluate([obs(3, "unreachable"), obs(1, "ok"), obs(2, "timeout")], previous=previous("healthy"))
        self.assertEqual(left.state.to_json(), right.state.to_json())
        self.assertEqual(left.transition.to_json(), right.transition.to_json())

    def test_bounds_asset_mismatch_and_future_sample_fail_closed(self) -> None:
        small = DeterministicHealthEvaluator(HealthPolicyConfig(), max_samples=3)
        with self.assertRaises(MonitoringContractError):
            small.evaluate(
                asset_id="switch-01",
                observations=[obs(1, "ok"), obs(2, "ok"), obs(3, "ok"), obs(4, "ok")],
                evaluated_at="2026-09-01T14:00:20Z",
                evaluation_evidence_ref="eval:20",
            )
        with self.assertRaises(MonitoringContractError):
            self.evaluate([obs(1, "ok", asset_id="switch-02")])
        with self.assertRaises(MonitoringContractError):
            self.evaluate([obs(1, "ok", at="2026-09-01T14:01:00Z")])


if __name__ == "__main__":
    unittest.main()
