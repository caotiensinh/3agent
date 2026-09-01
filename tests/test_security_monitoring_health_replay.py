from __future__ import annotations

import unittest

from three_agent.security_monitoring import (
    DeterministicHealthEvaluator,
    HealthPolicyConfig,
    HealthStateRecord,
    ObservationRecord,
)


def obs(n: int, status: str) -> ObservationRecord:
    return ObservationRecord(
        run_id=f"run-{n}",
        asset_id="switch-01",
        collector="icmp_echo",
        observed_at=f"2026-09-01T14:00:{n:02d}Z",
        metric="liveness",
        status=status,
        evidence_ref=f"obs:{n}",
    ).validate()


class HealthReplayIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = DeterministicHealthEvaluator(
            HealthPolicyConfig(
                failure_samples_to_degraded=2,
                failure_samples_to_unreachable=3,
                recovery_samples_to_healthy=2,
                data_gap_after_seconds=60,
            )
        )

    def replay(self) -> tuple[tuple[str, str | None], ...]:
        frames = (
            ("2026-09-01T14:00:08Z", (obs(1, "ok"),)),
            ("2026-09-01T14:00:09Z", (obs(1, "ok"), obs(2, "ok"))),
            ("2026-09-01T14:00:10Z", (obs(2, "ok"), obs(3, "timeout"))),
            ("2026-09-01T14:00:11Z", (obs(3, "timeout"), obs(4, "unreachable"))),
            ("2026-09-01T14:00:12Z", (obs(3, "timeout"), obs(4, "unreachable"), obs(5, "timeout"))),
            ("2026-09-01T14:00:13Z", (obs(5, "timeout"), obs(6, "ok"))),
            ("2026-09-01T14:00:14Z", (obs(6, "ok"), obs(7, "ok"))),
        )
        previous: HealthStateRecord | None = None
        receipts: list[tuple[str, str | None]] = []
        for index, (evaluated_at, observations) in enumerate(frames, start=1):
            result = self.engine.evaluate(
                asset_id="switch-01",
                observations=observations,
                evaluated_at=evaluated_at,
                evaluation_evidence_ref=f"eval:{index}",
                previous=previous,
            )
            receipts.append(
                (
                    result.state.to_json(),
                    None if result.transition is None else result.transition.to_json(),
                )
            )
            previous = result.state
        return tuple(receipts)

    def test_replay_is_byte_identical_and_contains_expected_transitions(self) -> None:
        first = self.replay()
        second = self.replay()
        self.assertEqual(first, second)

        states = [item[0] for item in first]
        self.assertIn('"state":"healthy"', states[1])
        self.assertIn('"state":"healthy"', states[2])
        self.assertIn('"state":"degraded"', states[3])
        self.assertIn('"state":"unreachable"', states[4])
        self.assertIn('"state":"unreachable"', states[5])
        self.assertIn('"state":"healthy"', states[6])

        transitions = [item[1] for item in first if item[1] is not None]
        self.assertEqual(len(transitions), 4)
        self.assertIn('"previous_state":"unknown"', transitions[0])
        self.assertIn('"current_state":"degraded"', transitions[1])
        self.assertIn('"previous_state":"degraded"', transitions[2])
        self.assertIn('"current_state":"unreachable"', transitions[2])
        self.assertIn('"previous_state":"unreachable"', transitions[3])
        self.assertIn('"current_state":"healthy"', transitions[3])

    def test_degraded_state_escalates_after_hard_failure_threshold(self) -> None:
        previous = HealthStateRecord(
            asset_id="switch-01",
            state="degraded",
            evaluated_at="2026-09-01T14:00:02Z",
            evidence_refs=("eval:previous",),
            reason_code="DEGRADED_THRESHOLD_MET",
        ).validate()
        result = self.engine.evaluate(
            asset_id="switch-01",
            observations=(obs(3, "timeout"), obs(4, "unreachable"), obs(5, "timeout")),
            evaluated_at="2026-09-01T14:00:10Z",
            evaluation_evidence_ref="eval:escalate",
            previous=previous,
        )
        self.assertEqual(result.state.state, "unreachable")
        self.assertIsNotNone(result.transition)
        assert result.transition is not None
        self.assertEqual(result.transition.reason_code, "UNREACHABLE_THRESHOLD_MET")
        self.assertEqual(result.transition.previous_state, "degraded")

    def test_data_gap_is_reclassified_only_after_fresh_bounded_evidence(self) -> None:
        previous = HealthStateRecord(
            asset_id="switch-01",
            state="data_gap",
            evaluated_at="2026-09-01T13:59:00Z",
            evidence_refs=("eval:gap",),
            reason_code="OBSERVATION_DATA_GAP",
        ).validate()
        pending = self.engine.evaluate(
            asset_id="switch-01",
            observations=(obs(4, "unreachable"),),
            evaluated_at="2026-09-01T14:00:10Z",
            evaluation_evidence_ref="eval:gap-1",
            previous=previous,
        )
        self.assertEqual(pending.state.state, "data_gap")
        self.assertIsNone(pending.transition)

        classified = self.engine.evaluate(
            asset_id="switch-01",
            observations=(obs(4, "unreachable"), obs(5, "timeout")),
            evaluated_at="2026-09-01T14:00:10Z",
            evaluation_evidence_ref="eval:gap-2",
            previous=previous,
        )
        self.assertEqual(classified.state.state, "degraded")
        self.assertIsNotNone(classified.transition)


if __name__ == "__main__":
    unittest.main()
