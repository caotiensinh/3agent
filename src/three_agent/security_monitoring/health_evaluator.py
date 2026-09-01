from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from .contracts import MonitoringContractError, ObservationRecord, _compact
from .health_state import HealthPolicyConfig, HealthStateRecord, HealthTransitionRecord, _utc_timestamp

_FAILURE = {"unreachable", "timeout"}
_DEGRADED = {"error", "unsupported", "discontinuity"}
_OK = {"ok"}


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass(frozen=True)
class HealthEvaluation:
    state: HealthStateRecord
    transition: HealthTransitionRecord | None
    unhealthy_streak: int
    hard_failure_streak: int
    recovery_streak: int


class DeterministicHealthEvaluator:
    """Interpret durable observations with bounded hysteresis and no I/O."""

    def __init__(self, policy: HealthPolicyConfig, *, max_samples: int = 256) -> None:
        self.policy = policy.validate()
        if isinstance(max_samples, bool) or not isinstance(max_samples, int) or not 1 <= max_samples <= 4096:
            raise MonitoringContractError("max_samples must be an integer within 1..4096")
        if max_samples < max(
            self.policy.failure_samples_to_unreachable,
            self.policy.recovery_samples_to_healthy,
        ):
            raise MonitoringContractError("max_samples cannot be smaller than hysteresis thresholds")
        self.max_samples = max_samples

    def evaluate(
        self,
        *,
        asset_id: str,
        observations: Iterable[ObservationRecord],
        evaluated_at: str,
        evaluation_evidence_ref: str,
        previous: HealthStateRecord | None = None,
        maintenance: bool = False,
        maintenance_evidence_ref: str | None = None,
    ) -> HealthEvaluation:
        asset = _compact(asset_id, "asset_id", max_len=128)
        now_text = _utc_timestamp(evaluated_at, "evaluated_at")
        now = _dt(now_text)
        evaluation_ref = _compact(evaluation_evidence_ref, "evaluation_evidence_ref", max_len=256)
        if not isinstance(maintenance, bool):
            raise MonitoringContractError("maintenance must be boolean")
        if maintenance and maintenance_evidence_ref is None:
            raise MonitoringContractError("maintenance requires maintenance_evidence_ref")

        items = list(observations)
        if len(items) > self.max_samples:
            raise MonitoringContractError("health observation window exceeds max_samples")
        validated: list[ObservationRecord] = []
        for observation in items:
            observation.validate()
            if observation.asset_id != asset:
                raise MonitoringContractError("health observation asset_id mismatch")
            if _dt(observation.observed_at) > now:
                raise MonitoringContractError("health observation cannot be in the future")
            validated.append(observation)
        validated.sort(
            key=lambda item: (
                _dt(item.observed_at), item.run_id, item.collector, item.metric, item.evidence_ref or ""
            )
        )

        if previous is not None:
            previous.validate()
            if previous.asset_id != asset:
                raise MonitoringContractError("previous health state asset_id mismatch")
            previous_state = previous.state
        else:
            previous_state = "unknown"

        refs = [evaluation_ref]
        for item in validated:
            if item.evidence_ref is not None and item.evidence_ref not in refs:
                refs.append(item.evidence_ref)

        if maintenance:
            maintenance_ref = _compact(maintenance_evidence_ref or "", "maintenance_evidence_ref", max_len=256)
            if maintenance_ref not in refs:
                refs.append(maintenance_ref)
            target, reason = "maintenance", "MAINTENANCE_ACTIVE"
            unhealthy = hard = recovery = 0
        elif not validated:
            target, reason = "data_gap", "NO_DURABLE_OBSERVATION"
            unhealthy = hard = recovery = 0
        else:
            latest = validated[-1]
            age = (now - _dt(latest.observed_at)).total_seconds()
            if age > self.policy.data_gap_after_seconds:
                target, reason = "data_gap", "OBSERVATION_DATA_GAP"
                unhealthy = hard = recovery = 0
            else:
                unhealthy = 0
                hard = 0
                recovery = 0
                for item in reversed(validated):
                    if item.status in _OK:
                        recovery += 1
                    else:
                        break
                for item in reversed(validated):
                    if item.status in _FAILURE | _DEGRADED:
                        unhealthy += 1
                    else:
                        break
                for item in reversed(validated):
                    if item.status in _FAILURE:
                        hard += 1
                    else:
                        break

                if previous_state in {"degraded", "unreachable", "data_gap"}:
                    if recovery >= self.policy.recovery_samples_to_healthy:
                        target, reason = "healthy", "RECOVERY_THRESHOLD_MET"
                    else:
                        target, reason = previous_state, "RECOVERY_HYSTERESIS_PENDING"
                elif hard >= self.policy.failure_samples_to_unreachable:
                    target, reason = "unreachable", "UNREACHABLE_THRESHOLD_MET"
                elif unhealthy >= self.policy.failure_samples_to_degraded:
                    target, reason = "degraded", "DEGRADED_THRESHOLD_MET"
                elif recovery >= self.policy.recovery_samples_to_healthy:
                    target, reason = "healthy", "HEALTHY_THRESHOLD_MET"
                else:
                    target, reason = previous_state, "HYSTERESIS_PENDING"

        state = HealthStateRecord(
            asset_id=asset,
            state=target,
            evaluated_at=now_text,
            evidence_refs=tuple(refs),
            reason_code=reason,
        ).validate()
        transition = None
        if target != previous_state:
            transition = HealthTransitionRecord(
                asset_id=asset,
                previous_state=previous_state,
                current_state=target,
                transitioned_at=now_text,
                evidence_refs=tuple(refs),
                reason_code=reason,
                policy_fingerprint=self.policy.fingerprint,
            ).validate()
        return HealthEvaluation(state, transition, unhealthy, hard, recovery)
