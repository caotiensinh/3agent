from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from .contracts import MonitoringContractError, SEVERITIES, _compact, canonical_json, sha256_fingerprint
from .correlation_graph import CorrelationEvent, STAGE_ORDER
from .entity_context import ENTITY_ROLES, EventEntityReference
from .temporal_behavior import DeterministicTemporalBucketizer, TemporalAnalysisWindow, TemporalBucketConfig

TEMPORAL_SCENARIO_SCHEMA = "workspace-security-monitoring/temporal-scenario-v1"
TEMPORAL_ASSESSMENT_SCHEMA = "workspace-security-monitoring/temporal-assessment-v1"


def _bounded_int(value: int, field_name: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MonitoringContractError(f"{field_name} must be an integer")
    if value < minimum or value > maximum:
        raise MonitoringContractError(f"{field_name} must be within {minimum}..{maximum}")
    return value


def _canonical_utc(value: str, field_name: str) -> str:
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise MonitoringContractError(f"{field_name} must include timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class TemporalScenario:
    scenario_id: str
    stage: str
    scope_role: str
    min_events_per_bucket: int = 2
    min_matching_buckets: int = 2
    require_consecutive: bool = True
    severity: str = "medium"
    authority: str = "advisory"
    schema_version: str = TEMPORAL_SCENARIO_SCHEMA

    def validate(self) -> "TemporalScenario":
        object.__setattr__(self, "scenario_id", _compact(self.scenario_id, "scenario_id", max_len=128))
        stage = str(self.stage or "").strip().upper()
        if stage not in STAGE_ORDER:
            raise MonitoringContractError("temporal scenario stage is unsupported")
        object.__setattr__(self, "stage", stage)
        role = str(self.scope_role or "").strip().lower()
        if role not in ENTITY_ROLES:
            raise MonitoringContractError("temporal scenario scope_role is unsupported")
        object.__setattr__(self, "scope_role", role)
        object.__setattr__(
            self,
            "min_events_per_bucket",
            _bounded_int(self.min_events_per_bucket, "min_events_per_bucket", minimum=1, maximum=1000),
        )
        object.__setattr__(
            self,
            "min_matching_buckets",
            _bounded_int(self.min_matching_buckets, "min_matching_buckets", minimum=1, maximum=64),
        )
        if not isinstance(self.require_consecutive, bool):
            raise MonitoringContractError("require_consecutive must be boolean")
        if self.severity not in SEVERITIES:
            raise MonitoringContractError("temporal scenario severity is unsupported")
        if self.authority != "advisory":
            raise MonitoringContractError("temporal scenarios cannot grant execution authority")
        if self.schema_version != TEMPORAL_SCENARIO_SCHEMA:
            raise MonitoringContractError("unsupported temporal scenario schema")
        return self

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "authority": self.authority,
            "min_events_per_bucket": self.min_events_per_bucket,
            "min_matching_buckets": self.min_matching_buckets,
            "require_consecutive": self.require_consecutive,
            "scenario_id": self.scenario_id,
            "schema_version": self.schema_version,
            "scope_role": self.scope_role,
            "severity": self.severity,
            "stage": self.stage,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


@dataclass(frozen=True, order=True)
class TemporalScenarioAssessment:
    assessment_id: str
    scenario_id: str
    scope_role: str
    scope_entity_ref: str
    bucket_indices: tuple[int, ...]
    event_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    first_seen: str
    last_seen: str
    severity: str
    scenario_fingerprint: str
    authority: str = "advisory"
    schema_version: str = TEMPORAL_ASSESSMENT_SCHEMA

    def validate(self) -> "TemporalScenarioAssessment":
        object.__setattr__(self, "assessment_id", _compact(self.assessment_id, "assessment_id", max_len=128))
        object.__setattr__(self, "scenario_id", _compact(self.scenario_id, "scenario_id", max_len=128))
        role = str(self.scope_role or "").strip().lower()
        kind = ENTITY_ROLES.get(role)
        if kind is None:
            raise MonitoringContractError("temporal assessment scope_role is unsupported")
        EventEntityReference(kind=kind, role=role, entity_ref=self.scope_entity_ref).validate()
        object.__setattr__(self, "scope_role", role)
        buckets = tuple(sorted(set(self.bucket_indices)))
        if not buckets or len(buckets) > 64 or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in buckets):
            raise MonitoringContractError("temporal assessment bucket_indices are outside bounds")
        object.__setattr__(self, "bucket_indices", buckets)
        events = tuple(sorted(set(_compact(value, "event_id", max_len=128) for value in self.event_ids)))
        evidence = tuple(sorted(set(_compact(value, "evidence_ref", max_len=256) for value in self.evidence_refs)))
        if not events or not evidence or len(events) > 256 or len(evidence) > 256:
            raise MonitoringContractError("temporal assessment evidence is outside bounds")
        object.__setattr__(self, "event_ids", events)
        object.__setattr__(self, "evidence_refs", evidence)
        first = _canonical_utc(self.first_seen, "first_seen")
        last = _canonical_utc(self.last_seen, "last_seen")
        if datetime.fromisoformat(last.replace("Z", "+00:00")) < datetime.fromisoformat(first.replace("Z", "+00:00")):
            raise MonitoringContractError("temporal assessment last_seen precedes first_seen")
        object.__setattr__(self, "first_seen", first)
        object.__setattr__(self, "last_seen", last)
        if self.severity not in SEVERITIES:
            raise MonitoringContractError("temporal assessment severity is unsupported")
        fingerprint = str(self.scenario_fingerprint or "").strip().lower()
        if not fingerprint.startswith("sha256:") or len(fingerprint) != 71:
            raise MonitoringContractError("scenario_fingerprint must be a sha256 digest")
        object.__setattr__(self, "scenario_fingerprint", fingerprint)
        if self.authority != "advisory":
            raise MonitoringContractError("temporal assessment authority must remain advisory")
        if self.schema_version != TEMPORAL_ASSESSMENT_SCHEMA:
            raise MonitoringContractError("unsupported temporal assessment schema")
        return self

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "assessment_id": self.assessment_id,
            "authority": self.authority,
            "bucket_indices": list(self.bucket_indices),
            "event_ids": list(self.event_ids),
            "evidence_refs": list(self.evidence_refs),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "scenario_fingerprint": self.scenario_fingerprint,
            "scenario_id": self.scenario_id,
            "schema_version": self.schema_version,
            "scope_entity_ref": self.scope_entity_ref,
            "scope_role": self.scope_role,
            "severity": self.severity,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


def _matching_indices(indices: Iterable[int], *, minimum: int, consecutive: bool) -> tuple[int, ...]:
    ordered = tuple(sorted(set(indices)))
    if len(ordered) < minimum:
        return ()
    if not consecutive:
        return ordered[:minimum]
    for start in range(0, len(ordered) - minimum + 1):
        candidate = ordered[start : start + minimum]
        if all(right == left + 1 for left, right in zip(candidate, candidate[1:])):
            return candidate
    return ()


class DeterministicTemporalScenarioEngine:
    """Evaluate bounded temporal scenarios over normalized metadata only; never performs response actions."""

    def __init__(
        self,
        scenarios: Iterable[TemporalScenario],
        *,
        bucket_config: TemporalBucketConfig | None = None,
        max_assessments: int = 2000,
        max_events_per_assessment: int = 256,
    ) -> None:
        validated = tuple(sorted((item.validate() for item in scenarios), key=lambda item: item.scenario_id))
        ids = tuple(item.scenario_id for item in validated)
        if len(ids) != len(set(ids)):
            raise MonitoringContractError("duplicate temporal scenario_id")
        if not validated:
            raise MonitoringContractError("at least one temporal scenario is required")
        self.scenarios = validated
        self.bucket_config = (bucket_config or TemporalBucketConfig()).validate()
        self.bucketizer = DeterministicTemporalBucketizer(self.bucket_config)
        self.max_assessments = _bounded_int(max_assessments, "max_assessments", minimum=1, maximum=10000)
        self.max_events_per_assessment = _bounded_int(
            max_events_per_assessment,
            "max_events_per_assessment",
            minimum=1,
            maximum=256,
        )

    def evaluate(
        self,
        *,
        window: TemporalAnalysisWindow,
        events: Iterable[CorrelationEvent],
    ) -> tuple[TemporalScenarioAssessment, ...]:
        materialized: list[CorrelationEvent] = []
        for raw in events:
            materialized.append(raw.validate())
            if len(materialized) > self.bucket_config.max_events:
                raise MonitoringContractError("temporal scenario event bound exceeded")

        buckets = self.bucketizer.bucketize(window=window, events=materialized)
        event_by_id: dict[str, CorrelationEvent] = {}
        for item in materialized:
            event_by_id[item.event.event_id] = item

        results: list[TemporalScenarioAssessment] = []
        for scenario in self.scenarios:
            qualified: dict[str, dict[int, tuple[str, ...]]] = {}
            for bucket in buckets:
                scoped: dict[str, list[str]] = {}
                for event_id in bucket.event_ids:
                    item = event_by_id[event_id]
                    if item.stage != scenario.stage:
                        continue
                    for scope_ref in item.context.refs_for_role(scenario.scope_role):
                        scoped.setdefault(scope_ref, []).append(event_id)
                for scope_ref, event_ids in scoped.items():
                    unique_ids = tuple(sorted(set(event_ids)))
                    if len(unique_ids) >= scenario.min_events_per_bucket:
                        qualified.setdefault(scope_ref, {})[bucket.bucket_index] = unique_ids

            for scope_ref in sorted(qualified):
                selected_indices = _matching_indices(
                    qualified[scope_ref],
                    minimum=scenario.min_matching_buckets,
                    consecutive=scenario.require_consecutive,
                )
                if not selected_indices:
                    continue
                selected_ids = tuple(
                    sorted(
                        {
                            event_id
                            for index in selected_indices
                            for event_id in qualified[scope_ref][index]
                        }
                    )
                )
                if len(selected_ids) > self.max_events_per_assessment:
                    raise MonitoringContractError("temporal assessment event bound exceeded")
                selected_events = tuple(event_by_id[event_id] for event_id in selected_ids)
                if any(item.event.evidence_ref is None for item in selected_events):
                    raise MonitoringContractError("temporal signal requires durable evidence_ref for every event")
                evidence_refs = tuple(sorted({item.event.evidence_ref for item in selected_events if item.event.evidence_ref}))
                observed = tuple(_canonical_utc(item.event.observed_at, "observed_at") for item in selected_events)
                identity = {
                    "scenario_fingerprint": scenario.fingerprint,
                    "scope_role": scenario.scope_role,
                    "scope_entity_ref": scope_ref,
                    "bucket_indices": list(selected_indices),
                    "event_ids": list(selected_ids),
                    "evidence_refs": list(evidence_refs),
                }
                assessment_id = "temporal-" + sha256_fingerprint(identity).split(":", 1)[1][:24]
                results.append(
                    TemporalScenarioAssessment(
                        assessment_id=assessment_id,
                        scenario_id=scenario.scenario_id,
                        scope_role=scenario.scope_role,
                        scope_entity_ref=scope_ref,
                        bucket_indices=selected_indices,
                        event_ids=selected_ids,
                        evidence_refs=evidence_refs,
                        first_seen=min(observed),
                        last_seen=max(observed),
                        severity=scenario.severity,
                        scenario_fingerprint=scenario.fingerprint,
                    ).validate()
                )
                if len(results) > self.max_assessments:
                    raise MonitoringContractError("temporal assessment bound exceeded")

        return tuple(sorted(results, key=lambda item: (item.scenario_id, item.scope_entity_ref, item.assessment_id)))
