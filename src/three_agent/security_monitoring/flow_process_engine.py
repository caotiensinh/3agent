from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from .contracts import MonitoringContractError, canonical_json, sha256_fingerprint
from .flow_process_attribution import FlowTupleEvidence, SocketProcessObservation

FLOW_PROCESS_ASSESSMENT_SCHEMA = "workspace-security-monitoring/flow-process-attribution-v1"
FLOW_PROCESS_STATUSES = {"attributed", "ambiguous", "unmatched"}


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _delta_microseconds(left: datetime, right: datetime) -> int:
    delta = left - right
    if delta.days < 0:
        delta = -delta
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


@dataclass(frozen=True)
class FlowProcessAttributionConfig:
    max_time_skew_seconds: int = 5
    max_flows: int = 2000
    max_socket_observations: int = 10000
    max_assessments: int = 2000

    def validate(self) -> "FlowProcessAttributionConfig":
        for field_name, value, minimum, maximum in (
            ("max_time_skew_seconds", self.max_time_skew_seconds, 0, 300),
            ("max_flows", self.max_flows, 1, 10000),
            ("max_socket_observations", self.max_socket_observations, 1, 50000),
            ("max_assessments", self.max_assessments, 1, 10000),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise MonitoringContractError(
                    f"{field_name} must be an integer within {minimum}..{maximum}"
                )
        if self.max_assessments < self.max_flows:
            raise MonitoringContractError("max_assessments cannot be smaller than max_flows")
        return self

    @property
    def fingerprint(self) -> str:
        self.validate()
        return sha256_fingerprint(
            {
                "max_assessments": self.max_assessments,
                "max_flows": self.max_flows,
                "max_socket_observations": self.max_socket_observations,
                "max_time_skew_seconds": self.max_time_skew_seconds,
            }
        )


@dataclass(frozen=True)
class FlowProcessAttributionAssessment:
    attribution_id: str
    flow_event_id: str
    status: str
    flow_fingerprint: str
    flow_evidence_ref: str
    candidate_identity_count: int
    asset_refs: tuple[str, ...]
    process_refs: tuple[str, ...]
    user_refs: tuple[str, ...]
    socket_evidence_refs: tuple[str, ...]
    match_directions: tuple[str, ...]
    closest_delta_microseconds: int | None
    config_fingerprint: str
    authority: str = "advisory"
    schema_version: str = FLOW_PROCESS_ASSESSMENT_SCHEMA

    def validate(self) -> "FlowProcessAttributionAssessment":
        if self.status not in FLOW_PROCESS_STATUSES:
            raise MonitoringContractError("unsupported flow process attribution status")
        if not self.flow_event_id or len(self.flow_event_id) > 128:
            raise MonitoringContractError("flow_event_id is invalid")
        if not self.flow_fingerprint.startswith("sha256:") or len(self.flow_fingerprint) != 71:
            raise MonitoringContractError("flow_fingerprint must be a sha256 digest")
        if not self.flow_evidence_ref or len(self.flow_evidence_ref) > 256:
            raise MonitoringContractError("flow_evidence_ref is invalid")
        if (
            isinstance(self.candidate_identity_count, bool)
            or not isinstance(self.candidate_identity_count, int)
            or not 0 <= self.candidate_identity_count <= 64
        ):
            raise MonitoringContractError("candidate_identity_count must be within 0..64")
        if len(self.asset_refs) > 64 or len(self.process_refs) > 64 or len(self.user_refs) > 64:
            raise MonitoringContractError("flow process identity reference bound exceeded")
        if len(self.socket_evidence_refs) > 256:
            raise MonitoringContractError("flow process socket evidence bound exceeded")
        if tuple(sorted(set(self.asset_refs))) != self.asset_refs:
            raise MonitoringContractError("asset_refs must be sorted and unique")
        if tuple(sorted(set(self.process_refs))) != self.process_refs:
            raise MonitoringContractError("process_refs must be sorted and unique")
        if tuple(sorted(set(self.user_refs))) != self.user_refs:
            raise MonitoringContractError("user_refs must be sorted and unique")
        if tuple(sorted(set(self.socket_evidence_refs))) != self.socket_evidence_refs:
            raise MonitoringContractError("socket_evidence_refs must be sorted and unique")
        if tuple(sorted(set(self.match_directions))) != self.match_directions:
            raise MonitoringContractError("match_directions must be sorted and unique")
        if any(value not in {"direct", "reverse"} for value in self.match_directions):
            raise MonitoringContractError("unsupported flow process match direction")
        if self.closest_delta_microseconds is not None:
            if (
                isinstance(self.closest_delta_microseconds, bool)
                or not isinstance(self.closest_delta_microseconds, int)
                or self.closest_delta_microseconds < 0
            ):
                raise MonitoringContractError("closest_delta_microseconds is invalid")
        if not self.config_fingerprint.startswith("sha256:") or len(self.config_fingerprint) != 71:
            raise MonitoringContractError("config_fingerprint must be a sha256 digest")
        if self.authority != "advisory":
            raise MonitoringContractError("flow process attribution must remain advisory")
        if self.schema_version != FLOW_PROCESS_ASSESSMENT_SCHEMA:
            raise MonitoringContractError("unsupported flow process attribution schema")

        if self.status == "unmatched":
            if self.candidate_identity_count != 0:
                raise MonitoringContractError("unmatched attribution must have zero candidate identities")
            if any((self.asset_refs, self.process_refs, self.user_refs, self.socket_evidence_refs, self.match_directions)):
                raise MonitoringContractError("unmatched attribution cannot contain socket identities")
            if self.closest_delta_microseconds is not None:
                raise MonitoringContractError("unmatched attribution cannot contain a time delta")
        elif self.status == "attributed":
            if self.candidate_identity_count != 1:
                raise MonitoringContractError("attributed flow requires exactly one candidate identity")
            if len(self.asset_refs) != 1 or len(self.process_refs) != 1:
                raise MonitoringContractError("attributed flow requires exactly one asset and process")
            if not self.socket_evidence_refs or not self.match_directions:
                raise MonitoringContractError("attributed flow requires socket evidence and direction")
            if self.closest_delta_microseconds is None:
                raise MonitoringContractError("attributed flow requires a time delta")
        else:
            if self.candidate_identity_count < 2:
                raise MonitoringContractError("ambiguous attribution requires multiple candidate identities")
            if not self.asset_refs or not self.process_refs:
                raise MonitoringContractError("ambiguous flow requires asset/process identities")
            if not self.socket_evidence_refs or not self.match_directions:
                raise MonitoringContractError("ambiguous flow requires socket evidence and direction")
            if self.closest_delta_microseconds is None:
                raise MonitoringContractError("ambiguous flow requires a time delta")

        expected = "flowproc-" + sha256_fingerprint(self._identity_payload()).split(":", 1)[1][:24]
        if self.attribution_id != expected:
            raise MonitoringContractError("attribution_id must derive from assessment content")
        return self

    def _identity_payload(self) -> dict[str, object]:
        return {
            "asset_refs": list(self.asset_refs),
            "authority": self.authority,
            "candidate_identity_count": self.candidate_identity_count,
            "closest_delta_microseconds": self.closest_delta_microseconds,
            "config_fingerprint": self.config_fingerprint,
            "flow_event_id": self.flow_event_id,
            "flow_fingerprint": self.flow_fingerprint,
            "flow_evidence_ref": self.flow_evidence_ref,
            "match_directions": list(self.match_directions),
            "process_refs": list(self.process_refs),
            "schema_version": self.schema_version,
            "socket_evidence_refs": list(self.socket_evidence_refs),
            "status": self.status,
            "user_refs": list(self.user_refs),
        }

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {"attribution_id": self.attribution_id, **self._identity_payload()}

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


@dataclass(frozen=True)
class _MatchedSocket:
    observation: SocketProcessObservation
    direction: str
    delta_microseconds: int


class DeterministicFlowProcessAttributor:
    """Pure exact tuple/time correlator; ambiguous evidence is never guessed."""

    def __init__(self, config: FlowProcessAttributionConfig | None = None) -> None:
        self.config = (config or FlowProcessAttributionConfig()).validate()

    @staticmethod
    def _flow_identity(flow: FlowTupleEvidence) -> tuple[object, ...]:
        flow.validate()
        return (
            flow.event_id,
            flow.observed_at,
            flow.source_endpoint_ref,
            flow.destination_endpoint_ref,
            flow.evidence_ref,
            flow.authority,
            flow.schema_version,
        )

    @staticmethod
    def _socket_identity(item: SocketProcessObservation) -> tuple[object, ...]:
        item.validate()
        return (
            item.asset_ref,
            item.observed_at,
            item.local_endpoint_ref,
            item.remote_endpoint_ref,
            item.process_ref,
            item.user_ref,
            item.evidence_ref,
            item.authority,
            item.schema_version,
        )

    def _dedupe_flows(self, flows: Iterable[FlowTupleEvidence]) -> tuple[FlowTupleEvidence, ...]:
        unique: dict[str, FlowTupleEvidence] = {}
        for raw in flows:
            item = raw.validate()
            previous = unique.get(item.event_id)
            if previous is not None:
                if self._flow_identity(previous) != self._flow_identity(item):
                    raise MonitoringContractError("duplicate flow event_id has conflicting tuple evidence")
                continue
            unique[item.event_id] = item
            if len(unique) > self.config.max_flows:
                raise MonitoringContractError("flow process flow bound exceeded")
        return tuple(sorted(unique.values(), key=lambda item: (_dt(item.observed_at), item.event_id)))

    def _dedupe_sockets(
        self, observations: Iterable[SocketProcessObservation]
    ) -> tuple[SocketProcessObservation, ...]:
        by_evidence: dict[str, SocketProcessObservation] = {}
        by_fingerprint: dict[str, SocketProcessObservation] = {}
        count = 0
        for raw in observations:
            item = raw.validate()
            count += 1
            if count > self.config.max_socket_observations:
                raise MonitoringContractError("flow process socket observation bound exceeded")
            existing_evidence = by_evidence.get(item.evidence_ref)
            if existing_evidence is not None and self._socket_identity(existing_evidence) != self._socket_identity(item):
                raise MonitoringContractError("socket evidence_ref has conflicting observation content")
            by_evidence[item.evidence_ref] = item
            by_fingerprint[item.fingerprint] = item
        return tuple(
            sorted(
                by_fingerprint.values(),
                key=lambda item: (_dt(item.observed_at), item.asset_ref, item.process_ref, item.evidence_ref),
            )
        )

    def _matches(
        self,
        flow: FlowTupleEvidence,
        sockets: tuple[SocketProcessObservation, ...],
    ) -> tuple[_MatchedSocket, ...]:
        flow_time = _dt(flow.observed_at)
        max_delta = self.config.max_time_skew_seconds * 1_000_000
        matches: list[_MatchedSocket] = []
        for item in sockets:
            if item.protocol != flow.protocol:
                continue
            direction = None
            if (
                item.local_endpoint_ref == flow.source_endpoint_ref
                and item.remote_endpoint_ref == flow.destination_endpoint_ref
            ):
                direction = "direct"
            elif (
                item.local_endpoint_ref == flow.destination_endpoint_ref
                and item.remote_endpoint_ref == flow.source_endpoint_ref
            ):
                direction = "reverse"
            if direction is None:
                continue
            delta = _delta_microseconds(_dt(item.observed_at), flow_time)
            if delta <= max_delta:
                matches.append(_MatchedSocket(item, direction, delta))
        return tuple(matches)

    def _assessment(
        self,
        flow: FlowTupleEvidence,
        matches: tuple[_MatchedSocket, ...],
    ) -> FlowProcessAttributionAssessment:
        if not matches:
            payload = dict(
                flow_event_id=flow.event_id,
                status="unmatched",
                flow_fingerprint=flow.fingerprint,
                flow_evidence_ref=flow.evidence_ref,
                candidate_identity_count=0,
                asset_refs=(),
                process_refs=(),
                user_refs=(),
                socket_evidence_refs=(),
                match_directions=(),
                closest_delta_microseconds=None,
                config_fingerprint=self.config.fingerprint,
            )
        else:
            identities = {
                (match.observation.asset_ref, match.observation.process_ref, match.observation.user_ref)
                for match in matches
            }
            status = "attributed" if len(identities) == 1 else "ambiguous"
            payload = dict(
                flow_event_id=flow.event_id,
                status=status,
                flow_fingerprint=flow.fingerprint,
                flow_evidence_ref=flow.evidence_ref,
                candidate_identity_count=len(identities),
                asset_refs=tuple(sorted({value[0] for value in identities})),
                process_refs=tuple(sorted({value[1] for value in identities})),
                user_refs=tuple(sorted({value[2] for value in identities if value[2] is not None})),
                socket_evidence_refs=tuple(sorted({match.observation.evidence_ref for match in matches})),
                match_directions=tuple(sorted({match.direction for match in matches})),
                closest_delta_microseconds=min(match.delta_microseconds for match in matches),
                config_fingerprint=self.config.fingerprint,
            )
        identity = {
            **payload,
            "authority": "advisory",
            "schema_version": FLOW_PROCESS_ASSESSMENT_SCHEMA,
        }
        attribution_id = "flowproc-" + sha256_fingerprint(identity).split(":", 1)[1][:24]
        return FlowProcessAttributionAssessment(attribution_id=attribution_id, **payload).validate()

    def attribute(
        self,
        *,
        flows: Iterable[FlowTupleEvidence],
        socket_observations: Iterable[SocketProcessObservation],
    ) -> tuple[FlowProcessAttributionAssessment, ...]:
        flow_items = self._dedupe_flows(flows)
        socket_items = self._dedupe_sockets(socket_observations)
        if len(flow_items) > self.config.max_assessments:
            raise MonitoringContractError("flow process assessment bound exceeded")
        return tuple(self._assessment(flow, self._matches(flow, socket_items)) for flow in flow_items)
