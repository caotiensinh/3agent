from __future__ import annotations

from dataclasses import dataclass, replace

from .contracts import CanonicalEvent, MonitoringContractError, ObservationRecord, sha256_fingerprint
from .entity_context import EventEntityContext, EventEntityReference

OBSERVATION_NORMALIZER_VERSION = "workspace-observation-normalizer/v1"
_INTERFACE_SUFFIXES = (
    "rx_bytes",
    "rx_packets",
    "rx_errors",
    "rx_dropped",
    "tx_bytes",
    "tx_packets",
    "tx_errors",
    "tx_dropped",
    "rx_discards",
    "tx_discards",
    "speed_bps",
)


@dataclass(frozen=True)
class NormalizedObservationEvidence:
    observation: ObservationRecord
    event: CanonicalEvent
    entity_context: EventEntityContext
    schema_version: str = "workspace-security-monitoring/normalized-observation-evidence-v1"

    def validate(self) -> "NormalizedObservationEvidence":
        self.observation.validate()
        self.event.validate()
        self.entity_context.validate()
        if self.event.event_id != self.entity_context.event_id:
            raise MonitoringContractError("normalized observation event/context id mismatch")
        if self.observation.evidence_ref != self.event.evidence_ref:
            raise MonitoringContractError("normalized observation evidence_ref mismatch")
        if not self.entity_context.refs_for_role("asset"):
            raise MonitoringContractError("normalized observation requires approved asset entity")
        return self


def _interface_from_metric(metric: str) -> str | None:
    text = str(metric)
    if not text.startswith("if_"):
        return None
    for suffix in _INTERFACE_SUFFIXES:
        marker = "_" + suffix
        if text.endswith(marker):
            interface = text[3 : -len(marker)]
            if interface:
                return interface
    return None


def normalize_observation_evidence(observation: ObservationRecord) -> NormalizedObservationEvidence:
    """Convert one bounded collector observation into correlation-safe evidence.

    Raw credential references and collector backend state are outside this contract.
    Interface names become typed hashes; approved inventory asset IDs remain explicit.
    """

    observation.validate()
    identity = {
        "run_id": observation.run_id,
        "asset_id": observation.asset_id,
        "collector": observation.collector,
        "observed_at": observation.observed_at,
        "metric": observation.metric,
        "status": observation.status,
        "value": observation.value,
        "unit": observation.unit,
    }
    digest = sha256_fingerprint(identity)
    evidence_ref = "observation:" + digest.removeprefix("sha256:")[:32]
    normalized_observation = replace(observation, evidence_ref=evidence_ref).validate()

    event = CanonicalEvent(
        event_id="evt-" + digest.removeprefix("sha256:")[:24],
        source_id=observation.asset_id,
        source_type="monitoring_observation",
        observed_at=observation.observed_at,
        category="monitoring." + observation.collector,
        severity="info",
        message_sha256=digest,
        parser_version=OBSERVATION_NORMALIZER_VERSION,
        evidence_ref=evidence_ref,
    ).validate()

    references = [
        EventEntityReference.approved_asset(role="asset", asset_id=observation.asset_id),
    ]
    interface = _interface_from_metric(observation.metric)
    if interface is not None:
        references.append(
            EventEntityReference.opaque(kind="interface", role="interface", value=interface)
        )
    context = EventEntityContext(event_id=event.event_id, references=tuple(references)).validate()
    return NormalizedObservationEvidence(
        observation=normalized_observation,
        event=event,
        entity_context=context,
    ).validate()
