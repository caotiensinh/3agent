from __future__ import annotations

from typing import Iterable

from .contracts import APPROVED_DATA_CLASSES, MonitoringContractError, canonical_json
from .forensic_evidence import DerivedEvidence, EvidenceObject, EvidenceProvenance
from .incident_timeline import IncidentTimeline

INCIDENT_TIMELINE_EVIDENCE_ADAPTER_VERSION = "v0.13"
INCIDENT_TIMELINE_PRODUCER_VERSION = "incident-timeline-v0.10+adapter-v0.13"
INCIDENT_TIMELINE_DERIVATION_ID = "incident-timeline-evidence-v0.13"

_DATA_CLASS_RANK = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
    "secret": 4,
}


def _most_restrictive_data_class(evidence: Iterable[EvidenceObject]) -> str:
    values = tuple(item.data_class for item in evidence)
    if not values or any(value not in APPROVED_DATA_CLASSES for value in values):
        raise MonitoringContractError("timeline evidence requires valid source data classes")
    return max(values, key=lambda value: _DATA_CLASS_RANK[value])


def timeline_to_derived_evidence(
    timeline: IncidentTimeline,
    source_evidence: Iterable[EvidenceObject],
    *,
    produced_at: str,
) -> DerivedEvidence:
    """Bind an existing deterministic IncidentTimeline to canonical forensic evidence.

    This adapter does not build, extend or reinterpret the timeline. It only proves
    exact lineage from the timeline's evidence refs to already-validated canonical
    source evidence and emits one metadata-only DerivedEvidence object.
    """

    if not isinstance(timeline, IncidentTimeline):
        raise MonitoringContractError("timeline evidence adapter requires IncidentTimeline")
    timeline.validate()

    sources = tuple(source_evidence)
    if not sources:
        raise MonitoringContractError("timeline evidence adapter requires source evidence")
    by_id: dict[str, EvidenceObject] = {}
    for raw in sources:
        if not isinstance(raw, EvidenceObject):
            raise MonitoringContractError("timeline source evidence type is invalid")
        item = raw.validate()
        if item.evidence_id in by_id:
            raise MonitoringContractError("timeline source evidence IDs must be unique")
        by_id[item.evidence_id] = item

    expected_refs = tuple(sorted(timeline.evidence_refs))
    actual_refs = tuple(sorted(by_id))
    if actual_refs != expected_refs:
        missing = tuple(sorted(set(expected_refs) - set(actual_refs)))
        extra = tuple(sorted(set(actual_refs) - set(expected_refs)))
        raise MonitoringContractError(
            f"timeline source evidence must exactly match timeline evidence refs: missing={missing!r} extra={extra!r}"
        )

    ordered_sources = tuple(by_id[evidence_id] for evidence_id in expected_refs)
    input_refs = tuple(item.reference("derived_from") for item in ordered_sources)
    timeline_payload = canonical_json(timeline.public_dict()).encode("utf-8")
    timeline_fingerprint = timeline.fingerprint
    digest = timeline_fingerprint.split(":", 1)[1]
    parent_refs = tuple(item.evidence_id for item in ordered_sources)

    evidence = EvidenceObject(
        evidence_id=f"evidence:timeline-{digest[:24]}",
        evidence_type="timeline",
        content_sha256=timeline_fingerprint,
        byte_size=len(timeline_payload),
        data_class=_most_restrictive_data_class(ordered_sources),
        provenance=EvidenceProvenance(
            source_id=f"incident-timeline:{digest[:24]}",
            source_type="incident_timeline",
            collected_at=produced_at,
            producer_id="workspace-incident-timeline-evidence-adapter",
            producer_version=INCIDENT_TIMELINE_PRODUCER_VERSION,
            source_content_sha256=timeline_fingerprint,
            upstream_evidence_refs=parent_refs,
        ).validate(),
        event_time=None,
        parent_evidence_refs=parent_refs,
        derived=True,
        immutable=True,
        payload_embedded=False,
    ).validate()

    return DerivedEvidence(
        evidence=evidence,
        derivation_id=INCIDENT_TIMELINE_DERIVATION_ID,
        input_evidence_refs=input_refs,
        authority="advisory",
    ).validate()
