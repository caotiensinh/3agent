from __future__ import annotations

from typing import TYPE_CHECKING

from .contracts import CanonicalEvent, MonitoringContractError, sha256_fingerprint
from .entity_context import EventEntityContext, EventEntityReference
from .flow_process_attribution import FlowTupleEvidence
from .flow_process_engine import FlowProcessAttributionAssessment

if TYPE_CHECKING:
    from .correlation_graph import CorrelationEvent

# Reuse the PROCESS event dialect already understood by the incident graph.
# Provenance remains explicit through source_id and parser_version below.
FLOW_PROCESS_GRAPH_SOURCE_TYPE = "workspace_audit"
FLOW_PROCESS_GRAPH_CATEGORY = "workspace_audit.process_start"
FLOW_PROCESS_GRAPH_SOURCE_ID = "flow-process-attribution"
FLOW_PROCESS_GRAPH_PARSER_VERSION = "flow-process-graph-bridge/v1"


def _event_id(*, flow: FlowTupleEvidence, assessment: FlowProcessAttributionAssessment) -> str:
    identity = {
        "assessment_fingerprint": assessment.fingerprint,
        "flow_fingerprint": flow.fingerprint,
        "schema": FLOW_PROCESS_GRAPH_PARSER_VERSION,
    }
    return "flowproc-event-" + sha256_fingerprint(identity).split(":", 1)[1][:24]


def attribution_to_correlation_event(
    *,
    flow: FlowTupleEvidence,
    assessment: FlowProcessAttributionAssessment,
) -> "CorrelationEvent | None":
    """Bridge exact flow/process attribution into the existing incident graph.

    The bridge is deterministic and side-effect free. Only an exact `attributed`
    assessment becomes PROCESS-stage evidence. Ambiguous or unmatched evidence
    intentionally emits no correlation event and therefore cannot create an
    identity edge by guesswork.
    """

    flow = flow.validate()
    assessment = assessment.validate()
    if assessment.flow_event_id != flow.event_id:
        raise MonitoringContractError("flow process assessment event_id does not bind supplied flow")
    if assessment.flow_fingerprint != flow.fingerprint:
        raise MonitoringContractError("flow process assessment fingerprint does not bind supplied flow")
    if assessment.flow_evidence_ref != flow.evidence_ref:
        raise MonitoringContractError("flow process assessment evidence_ref does not bind supplied flow")

    if assessment.status != "attributed":
        return None
    if assessment.candidate_identity_count != 1:
        raise MonitoringContractError("graph bridge requires exactly one attributed identity")
    if len(assessment.asset_refs) != 1 or len(assessment.process_refs) != 1:
        raise MonitoringContractError("graph bridge requires exactly one asset and process reference")
    if len(assessment.user_refs) > 1:
        raise MonitoringContractError("graph bridge refuses multiple user references for one identity")

    event_id = _event_id(flow=flow, assessment=assessment)
    event = CanonicalEvent(
        event_id=event_id,
        source_id=FLOW_PROCESS_GRAPH_SOURCE_ID,
        source_type=FLOW_PROCESS_GRAPH_SOURCE_TYPE,
        observed_at=flow.observed_at,
        category=FLOW_PROCESS_GRAPH_CATEGORY,
        severity="info",
        message_sha256=assessment.fingerprint,
        parser_version=FLOW_PROCESS_GRAPH_PARSER_VERSION,
        evidence_ref=assessment.attribution_id,
    ).validate()

    references = [
        EventEntityReference(
            kind="asset",
            role="asset",
            entity_ref=assessment.asset_refs[0],
        ).validate(),
        EventEntityReference(
            kind="process",
            role="process_image",
            entity_ref=assessment.process_refs[0],
        ).validate(),
    ]
    if assessment.user_refs:
        references.append(
            EventEntityReference(
                kind="user",
                role="auth_user",
                entity_ref=assessment.user_refs[0],
            ).validate()
        )

    context = EventEntityContext(event_id=event_id, references=tuple(references)).validate()

    from .correlation_graph import CorrelationEvent

    return CorrelationEvent(event=event, context=context).validate()
