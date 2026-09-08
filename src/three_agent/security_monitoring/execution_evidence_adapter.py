from __future__ import annotations

from three_agent.execution_observation import ExecutionEvidenceBinding
from three_agent.execution_plan import ExecutionPlan

from .normalized_evidence import NormalizedEvidence, NormalizedEvidenceError


class ExecutionEvidenceAdapterError(ValueError):
    """Security evidence cannot be safely attached to a runtime execution node."""


def bind_normalized_evidence(
    *,
    plan: ExecutionPlan,
    node_id: str,
    evidence: NormalizedEvidence,
    requirement: str | None = None,
) -> ExecutionEvidenceBinding:
    """Bind an existing security-domain evidence record to one exact runtime node.

    The adapter does not copy evidence payloads into the runtime observation. It checks
    the existing task and authorization fingerprints and returns only the stable
    evidence reference plus canonical evidence identity.
    """

    if not isinstance(plan, ExecutionPlan):
        raise ExecutionEvidenceAdapterError("INVALID_EXECUTION_PLAN")
    plan.validate()
    node = next((row for row in plan.nodes if row.node_id == node_id), None)
    if node is None:
        raise ExecutionEvidenceAdapterError(f"UNKNOWN_EXECUTION_NODE:{node_id}")
    if not isinstance(evidence, NormalizedEvidence):
        raise ExecutionEvidenceAdapterError("INVALID_NORMALIZED_EVIDENCE")
    try:
        evidence.validate()
    except NormalizedEvidenceError as exc:
        raise ExecutionEvidenceAdapterError("NORMALIZED_EVIDENCE_VALIDATION_FAILED") from exc

    if evidence.task_ref_sha256 != plan.task_context_identity_fingerprint:
        raise ExecutionEvidenceAdapterError("EVIDENCE_TASK_CONTEXT_MISMATCH")
    if evidence.authorization_ref_sha256 != node.authority_fingerprint:
        raise ExecutionEvidenceAdapterError("EVIDENCE_AUTHORITY_MISMATCH")

    binding = ExecutionEvidenceBinding(
        requirement=requirement,
        evidence_ref=evidence.evidence_id,
        evidence_fingerprint=evidence.identity_sha256,
    )
    binding.validate()
    return binding
