from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..capability_authority import CAPABILITY_DECISION_SCHEMA, CapabilityDecision
from .contracts import sha256_fingerprint

DIAGNOSTIC_LINEAGE_SCHEMA = "workspace-diagnostic-evidence-lineage/v1"
DIAGNOSTIC_LINEAGE_NODE_SCHEMA = "workspace-diagnostic-lineage-node/v1"
LINEAGE_KINDS = (
    "task",
    "request",
    "capability_tool",
    "invocation_decision",
    "observation",
    "evidence",
)
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,255}$")


class DiagnosticLineageError(ValueError):
    """Diagnostic provenance is incomplete, conflicting, or unsafe to normalize."""


def _sha256(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise DiagnosticLineageError(f"INVALID_{field_name.upper()}")
    return value


def _reference(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise DiagnosticLineageError(f"INVALID_{field_name.upper()}")
    if len(value) > 256 or not _REF_RE.fullmatch(value) or "://" in value:
        raise DiagnosticLineageError(f"INVALID_{field_name.upper()}")
    if any(segment == ".." for segment in value.split("/")):
        raise DiagnosticLineageError(f"INVALID_{field_name.upper()}")
    return value


@dataclass(frozen=True)
class DiagnosticLineageNode:
    kind: str
    identity_sha256: str
    parent_sha256: str | None
    schema_version: str = DIAGNOSTIC_LINEAGE_NODE_SCHEMA

    def validate(self) -> "DiagnosticLineageNode":
        if self.schema_version != DIAGNOSTIC_LINEAGE_NODE_SCHEMA:
            raise DiagnosticLineageError("LINEAGE_NODE_SCHEMA_VERSION_MISMATCH")
        if self.kind not in LINEAGE_KINDS:
            raise DiagnosticLineageError("INVALID_LINEAGE_NODE_KIND")
        _sha256(self.identity_sha256, "identity_sha256")
        if self.parent_sha256 is not None:
            _sha256(self.parent_sha256, "parent_sha256")
        return self

    def canonical_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "identity_sha256": self.identity_sha256,
            "parent_sha256": self.parent_sha256,
        }


@dataclass(frozen=True)
class DiagnosticEvidenceLineage:
    task_id: str
    source_tool: str
    source_capability: str
    invocation_allowed: bool
    nodes: tuple[DiagnosticLineageNode, ...]
    provenance_status: str = "complete"
    trust_status: str = "unverified"
    authority: str = "advisory"
    automatic_action_allowed: bool = False
    schema_version: str = DIAGNOSTIC_LINEAGE_SCHEMA

    def validate(self) -> "DiagnosticEvidenceLineage":
        if self.schema_version != DIAGNOSTIC_LINEAGE_SCHEMA:
            raise DiagnosticLineageError("LINEAGE_SCHEMA_VERSION_MISMATCH")
        object.__setattr__(self, "task_id", _reference(self.task_id, "task_id"))
        object.__setattr__(self, "source_tool", _reference(self.source_tool, "source_tool"))
        object.__setattr__(
            self,
            "source_capability",
            _reference(self.source_capability, "source_capability"),
        )
        if not isinstance(self.invocation_allowed, bool) or not self.invocation_allowed:
            raise DiagnosticLineageError("LINEAGE_REQUIRES_ALLOWED_INVOCATION")
        if not isinstance(self.nodes, tuple) or len(self.nodes) != len(LINEAGE_KINDS):
            raise DiagnosticLineageError("LINEAGE_ORPHAN_OR_NODE_COUNT_MISMATCH")

        normalized = tuple(node.validate() for node in self.nodes)
        kinds = tuple(node.kind for node in normalized)
        if kinds != LINEAGE_KINDS:
            raise DiagnosticLineageError("LINEAGE_ORDER_OR_KIND_MISMATCH")
        if normalized[0].parent_sha256 is not None:
            raise DiagnosticLineageError("LINEAGE_TASK_NODE_CANNOT_HAVE_PARENT")
        for parent, child in zip(normalized, normalized[1:]):
            if child.parent_sha256 != parent.identity_sha256:
                raise DiagnosticLineageError("LINEAGE_PARENT_CHILD_MISMATCH")
        identities = tuple(node.identity_sha256 for node in normalized)
        if len(set(identities)) != len(identities):
            raise DiagnosticLineageError("LINEAGE_CONFLICTING_IDENTITIES")

        if self.provenance_status != "complete":
            raise DiagnosticLineageError("LINEAGE_PROVENANCE_INCOMPLETE")
        if self.trust_status != "unverified":
            raise DiagnosticLineageError("LINEAGE_CANNOT_SELF_ATTEST_TRUST")
        if not isinstance(self.automatic_action_allowed, bool):
            raise DiagnosticLineageError("INVALID_AUTOMATIC_ACTION_ALLOWED")
        if self.authority != "advisory" or self.automatic_action_allowed:
            raise DiagnosticLineageError("LINEAGE_CANNOT_GRANT_AUTHORITY")
        return self

    def canonical_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "source_tool": self.source_tool,
            "source_capability": self.source_capability,
            "invocation_allowed": self.invocation_allowed,
            "nodes": [node.canonical_dict() for node in self.nodes],
            "provenance_status": self.provenance_status,
            "trust_status": self.trust_status,
            "authority": self.authority,
            "automatic_action_allowed": self.automatic_action_allowed,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.canonical_dict())


def normalize_diagnostic_lineage(
    *,
    decision: CapabilityDecision,
    task_ref_sha256: str,
    request_ref_sha256: str,
    source_tool: str,
    observation_fingerprint: str,
    evidence_fingerprint: str,
) -> DiagnosticEvidenceLineage:
    """Build a deterministic, hash-only provenance chain for diagnostic evidence.

    The chain records provenance but deliberately does not convert provenance into
    trust or execution authority. Raw resource references and observation payloads
    are never copied into the lineage record.
    """

    if not isinstance(decision, CapabilityDecision):
        raise DiagnosticLineageError("INVALID_CAPABILITY_DECISION")
    if decision.schema_version != CAPABILITY_DECISION_SCHEMA:
        raise DiagnosticLineageError("CAPABILITY_DECISION_SCHEMA_VERSION_MISMATCH")
    if not isinstance(decision.allowed, bool) or not decision.allowed:
        raise DiagnosticLineageError("LINEAGE_REQUIRES_ALLOWED_INVOCATION")

    task_ref = _sha256(task_ref_sha256, "task_ref_sha256")
    request_ref = _sha256(request_ref_sha256, "request_ref_sha256")
    observation_ref = _sha256(observation_fingerprint, "observation_fingerprint")
    evidence_ref = _sha256(evidence_fingerprint, "evidence_fingerprint")
    tool = _reference(source_tool, "source_tool")
    capability = _reference(decision.capability, "source_capability")
    task_id = _reference(decision.task_id, "task_id")

    task_identity = sha256_fingerprint(
        {
            "kind": "task",
            "task_id": task_id,
            "task_ref_sha256": task_ref,
        }
    )
    request_identity = sha256_fingerprint(
        {
            "kind": "request",
            "request_ref_sha256": request_ref,
            "parent_sha256": task_identity,
        }
    )
    capability_identity = sha256_fingerprint(
        {
            "kind": "capability_tool",
            "source_tool": tool,
            "source_capability": capability,
            "parent_sha256": request_identity,
        }
    )
    invocation_identity = sha256_fingerprint(
        {
            "kind": "invocation_decision",
            "decision_metadata": decision.metadata(),
            "parent_sha256": capability_identity,
        }
    )
    observation_identity = sha256_fingerprint(
        {
            "kind": "observation",
            "observation_fingerprint": observation_ref,
            "parent_sha256": invocation_identity,
        }
    )
    evidence_identity = sha256_fingerprint(
        {
            "kind": "evidence",
            "evidence_fingerprint": evidence_ref,
            "parent_sha256": observation_identity,
        }
    )

    identities = (
        task_identity,
        request_identity,
        capability_identity,
        invocation_identity,
        observation_identity,
        evidence_identity,
    )
    parents: tuple[str | None, ...] = (None,) + identities[:-1]
    nodes = tuple(
        DiagnosticLineageNode(kind=kind, identity_sha256=identity, parent_sha256=parent)
        for kind, identity, parent in zip(LINEAGE_KINDS, identities, parents)
    )
    return DiagnosticEvidenceLineage(
        task_id=task_id,
        source_tool=tool,
        source_capability=capability,
        invocation_allowed=True,
        nodes=nodes,
    ).validate()
