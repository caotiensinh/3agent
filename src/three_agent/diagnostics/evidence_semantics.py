from __future__ import annotations

from dataclasses import dataclass

from .backup_status_tools import BACKUP_STATUS_TOOL_ID
from .cloud_files_tools import CLOUD_FILES_STATUS_TOOL_ID
from .identity_account_state_tools import IDENTITY_ACCOUNT_STATE_TOOL_ID
from .mail_exchange_tools import MAIL_EXCHANGE_STATUS_TOOL_ID
from .voip_tools import VOIP_CLIENT_STATE_TOOL_ID

EVIDENCE_SEMANTICS_SCHEMA = "workspace-diagnostic-evidence-semantics/v1"


@dataclass(frozen=True)
class EvidenceSemanticDescriptor:
    """Planning metadata that separates an evidence primitive from route capability claims."""

    tool_id: str
    evidence_kind: str
    prohibited_claims: tuple[str, ...]
    satisfied_capability_tags: tuple[str, ...] = ()
    local_only: bool = True
    execution_enabled: bool = False
    selection_authority: str = "none"
    schema_version: str = EVIDENCE_SEMANTICS_SCHEMA

    def validate(self) -> "EvidenceSemanticDescriptor":
        if self.schema_version != EVIDENCE_SEMANTICS_SCHEMA:
            raise ValueError(f"unsupported evidence semantics schema: {self.schema_version}")
        if not self.tool_id.strip() or not self.evidence_kind.strip():
            raise ValueError("tool_id and evidence_kind are required")
        if not self.prohibited_claims:
            raise ValueError("prohibited_claims is required")
        if tuple(sorted(set(self.prohibited_claims))) != self.prohibited_claims:
            raise ValueError("prohibited_claims must be unique and sorted")
        if tuple(sorted(set(self.satisfied_capability_tags))) != self.satisfied_capability_tags:
            raise ValueError("satisfied_capability_tags must be unique and sorted")
        if self.local_only is not True:
            raise ValueError("wave1 evidence semantics must remain local-only")
        if self.execution_enabled is not False:
            raise ValueError("evidence descriptors cannot enable execution")
        if self.selection_authority != "none":
            raise ValueError("evidence descriptors cannot grant selection authority")
        return self


WAVE1_EVIDENCE_DESCRIPTORS = (
    EvidenceSemanticDescriptor(
        tool_id=CLOUD_FILES_STATUS_TOOL_ID,
        evidence_kind="local_cloud_sync_client_process_state",
        prohibited_claims=(
            "authentication_validity",
            "provider_health",
            "root_cause",
            "sync_success",
        ),
    ).validate(),
    EvidenceSemanticDescriptor(
        tool_id=MAIL_EXCHANGE_STATUS_TOOL_ID,
        evidence_kind="local_mail_client_process_state",
        prohibited_claims=(
            "authentication_validity",
            "mail_delivery_health",
            "remote_exchange_health",
            "root_cause",
        ),
    ).validate(),
    EvidenceSemanticDescriptor(
        tool_id=VOIP_CLIENT_STATE_TOOL_ID,
        evidence_kind="local_voip_client_process_state",
        prohibited_claims=(
            "call_path_health",
            "media_health",
            "remote_pbx_health",
            "root_cause",
            "sip_registration",
        ),
    ).validate(),
    EvidenceSemanticDescriptor(
        tool_id=IDENTITY_ACCOUNT_STATE_TOOL_ID,
        evidence_kind="local_identity_account_state",
        prohibited_claims=(
            "authentication_validity",
            "directory_health",
            "remote_lockout_state",
            "root_cause",
        ),
    ).validate(),
    EvidenceSemanticDescriptor(
        tool_id=BACKUP_STATUS_TOOL_ID,
        evidence_kind="local_backup_component_state",
        prohibited_claims=(
            "backup_freshness",
            "backup_success",
            "remote_destination_health",
            "restore_viability",
            "root_cause",
        ),
    ).validate(),
)

_DESCRIPTOR_BY_TOOL_ID = {item.tool_id: item for item in WAVE1_EVIDENCE_DESCRIPTORS}
if len(_DESCRIPTOR_BY_TOOL_ID) != len(WAVE1_EVIDENCE_DESCRIPTORS):
    raise RuntimeError("duplicate wave1 evidence semantic tool id")


def evidence_semantic_descriptor(tool_id: str) -> EvidenceSemanticDescriptor:
    try:
        return _DESCRIPTOR_BY_TOOL_ID[str(tool_id)]
    except KeyError as exc:
        raise KeyError(f"unknown evidence semantic tool id: {tool_id}") from exc


__all__ = [
    "EVIDENCE_SEMANTICS_SCHEMA",
    "EvidenceSemanticDescriptor",
    "WAVE1_EVIDENCE_DESCRIPTORS",
    "evidence_semantic_descriptor",
]
