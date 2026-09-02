from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .contracts import MonitoringContractError

ENTERPRISE_TRUTH_STATES = ("VERIFIED FACT", "INFERENCE", "UNKNOWN")
MAX_ENTERPRISE_STATEMENT_CHARS = 2000
MAX_ENTERPRISE_EVIDENCE_REFS = 8
MAX_ENTERPRISE_EVIDENCE_REF_CHARS = 256


@dataclass(frozen=True)
class EnterpriseFinding:
    """Evidence-bounded enterprise truth-state contract.

    This contract classifies analyst statements only. It carries no tool,
    remediation, command, policy-mutation, or execution authority.
    """

    truth_state: str
    statement: str
    evidence_ids: tuple[str, ...] = ()

    def validate(self, *, allowed_evidence_ids: Iterable[str]) -> "EnterpriseFinding":
        if self.truth_state not in ENTERPRISE_TRUTH_STATES:
            raise MonitoringContractError("unsupported enterprise truth state")
        if not isinstance(self.statement, str) or not self.statement.strip():
            raise MonitoringContractError("enterprise finding statement must be non-empty")
        if len(self.statement) > MAX_ENTERPRISE_STATEMENT_CHARS:
            raise MonitoringContractError("enterprise finding statement exceeds bounds")
        if not isinstance(self.evidence_ids, tuple):
            raise MonitoringContractError("enterprise finding evidence_ids must be a tuple")
        if len(self.evidence_ids) > MAX_ENTERPRISE_EVIDENCE_REFS:
            raise MonitoringContractError("enterprise finding evidence references exceed bounds")

        allowed = set(allowed_evidence_ids)
        for evidence_id in self.evidence_ids:
            if (
                not isinstance(evidence_id, str)
                or not evidence_id
                or len(evidence_id) > MAX_ENTERPRISE_EVIDENCE_REF_CHARS
            ):
                raise MonitoringContractError("enterprise finding evidence reference is invalid")
            if evidence_id not in allowed:
                raise MonitoringContractError("enterprise finding evidence reference is unknown")

        if self.truth_state == "VERIFIED FACT" and not self.evidence_ids:
            raise MonitoringContractError("VERIFIED FACT requires evidence")
        return self

    def public_dict(self) -> dict[str, object]:
        return {
            "truth_state": self.truth_state,
            "statement": self.statement,
            "evidence_ids": list(self.evidence_ids),
        }
