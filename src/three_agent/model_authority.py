from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .task_contract import TaskContract

_TIER_ORDER = {"none": 0, "small": 1, "specialist": 2, "strong": 3}


class ModelAuthorityDenied(RuntimeError):
    """A model-tier transition would exceed immutable TaskContract authority."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class TaskModelAuthority:
    """Immutable capability/model envelope projected from one TaskContract.

    The fingerprint covers source/tool/write/network/sensitivity and model-route
    authority. Only the fingerprint and compact tier metadata should be persisted;
    raw task/evidence content is not part of this object.
    """

    task_id: str
    sensitivity: str
    risk_level: str
    allowed_sources: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    write_scope: str | tuple[str, ...]
    network_scope: str
    initial_model_tier: str
    max_model_tier: str
    escalation_allowed: bool
    fingerprint: str

    @classmethod
    def from_contract(cls, contract: TaskContract) -> "TaskModelAuthority":
        contract.validate()
        write_scope: str | tuple[str, ...]
        if isinstance(contract.write_scope, tuple):
            write_scope = tuple(contract.write_scope)
        else:
            write_scope = str(contract.write_scope)
        payload = {
            "task_id": contract.task_id,
            "sensitivity": contract.sensitivity,
            "risk_level": contract.risk_level,
            "allowed_sources": list(contract.allowed_sources),
            "allowed_tools": list(contract.allowed_tools),
            "write_scope": list(write_scope) if isinstance(write_scope, tuple) else write_scope,
            "network_scope": contract.network_scope,
            "initial_model_tier": contract.model_policy.initial_tier,
            "max_model_tier": contract.model_policy.max_tier,
            "escalation_allowed": contract.model_policy.escalation_allowed,
        }
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return cls(
            task_id=contract.task_id,
            sensitivity=contract.sensitivity,
            risk_level=contract.risk_level,
            allowed_sources=tuple(contract.allowed_sources),
            allowed_tools=tuple(contract.allowed_tools),
            write_scope=write_scope,
            network_scope=contract.network_scope,
            initial_model_tier=contract.model_policy.initial_tier,
            max_model_tier=contract.model_policy.max_tier,
            escalation_allowed=contract.model_policy.escalation_allowed,
            fingerprint="sha256:" + hashlib.sha256(canonical).hexdigest(),
        )

    def permits_tier(self, target_tier: str) -> bool:
        target = str(target_tier).strip().lower()
        if target not in _TIER_ORDER:
            return False
        if _TIER_ORDER[target] > _TIER_ORDER[self.max_model_tier]:
            return False
        if (
            _TIER_ORDER[target] > _TIER_ORDER[self.initial_model_tier]
            and not self.escalation_allowed
        ):
            return False
        return True

    def require_tier(self, target_tier: str) -> None:
        target = str(target_tier).strip().lower()
        if target not in _TIER_ORDER:
            raise ModelAuthorityDenied("MODEL_TIER_UNKNOWN")
        if _TIER_ORDER[target] > _TIER_ORDER[self.max_model_tier]:
            raise ModelAuthorityDenied("MODEL_TIER_EXCEEDS_CONTRACT_MAX")
        if (
            _TIER_ORDER[target] > _TIER_ORDER[self.initial_model_tier]
            and not self.escalation_allowed
        ):
            raise ModelAuthorityDenied("MODEL_ESCALATION_NOT_AUTHORIZED")

    def metadata(self) -> dict[str, str | bool]:
        return {
            "schema_version": "workspace-task-model-authority/v1",
            "task_id": self.task_id,
            "authority_fingerprint": self.fingerprint,
            "initial_model_tier": self.initial_model_tier,
            "max_model_tier": self.max_model_tier,
            "escalation_allowed": self.escalation_allowed,
        }
