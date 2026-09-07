from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable

from .capability_authority import TaskCapabilityAuthority
from .task_contract import TaskContract

_TIER_ORDER = {"none": 0, "small": 1, "specialist": 2, "strong": 3}
_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class ModelAuthorityDenied(RuntimeError):
    """A model-tier transition or delegation would exceed immutable authority."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))


@dataclass(frozen=True)
class TaskModelAuthority:
    """Immutable capability/model envelope projected from one TaskContract.

    The fingerprint covers source/tool/write/network/sensitivity and model-route
    authority. Delegated envelopes may retain or reduce that authority but may
    never widen it. Only compact metadata/fingerprints should be persisted.
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
    delegated_from: str | None = None

    @classmethod
    def _build(
        cls,
        *,
        task_id: str,
        sensitivity: str,
        risk_level: str,
        allowed_sources: tuple[str, ...],
        allowed_tools: tuple[str, ...],
        write_scope: str | tuple[str, ...],
        network_scope: str,
        initial_model_tier: str,
        max_model_tier: str,
        escalation_allowed: bool,
        delegated_from: str | None = None,
    ) -> "TaskModelAuthority":
        normalized_task = str(task_id).strip()
        normalized_sensitivity = str(sensitivity).strip().lower()
        normalized_risk = str(risk_level).strip().lower()
        normalized_initial = str(initial_model_tier).strip().lower()
        normalized_max = str(max_model_tier).strip().lower()
        normalized_network = str(network_scope).strip().lower()
        normalized_sources = _unique(allowed_sources)
        normalized_tools = _unique(allowed_tools)
        if not normalized_task or len(normalized_task) > 128 or any(ch.isspace() for ch in normalized_task):
            raise ModelAuthorityDenied("MODEL_AUTHORITY_TASK_ID_INVALID")
        if normalized_risk not in _RISK_ORDER:
            raise ModelAuthorityDenied("MODEL_AUTHORITY_RISK_INVALID")
        if normalized_initial not in _TIER_ORDER or normalized_max not in _TIER_ORDER:
            raise ModelAuthorityDenied("MODEL_TIER_UNKNOWN")
        if _TIER_ORDER[normalized_initial] > _TIER_ORDER[normalized_max]:
            raise ModelAuthorityDenied("MODEL_INITIAL_TIER_EXCEEDS_MAX")
        if normalized_initial == "none" and (normalized_max != "none" or escalation_allowed):
            raise ModelAuthorityDenied("NO_LLM_AUTHORITY_INVALID")

        payload = {
            "task_id": normalized_task,
            "sensitivity": normalized_sensitivity,
            "risk_level": normalized_risk,
            "allowed_sources": list(normalized_sources),
            "allowed_tools": list(normalized_tools),
            "write_scope": list(write_scope) if isinstance(write_scope, tuple) else write_scope,
            "network_scope": normalized_network,
            "initial_model_tier": normalized_initial,
            "max_model_tier": normalized_max,
            "escalation_allowed": bool(escalation_allowed),
        }
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return cls(
            task_id=normalized_task,
            sensitivity=normalized_sensitivity,
            risk_level=normalized_risk,
            allowed_sources=normalized_sources,
            allowed_tools=normalized_tools,
            write_scope=write_scope,
            network_scope=normalized_network,
            initial_model_tier=normalized_initial,
            max_model_tier=normalized_max,
            escalation_allowed=bool(escalation_allowed),
            fingerprint="sha256:" + hashlib.sha256(canonical).hexdigest(),
            delegated_from=delegated_from,
        )

    @classmethod
    def from_contract(cls, contract: TaskContract) -> "TaskModelAuthority":
        contract.validate()
        write_scope: str | tuple[str, ...]
        if isinstance(contract.write_scope, tuple):
            write_scope = tuple(contract.write_scope)
        else:
            write_scope = str(contract.write_scope)
        return cls._build(
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

    def is_subset_of(self, parent: "TaskModelAuthority") -> bool:
        """Return True when this delegated envelope cannot exceed the parent."""
        try:
            child_capability = TaskCapabilityAuthority.from_model_authority(self)
            parent_capability = TaskCapabilityAuthority.from_model_authority(parent)
        except ValueError:
            return False
        if not child_capability.is_subset_of(parent_capability):
            return False
        if _RISK_ORDER[self.risk_level] < _RISK_ORDER[parent.risk_level]:
            return False
        if _TIER_ORDER[self.max_model_tier] > _TIER_ORDER[parent.max_model_tier]:
            return False
        if not parent.permits_tier(self.initial_model_tier):
            return False
        if self.escalation_allowed and not parent.escalation_allowed:
            return False
        return True

    def delegate(
        self,
        *,
        task_id: str | None = None,
        sensitivity: str | None = None,
        risk_level: str | None = None,
        allowed_sources: Iterable[str] | None = None,
        allowed_tools: Iterable[str] | None = None,
        write_scope: str | Iterable[str] | None = None,
        network_scope: str | None = None,
        initial_model_tier: str | None = None,
        max_model_tier: str | None = None,
        escalation_allowed: bool | None = None,
    ) -> "TaskModelAuthority":
        if write_scope is None:
            child_write: str | tuple[str, ...] = self.write_scope
        elif isinstance(write_scope, str):
            child_write = write_scope
        else:
            child_write = _unique(write_scope)
        child_max_tier = str(max_model_tier or self.max_model_tier).strip().lower()
        child_initial_tier = str(initial_model_tier or self.initial_model_tier).strip().lower()
        if (
            child_initial_tier in _TIER_ORDER
            and child_max_tier in _TIER_ORDER
            and _TIER_ORDER[child_initial_tier] > _TIER_ORDER[child_max_tier]
            and initial_model_tier is None
        ):
            child_initial_tier = child_max_tier
        child = self._build(
            task_id=task_id or self.task_id,
            sensitivity=sensitivity or self.sensitivity,
            risk_level=risk_level or self.risk_level,
            allowed_sources=self.allowed_sources if allowed_sources is None else _unique(allowed_sources),
            allowed_tools=self.allowed_tools if allowed_tools is None else _unique(allowed_tools),
            write_scope=child_write,
            network_scope=network_scope or self.network_scope,
            initial_model_tier=child_initial_tier,
            max_model_tier=child_max_tier,
            escalation_allowed=(
                self.escalation_allowed if escalation_allowed is None else bool(escalation_allowed)
            ),
            delegated_from=self.fingerprint,
        )
        if not child.is_subset_of(self):
            raise ModelAuthorityDenied("DELEGATED_MODEL_AUTHORITY_WIDENED")
        return child

    def metadata(self) -> dict[str, str | bool]:
        payload: dict[str, str | bool] = {
            "schema_version": "workspace-task-model-authority/v1",
            "task_id": self.task_id,
            "authority_fingerprint": self.fingerprint,
            "initial_model_tier": self.initial_model_tier,
            "max_model_tier": self.max_model_tier,
            "escalation_allowed": self.escalation_allowed,
        }
        if self.delegated_from is not None:
            payload["delegated_from"] = self.delegated_from
        return payload
