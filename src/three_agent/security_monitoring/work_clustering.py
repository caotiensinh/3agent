from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .contracts import AssetInventoryRecord, MonitoringContractError, _compact, canonical_json, sha256_fingerprint
from .plan import CollectorWorkItem
from .policy import MonitoringCapabilityDecision, MonitoringPolicyEngine, READ_ONLY_EFFECTS
from .rule_compiler import CompiledRulePlan

RULE_WORK_BINDING_SCHEMA = "workspace-security-monitoring/rule-work-binding-v1"
RULE_WORK_CLUSTER_SCHEMA = "workspace-security-monitoring/rule-work-cluster-v1"


def _work_identity(work: CollectorWorkItem) -> dict[str, object]:
    return {
        "asset_id": work.asset_id,
        "capability": work.capability,
        "credential_ref": None if work.credential_ref is None else work.credential_ref.handle,
        "target_host": work.target_host,
        "target_port": work.target_port,
        "work_id": work.work_id,
    }


@dataclass(frozen=True)
class AuthorizedRuleWorkBinding:
    rule_id: str
    compiled_rule_fingerprint: str
    work: CollectorWorkItem
    decision: MonitoringCapabilityDecision
    schema_version: str = RULE_WORK_BINDING_SCHEMA

    def validate(self) -> "AuthorizedRuleWorkBinding":
        object.__setattr__(self, "rule_id", _compact(self.rule_id, "rule_id", max_len=128))
        fingerprint = str(self.compiled_rule_fingerprint or "").strip().lower()
        if not fingerprint.startswith("sha256:") or len(fingerprint) != 71:
            raise MonitoringContractError("compiled_rule_fingerprint must be a sha256 digest")
        object.__setattr__(self, "compiled_rule_fingerprint", fingerprint)
        if not self.decision.allowed or self.decision.reason_code != "MONITORING_READ_AUTHORIZED":
            raise MonitoringContractError("rule work binding requires an allowed monitoring decision")
        if self.decision.asset_id != self.work.asset_id:
            raise MonitoringContractError("rule work decision asset mismatch")
        if self.decision.capability != self.work.capability:
            raise MonitoringContractError("rule work decision capability mismatch")
        expected_effect = READ_ONLY_EFFECTS.get(self.work.capability)
        if expected_effect is None or self.decision.effect != expected_effect:
            raise MonitoringContractError("rule work decision effect mismatch")
        if self.decision.target_host != self.work.target_host:
            raise MonitoringContractError("rule work decision target mismatch")
        if self.decision.target_port != self.work.target_port:
            raise MonitoringContractError("rule work decision port mismatch")
        if self.schema_version != RULE_WORK_BINDING_SCHEMA:
            raise MonitoringContractError("unsupported rule work binding schema")
        return self

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "compiled_rule_fingerprint": self.compiled_rule_fingerprint,
            "decision": self.decision.metadata(),
            "rule_id": self.rule_id,
            "schema_version": self.schema_version,
            "work": _work_identity(self.work),
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


@dataclass(frozen=True)
class RuleWorkCluster:
    cluster_id: str
    work: CollectorWorkItem
    rule_ids: tuple[str, ...]
    compiled_rule_fingerprints: tuple[str, ...]
    binding_fingerprints: tuple[str, ...]
    policy_fingerprint: str
    asset_fingerprint: str
    schema_version: str = RULE_WORK_CLUSTER_SCHEMA

    def validate(self) -> "RuleWorkCluster":
        object.__setattr__(self, "cluster_id", _compact(self.cluster_id, "cluster_id", max_len=128))
        rule_ids = tuple(sorted(set(_compact(value, "rule_id", max_len=128) for value in self.rule_ids)))
        if not rule_ids or rule_ids != self.rule_ids:
            raise MonitoringContractError("cluster rule_ids must be non-empty, sorted and unique")
        object.__setattr__(self, "rule_ids", rule_ids)
        compiled = tuple(sorted(set(str(value).lower() for value in self.compiled_rule_fingerprints)))
        bindings = tuple(sorted(set(str(value).lower() for value in self.binding_fingerprints)))
        if len(compiled) != len(rule_ids) or len(bindings) != len(rule_ids):
            raise MonitoringContractError("cluster provenance must map exactly to rule bindings")
        if any(not value.startswith("sha256:") or len(value) != 71 for value in compiled + bindings):
            raise MonitoringContractError("cluster provenance requires sha256 fingerprints")
        object.__setattr__(self, "compiled_rule_fingerprints", compiled)
        object.__setattr__(self, "binding_fingerprints", bindings)
        for field_name, value in (
            ("policy_fingerprint", self.policy_fingerprint),
            ("asset_fingerprint", self.asset_fingerprint),
        ):
            fingerprint = str(value or "").strip().lower()
            if not fingerprint.startswith("sha256:") or len(fingerprint) != 71:
                raise MonitoringContractError(f"{field_name} must be a sha256 digest")
            object.__setattr__(self, field_name, fingerprint)
        if self.schema_version != RULE_WORK_CLUSTER_SCHEMA:
            raise MonitoringContractError("unsupported rule work cluster schema")
        return self

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "asset_fingerprint": self.asset_fingerprint,
            "binding_fingerprints": list(self.binding_fingerprints),
            "cluster_id": self.cluster_id,
            "compiled_rule_fingerprints": list(self.compiled_rule_fingerprints),
            "policy_fingerprint": self.policy_fingerprint,
            "rule_ids": list(self.rule_ids),
            "schema_version": self.schema_version,
            "work": _work_identity(self.work),
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


def bind_rule_to_authorized_work(
    *,
    plan: CompiledRulePlan,
    work: CollectorWorkItem,
    asset: AssetInventoryRecord,
    policy_engine: MonitoringPolicyEngine,
) -> AuthorizedRuleWorkBinding:
    """Bind a rule to inventory-derived work only after exact existing-policy authorization."""

    plan.validate()
    asset.validate()
    if not plan.enabled:
        raise MonitoringContractError("disabled rule cannot request collection work")
    if work.asset_id != asset.asset_id:
        raise MonitoringContractError("work item does not belong to supplied approved asset")
    if work.capability not in plan.required_capabilities:
        raise MonitoringContractError("work capability is not required by compiled rule")
    expected_effect = READ_ONLY_EFFECTS.get(work.capability)
    if expected_effect is None:
        raise MonitoringContractError("work capability has no read-only effect mapping")
    decision = policy_engine.authorize(
        asset,
        capability=work.capability,
        effect=expected_effect,
        target_host=work.target_host,
        target_port=work.target_port,
        credential_ref=work.credential_ref,
    )
    if not decision.allowed:
        raise PermissionError(decision.reason_code)
    return AuthorizedRuleWorkBinding(
        rule_id=plan.rule_id,
        compiled_rule_fingerprint=plan.fingerprint,
        work=work,
        decision=decision,
    ).validate()


def cluster_authorized_rule_work(
    bindings: Iterable[AuthorizedRuleWorkBinding],
    *,
    max_bindings: int = 10000,
    max_clusters: int = 5000,
) -> tuple[RuleWorkCluster, ...]:
    """Deduplicate exact already-authorized collection work across rules before execution."""

    if isinstance(max_bindings, bool) or not isinstance(max_bindings, int) or not 1 <= max_bindings <= 50000:
        raise MonitoringContractError("max_bindings must be an integer within 1..50000")
    if isinstance(max_clusters, bool) or not isinstance(max_clusters, int) or not 1 <= max_clusters <= 20000:
        raise MonitoringContractError("max_clusters must be an integer within 1..20000")

    grouped: dict[str, list[AuthorizedRuleWorkBinding]] = {}
    work_by_id: dict[str, dict[str, object]] = {}
    count = 0
    for raw in bindings:
        binding = raw.validate()
        count += 1
        if count > max_bindings:
            raise MonitoringContractError("rule work binding bound exceeded")
        identity = _work_identity(binding.work)
        previous = work_by_id.get(binding.work.work_id)
        if previous is not None and previous != identity:
            raise MonitoringContractError("same work_id has conflicting work identity")
        work_by_id[binding.work.work_id] = identity
        grouped.setdefault(binding.work.work_id, []).append(binding)

    if len(grouped) > max_clusters:
        raise MonitoringContractError("rule work cluster bound exceeded")

    clusters: list[RuleWorkCluster] = []
    for work_id in sorted(grouped):
        members = sorted(grouped[work_id], key=lambda item: (item.rule_id, item.compiled_rule_fingerprint))
        first = members[0]
        if any(item.decision.policy_fingerprint != first.decision.policy_fingerprint for item in members):
            raise MonitoringContractError("equivalent work cannot mix policy fingerprints")
        if any(item.decision.asset_fingerprint != first.decision.asset_fingerprint for item in members):
            raise MonitoringContractError("equivalent work cannot mix asset fingerprints")
        unique_rules: dict[str, AuthorizedRuleWorkBinding] = {}
        for item in members:
            previous = unique_rules.get(item.rule_id)
            if previous is not None and previous.compiled_rule_fingerprint != item.compiled_rule_fingerprint:
                raise MonitoringContractError("same rule_id has conflicting compiled provenance")
            unique_rules[item.rule_id] = item
        selected = tuple(unique_rules[key] for key in sorted(unique_rules))
        identity = {
            "work": _work_identity(first.work),
            "rule_ids": [item.rule_id for item in selected],
            "compiled_rule_fingerprints": [item.compiled_rule_fingerprint for item in selected],
            "policy_fingerprint": first.decision.policy_fingerprint,
            "asset_fingerprint": first.decision.asset_fingerprint,
        }
        cluster_id = "work-cluster-" + sha256_fingerprint(identity).split(":", 1)[1][:24]
        clusters.append(
            RuleWorkCluster(
                cluster_id=cluster_id,
                work=first.work,
                rule_ids=tuple(item.rule_id for item in selected),
                compiled_rule_fingerprints=tuple(sorted(item.compiled_rule_fingerprint for item in selected)),
                binding_fingerprints=tuple(sorted(item.fingerprint for item in selected)),
                policy_fingerprint=first.decision.policy_fingerprint,
                asset_fingerprint=first.decision.asset_fingerprint,
            ).validate()
        )
    return tuple(clusters)
