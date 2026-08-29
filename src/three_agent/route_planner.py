from __future__ import annotations

from dataclasses import dataclass

from .task_contract import TaskContract


ROUTE_DECISION_SCHEMA = "workspace-route-decision/v1"


@dataclass(frozen=True)
class RouteDecision:
    route: str
    reason_code: str
    initial_model_tier: str
    max_model_tier: str
    escalation_allowed: bool

    def to_dict(self) -> dict:
        return {
            "schema_version": ROUTE_DECISION_SCHEMA,
            "route": self.route,
            "reason_code": self.reason_code,
            "initial_model_tier": self.initial_model_tier,
            "max_model_tier": self.max_model_tier,
            "escalation_allowed": self.escalation_allowed,
        }


class DeterministicRoutePlanner:
    """Derive an auditable execution route from the already-authoritative contract.

    The planner never reads raw task content and never grants authority. It only
    projects TaskContract model policy into a compact route decision. A `NO_LLM`
    route is possible only when the contract itself has already reduced both model
    tiers to `none` and disabled escalation.
    """

    @staticmethod
    def plan(contract: TaskContract) -> RouteDecision:
        contract.validate()
        policy = contract.model_policy
        if policy.initial_tier == "none":
            return RouteDecision(
                route="NO_LLM",
                reason_code="CONTRACT_NO_LLM",
                initial_model_tier="none",
                max_model_tier="none",
                escalation_allowed=False,
            )
        return RouteDecision(
            route="MODEL",
            reason_code=f"CONTRACT_{policy.initial_tier.upper()}_FIRST",
            initial_model_tier=policy.initial_tier,
            max_model_tier=policy.max_tier,
            escalation_allowed=policy.escalation_allowed,
        )
