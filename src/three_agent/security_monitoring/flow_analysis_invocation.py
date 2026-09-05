"""Compatibility facade for the canonical flow-analysis invocation path.

Guardian v0.1 consolidated reviewed flow binding and invocation authority into
``operation_binding`` and ``operation_invocation``. This module keeps the legacy
flow-analysis import and constructor contracts without owning an independent binding
manifest, dispatch path, or authorization decision.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .capability_registry import SecurityCapabilityRegistry
from .operation_binding import (
    FLOW_ANALYSIS_HANDLER_ID,
    SecurityOperationBindingError,
    SecurityOperationBindingRegistry,
    SecurityOperationHandlerUnbound,
    reviewed_runtime_handler_exists,
)
from .operation_invocation import (
    FLOW_ANALYSIS_INVOCATION_RECEIPT_SCHEMA,
    FLOW_ANALYSIS_OUTPUT_KIND,
    FlowAnalysisInvocationReceipt,
    FlowAnalysisInvocationRequest,
    SecurityOperationInvocationError,
    SecurityOperationInvoker,
)

_FLOW_ANALYSIS_KEY = ("network.flow.analyze", "analyze_flow_evidence")


@dataclass(frozen=True)
class FlowAnalysisReviewedOperationBinding:
    """Read-only legacy view of the canonical reviewed flow binding."""

    capability_id: str
    operation_id: str
    status: str
    reason_code: str
    handler_id: str
    handler_kind: str = "pure_function"
    output_kind: str = FLOW_ANALYSIS_OUTPUT_KIND
    schema_version: str = "workspace-security-operation-binding/v1"

    def validate(self) -> "FlowAnalysisReviewedOperationBinding":
        if (self.capability_id, self.operation_id) != _FLOW_ANALYSIS_KEY:
            raise SecurityOperationBindingError("flow analysis reviewed binding key mismatch")
        if self.status != "bound" or self.reason_code != "BOUND_TO_REVIEWED_RUNTIME_HANDLER":
            raise SecurityOperationBindingError("flow analysis reviewed binding must remain explicitly bound")
        if self.handler_id != FLOW_ANALYSIS_HANDLER_ID:
            raise SecurityOperationBindingError("flow analysis reviewed binding handler mismatch")
        if self.handler_kind != "pure_function":
            raise SecurityOperationBindingError("flow analysis handler_kind must be pure_function")
        if self.output_kind != FLOW_ANALYSIS_OUTPUT_KIND:
            raise SecurityOperationBindingError("flow analysis output_kind mismatch")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)


_canonical_flow_binding = SecurityOperationBindingRegistry().require_bound(*_FLOW_ANALYSIS_KEY)
FLOW_ANALYSIS_REVIEWED_BINDING = FlowAnalysisReviewedOperationBinding(
    capability_id=_canonical_flow_binding.capability_id,
    operation_id=_canonical_flow_binding.operation_id,
    status=_canonical_flow_binding.status,
    reason_code=_canonical_flow_binding.reason_code,
    handler_id=str(_canonical_flow_binding.handler_id),
    handler_kind=str(_canonical_flow_binding.handler_kind),
).validate()


class FlowAnalysisSecurityOperationBindingRegistry(SecurityOperationBindingRegistry):
    """Legacy registry facade over the immutable canonical flow binding profile.

    The legacy constructor accepted only an optional capability registry. Keeping that
    shape prevents callers from using this compatibility name to inject a replacement
    binding manifest. The canonical registry remains the source of binding authority.
    """

    def __init__(self, registry: SecurityCapabilityRegistry | None = None) -> None:
        super().__init__(registry=registry)

    def resolve(self, capability_id: str, operation_id: str):
        binding = super().resolve(capability_id, operation_id)
        if (capability_id, operation_id) == _FLOW_ANALYSIS_KEY:
            return FLOW_ANALYSIS_REVIEWED_BINDING
        return binding

    def require_bound(self, capability_id: str, operation_id: str):
        binding = self.resolve(capability_id, operation_id)
        if binding.status != "bound":
            raise SecurityOperationHandlerUnbound(binding.reason_code)
        return binding


class FlowAnalysisSecurityOperationInvoker(SecurityOperationInvoker):
    """Legacy constructor facade delegating execution to the canonical invoker.

    The pre-consolidation flow invoker owned its reviewed binding profile and rejected
    caller-supplied binding registries. Preserve that fail-closed boundary while using
    the canonical ``SecurityOperationInvoker`` for all validation, authorization,
    dispatch, and receipt generation.
    """

    def __init__(
        self,
        *,
        registry: SecurityCapabilityRegistry | None = None,
        **kwargs: Any,
    ) -> None:
        if "binding_registry" in kwargs:
            raise SecurityOperationInvocationError(
                "flow analysis invoker owns its reviewed binding profile"
            )
        security_registry = registry or SecurityCapabilityRegistry()
        super().__init__(
            registry=security_registry,
            binding_registry=FlowAnalysisSecurityOperationBindingRegistry(security_registry),
            **kwargs,
        )


def reviewed_flow_analysis_runtime_handler_exists(handler_id: str) -> bool:
    """Compatibility wrapper over the canonical closed-handler attestation."""

    return handler_id == FLOW_ANALYSIS_HANDLER_ID and reviewed_runtime_handler_exists(handler_id)
