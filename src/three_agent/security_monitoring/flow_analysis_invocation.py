"""Compatibility imports for the canonical flow-analysis invocation path.

Guardian v0.1 consolidated the reviewed flow binding and invocation authority into
``operation_binding`` and ``operation_invocation``. This module intentionally contains
no binding profile, subclass, dispatch override, or independent execution authority.
Existing imports continue to resolve to the canonical implementations.
"""

from __future__ import annotations

from .operation_binding import (
    FLOW_ANALYSIS_HANDLER_ID,
    SecurityOperationBindingRegistry,
    reviewed_runtime_handler_exists,
)
from .operation_invocation import (
    FLOW_ANALYSIS_INVOCATION_RECEIPT_SCHEMA,
    FLOW_ANALYSIS_OUTPUT_KIND,
    FlowAnalysisInvocationReceipt,
    FlowAnalysisInvocationRequest,
    SecurityOperationInvoker,
)

FlowAnalysisSecurityOperationBindingRegistry = SecurityOperationBindingRegistry
FlowAnalysisSecurityOperationInvoker = SecurityOperationInvoker
FLOW_ANALYSIS_REVIEWED_BINDING = SecurityOperationBindingRegistry().require_bound(
    "network.flow.analyze",
    "analyze_flow_evidence",
)


def reviewed_flow_analysis_runtime_handler_exists(handler_id: str) -> bool:
    """Compatibility wrapper over the canonical closed-handler attestation."""

    return handler_id == FLOW_ANALYSIS_HANDLER_ID and reviewed_runtime_handler_exists(handler_id)
