from __future__ import annotations

import platform
from functools import lru_cache
from typing import Any

from .diagnostics.complaint_semantics import normalize_complaint_semantics
from .diagnostics.runtime_registry import runtime_micro_tool_registry
from .micro_tool_registry import MicroToolRegistry, ToolSelectionRequest, ToolSelectionResult
from .office_it_tools import TOOL_SPECS, OfficeITToolSpec, iter_specs


@lru_cache(maxsize=1)
def office_it_micro_tool_registry() -> MicroToolRegistry:
    """Build the canonical adaptive metadata view over the existing Office IT tools."""
    return MicroToolRegistry.from_specs(iter_specs())


def _request_for_query(
    query: str,
    *,
    platform_name: str | None,
    mode: str,
    max_tools: int,
    authority: Any | None,
    admin_available: bool | None,
) -> ToolSelectionRequest:
    semantics = normalize_complaint_semantics(query)
    return ToolSelectionRequest(
        query=semantics.routing_query(),
        platform=platform_name or platform.system(),
        mode=mode,
        max_tools=max_tools,
        authority=authority,
        admin_available=admin_available,
        allow_external_network=False,
        full_authorized=False,
        escalated=False,
    )


def select_pc_diagnostic_tool_metadata(
    query: str,
    *,
    platform_name: str | None = None,
    mode: str = "quick",
    max_tools: int = 4,
    authority: Any | None = None,
    admin_available: bool | None = None,
) -> ToolSelectionResult:
    """Select bounded evidence across the canonical cross-platform diagnostic runtime."""
    request = _request_for_query(
        query,
        platform_name=platform_name,
        mode=mode,
        max_tools=max_tools,
        authority=authority,
        admin_available=admin_available,
    )
    return runtime_micro_tool_registry().select(request)


def select_office_it_tools(
    query: str,
    *,
    platform_name: str | None = None,
    mode: str = "quick",
    max_tools: int = 4,
    authority: Any | None = None,
    admin_available: bool | None = None,
) -> tuple[OfficeITToolSpec, ...]:
    """Backward-compatible Office IT selector with semantic normalization."""
    result = select_office_it_tool_metadata(
        query,
        platform_name=platform_name,
        mode=mode,
        max_tools=max_tools,
        authority=authority,
        admin_available=admin_available,
    )
    return tuple(TOOL_SPECS[metadata.id] for metadata in result.selected)


def select_office_it_tool_metadata(
    query: str,
    *,
    platform_name: str | None = None,
    mode: str = "quick",
    max_tools: int = 4,
    authority: Any | None = None,
    admin_available: bool | None = None,
) -> ToolSelectionResult:
    """Return the audit-friendly Office IT selection result without executing tools."""
    request = _request_for_query(
        query,
        platform_name=platform_name,
        mode=mode,
        max_tools=max_tools,
        authority=authority,
        admin_available=admin_available,
    )
    return office_it_micro_tool_registry().select(request)
