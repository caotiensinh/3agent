from __future__ import annotations

import platform
from functools import lru_cache
from typing import Any

from .micro_tool_registry import MicroToolRegistry, ToolSelectionRequest, ToolSelectionResult
from .office_it_tools import TOOL_SPECS, OfficeITToolSpec, iter_specs


@lru_cache(maxsize=1)
def office_it_micro_tool_registry() -> MicroToolRegistry:
    """Build the canonical adaptive metadata view over the existing Office IT tools."""
    return MicroToolRegistry.from_specs(iter_specs())


def select_office_it_tools(
    query: str,
    *,
    platform_name: str | None = None,
    mode: str = "quick",
    max_tools: int = 4,
    authority: Any | None = None,
    admin_available: bool | None = None,
) -> tuple[OfficeITToolSpec, ...]:
    """Select Office IT capabilities through the generic V0.2 registry.

    This adapter keeps the V0.1 tool implementations and exact execution authority
    unchanged. It only centralizes metadata validation and minimum-evidence routing.
    """
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
    """Return the audit-friendly V0.2 selection result without executing any tool."""
    request = ToolSelectionRequest(
        query=query,
        platform=platform_name or platform.system(),
        mode=mode,
        max_tools=max_tools,
        authority=authority,
        admin_available=admin_available,
        allow_external_network=False,
        full_authorized=False,
        escalated=False,
    )
    return office_it_micro_tool_registry().select(request)
