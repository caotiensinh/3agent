"""Canonical WorkSpace micro-tool contracts.

Importing this package exposes metadata types only. Executor modules are resolved lazily by
later runtime layers after policy approval.
"""

from .spec import (
    ToolCost,
    ToolEffect,
    ToolNetworkRequirement,
    ToolPlatform,
    ToolPrivilege,
    ToolSensitivity,
    ToolSpec,
    ToolSpecValidationError,
)

__all__ = [
    "ToolCost",
    "ToolEffect",
    "ToolNetworkRequirement",
    "ToolPlatform",
    "ToolPrivilege",
    "ToolSensitivity",
    "ToolSpec",
    "ToolSpecValidationError",
]
