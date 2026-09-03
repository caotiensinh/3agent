from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .privacy import (
    ACTION_ALLOW,
    INTERNET_EGRESS_POLICY_VERSION,
    SENSITIVITY_PUBLIC,
    apply_internet_egress_policy,
)

PUBLIC_QUERY_COMPILER_VERSION = "workspace-public-query-compiler/v2"


@dataclass(frozen=True)
class PublicQueryCompilation:
    allowed: bool
    query: str
    reasons: tuple[str, ...]
    removed_sensitive_fields: int
    compiler_version: str = PUBLIC_QUERY_COMPILER_VERSION
    sensitivity: str = SENSITIVITY_PUBLIC
    action: str = ACTION_ALLOW
    warning_required: bool = False
    policy_version: str = INTERNET_EGRESS_POLICY_VERSION


def compile_public_search_query(value: str, *, max_chars: int = 240) -> PublicQueryCompilation:
    """Derive one minimum public query under the four-level egress safety rule."""
    decision = apply_internet_egress_policy(value, max_chars=max_chars)
    return PublicQueryCompilation(
        allowed=decision.allowed,
        query=decision.query if decision.allowed else "",
        reasons=decision.reasons,
        removed_sensitive_fields=decision.removed_sensitive_fields,
        sensitivity=decision.sensitivity,
        action=decision.action,
        warning_required=decision.warning_required,
    )


def compile_public_search_queries(
    values: Iterable[str],
    *,
    fallback: str = "",
    max_queries: int = 4,
    max_chars: int = 240,
) -> tuple[list[str], list[str]]:
    """Compile/deduplicate queries; return safe queries and metadata-only diagnostics."""
    queries: list[str] = []
    diagnostics: list[str] = []
    candidates = [str(value) for value in values]
    if fallback:
        candidates.append(str(fallback))
    for candidate in candidates:
        result = compile_public_search_query(candidate, max_chars=max_chars)
        if not result.allowed:
            diagnostics.append(
                "public_query_blocked "
                f"sensitivity={result.sensitivity} action={result.action} "
                "reasons=" + ",".join(result.reasons)
            )
            continue
        if result.warning_required:
            diagnostics.append(
                "public_query_policy_warning "
                f"sensitivity={result.sensitivity} action={result.action} "
                f"removed_fields={result.removed_sensitive_fields}"
            )
        elif result.removed_sensitive_fields:
            diagnostics.append(
                f"public_query_sanitized removed_fields={result.removed_sensitive_fields}"
            )
        if result.query not in queries:
            queries.append(result.query)
        if len(queries) >= max_queries:
            break
    return queries, diagnostics
