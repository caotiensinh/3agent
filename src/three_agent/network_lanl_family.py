from __future__ import annotations

from .network_corpus_adapter import NetworkAdapterError

LANL_SOURCE_FAMILY_PREFIXES = {
    "auth": "lanl/auth/",
    "process": "lanl/process/",
    "dns": "lanl/dns/",
    "flow": "lanl/flow/",
    "redteam": "lanl/redteam/",
}


class LANLSourceFamilySchemaError(NetworkAdapterError):
    """LANL logical source reference is bound to the wrong source family."""


def validate_lanl_source_family_ref(
    source_object_ref: str,
    expected_family: str,
) -> None:
    family = str(expected_family or "").strip().casefold()
    expected_prefix = LANL_SOURCE_FAMILY_PREFIXES.get(family)
    if expected_prefix is None:
        raise LANLSourceFamilySchemaError("unsupported LANL source family")

    logical_ref = str(source_object_ref or "").strip()
    if not logical_ref.startswith(expected_prefix):
        raise LANLSourceFamilySchemaError(
            f"LANL source_object_ref must use {expected_prefix} namespace"
        )
