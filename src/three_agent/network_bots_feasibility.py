from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

PROFILE_SCHEMA = "workspace-network-bots-feasibility-profile/v1"
RECEIPT_SCHEMA = "workspace-network-bots-feasibility-receipt/v1"
EVALUATOR_VERSION = "bots-v2-feasibility/0.1"

SUPPORTED_LIGHTWEIGHT = "SUPPORTED_LIGHTWEIGHT"
BLOCKED_DEPENDENCY_COST = "BLOCKED_DEPENDENCY_COST"
VERDICTS = frozenset({SUPPORTED_LIGHTWEIGHT, BLOCKED_DEPENDENCY_COST})

BOTS_DATASET_ID = "splunk-bots-v2"
BOTS_VARIANTS = frozenset({"attack-only", "full", "hypothetical-lightweight-export"})
SOURCE_FACT_BASES = frozenset({"reviewed_authoritative", "synthetic_fixture"})

REQUIRED_PROFILE_KEYS = frozenset({
    "schema_version",
    "dataset_id",
    "variant",
    "distribution_format",
    "reviewed_size",
    "license_enterprise_compatible",
    "official_integrity_scheme",
    "vendor_runtime_required",
    "separately_licensed_addons_required",
    "documented_vendor_free_event_schema",
    "vendor_free_streaming_reader_available",
    "undocumented_index_decoding_required",
    "whole_corpus_buffer_required",
    "bounded_conversion_possible",
    "source_to_derived_provenance_possible",
    "network_service_required",
    "source_fact_basis",
})


class BOTSFeasibilityError(ValueError):
    """The reviewed BOTS feasibility profile is incomplete or invalid."""


def _bounded(value: Any, field: str, *, max_len: int = 128) -> str:
    if not isinstance(value, str):
        raise BOTSFeasibilityError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized:
        raise BOTSFeasibilityError(f"{field} must not be empty")
    if len(normalized) > max_len:
        raise BOTSFeasibilityError(f"{field} exceeds maximum length")
    return normalized


def _strict_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise BOTSFeasibilityError(f"{field} must be boolean")
    return value


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def canonical_sha256(value: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class BOTSFeasibilityProfile:
    dataset_id: str
    variant: str
    distribution_format: str
    reviewed_size: str
    license_enterprise_compatible: bool
    official_integrity_scheme: str
    vendor_runtime_required: bool
    separately_licensed_addons_required: bool
    documented_vendor_free_event_schema: bool
    vendor_free_streaming_reader_available: bool
    undocumented_index_decoding_required: bool
    whole_corpus_buffer_required: bool
    bounded_conversion_possible: bool
    source_to_derived_provenance_possible: bool
    network_service_required: bool
    source_fact_basis: str
    schema_version: str = PROFILE_SCHEMA

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BOTSFeasibilityProfile":
        if not isinstance(value, Mapping):
            raise BOTSFeasibilityError("profile must be an object")

        keys = frozenset(value.keys())
        missing = REQUIRED_PROFILE_KEYS - keys
        unknown = keys - REQUIRED_PROFILE_KEYS
        if missing:
            raise BOTSFeasibilityError(
                "profile missing required fields: " + ",".join(sorted(missing))
            )
        if unknown:
            raise BOTSFeasibilityError(
                "profile contains unknown fields: " + ",".join(sorted(unknown))
            )

        schema = _bounded(value["schema_version"], "schema_version")
        if schema != PROFILE_SCHEMA:
            raise BOTSFeasibilityError("unsupported feasibility profile schema")

        dataset_id = _bounded(value["dataset_id"], "dataset_id", max_len=80)
        if dataset_id != BOTS_DATASET_ID:
            raise BOTSFeasibilityError(
                f"evaluator requires dataset_id={BOTS_DATASET_ID}"
            )

        variant = _bounded(value["variant"], "variant", max_len=80)
        if variant not in BOTS_VARIANTS:
            raise BOTSFeasibilityError(f"unsupported BOTS variant {variant!r}")

        source_fact_basis = _bounded(
            value["source_fact_basis"], "source_fact_basis", max_len=64
        )
        if source_fact_basis not in SOURCE_FACT_BASES:
            raise BOTSFeasibilityError(
                "source facts must be reviewed_authoritative or synthetic_fixture"
            )

        return cls(
            dataset_id=dataset_id,
            variant=variant,
            distribution_format=_bounded(
                value["distribution_format"], "distribution_format", max_len=80
            ),
            reviewed_size=_bounded(value["reviewed_size"], "reviewed_size", max_len=40),
            license_enterprise_compatible=_strict_bool(
                value["license_enterprise_compatible"],
                "license_enterprise_compatible",
            ),
            official_integrity_scheme=_bounded(
                value["official_integrity_scheme"],
                "official_integrity_scheme",
                max_len=40,
            ),
            vendor_runtime_required=_strict_bool(
                value["vendor_runtime_required"], "vendor_runtime_required"
            ),
            separately_licensed_addons_required=_strict_bool(
                value["separately_licensed_addons_required"],
                "separately_licensed_addons_required",
            ),
            documented_vendor_free_event_schema=_strict_bool(
                value["documented_vendor_free_event_schema"],
                "documented_vendor_free_event_schema",
            ),
            vendor_free_streaming_reader_available=_strict_bool(
                value["vendor_free_streaming_reader_available"],
                "vendor_free_streaming_reader_available",
            ),
            undocumented_index_decoding_required=_strict_bool(
                value["undocumented_index_decoding_required"],
                "undocumented_index_decoding_required",
            ),
            whole_corpus_buffer_required=_strict_bool(
                value["whole_corpus_buffer_required"],
                "whole_corpus_buffer_required",
            ),
            bounded_conversion_possible=_strict_bool(
                value["bounded_conversion_possible"],
                "bounded_conversion_possible",
            ),
            source_to_derived_provenance_possible=_strict_bool(
                value["source_to_derived_provenance_possible"],
                "source_to_derived_provenance_possible",
            ),
            network_service_required=_strict_bool(
                value["network_service_required"], "network_service_required"
            ),
            source_fact_basis=source_fact_basis,
            schema_version=schema,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "dataset_id": self.dataset_id,
            "variant": self.variant,
            "distribution_format": self.distribution_format,
            "reviewed_size": self.reviewed_size,
            "license_enterprise_compatible": self.license_enterprise_compatible,
            "official_integrity_scheme": self.official_integrity_scheme,
            "vendor_runtime_required": self.vendor_runtime_required,
            "separately_licensed_addons_required": self.separately_licensed_addons_required,
            "documented_vendor_free_event_schema": self.documented_vendor_free_event_schema,
            "vendor_free_streaming_reader_available": self.vendor_free_streaming_reader_available,
            "undocumented_index_decoding_required": self.undocumented_index_decoding_required,
            "whole_corpus_buffer_required": self.whole_corpus_buffer_required,
            "bounded_conversion_possible": self.bounded_conversion_possible,
            "source_to_derived_provenance_possible": self.source_to_derived_provenance_possible,
            "network_service_required": self.network_service_required,
            "source_fact_basis": self.source_fact_basis,
        }

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.as_dict())


@dataclass(frozen=True)
class BOTSFeasibilityReceipt:
    dataset_id: str
    variant: str
    profile_fingerprint: str
    evaluator_version: str
    verdict: str
    blocker_codes: tuple[str, ...]
    receipt_fingerprint: str
    schema_version: str = RECEIPT_SCHEMA

    @classmethod
    def build(
        cls,
        *,
        profile: BOTSFeasibilityProfile,
        verdict: str,
        blocker_codes: tuple[str, ...],
    ) -> "BOTSFeasibilityReceipt":
        if verdict not in VERDICTS:
            raise BOTSFeasibilityError(f"unsupported verdict {verdict!r}")
        blockers = tuple(sorted(set(blocker_codes)))
        if verdict == SUPPORTED_LIGHTWEIGHT and blockers:
            raise BOTSFeasibilityError(
                "SUPPORTED_LIGHTWEIGHT may not contain blocker codes"
            )
        if verdict == BLOCKED_DEPENDENCY_COST and not blockers:
            raise BOTSFeasibilityError(
                "BLOCKED_DEPENDENCY_COST requires blocker codes"
            )
        identity = {
            "schema_version": RECEIPT_SCHEMA,
            "dataset_id": profile.dataset_id,
            "variant": profile.variant,
            "profile_fingerprint": profile.fingerprint,
            "evaluator_version": EVALUATOR_VERSION,
            "verdict": verdict,
            "blocker_codes": list(blockers),
        }
        return cls(
            dataset_id=profile.dataset_id,
            variant=profile.variant,
            profile_fingerprint=profile.fingerprint,
            evaluator_version=EVALUATOR_VERSION,
            verdict=verdict,
            blocker_codes=blockers,
            receipt_fingerprint=canonical_sha256(identity),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "dataset_id": self.dataset_id,
            "variant": self.variant,
            "profile_fingerprint": self.profile_fingerprint,
            "evaluator_version": self.evaluator_version,
            "verdict": self.verdict,
            "blocker_codes": list(self.blocker_codes),
            "receipt_fingerprint": self.receipt_fingerprint,
        }


def evaluate_bots_v2_feasibility(
    profile: BOTSFeasibilityProfile,
) -> BOTSFeasibilityReceipt:
    blockers: set[str] = set()

    if not profile.license_enterprise_compatible:
        blockers.add("LICENSE_NOT_ENTERPRISE_COMPATIBLE")
    if profile.distribution_format.casefold() in {
        "pre-indexed splunk",
        "preindexed_splunk",
        "splunk-index",
    }:
        blockers.add("PREINDEXED_VENDOR_FORMAT")
    if profile.vendor_runtime_required:
        blockers.add("VENDOR_RUNTIME_REQUIRED")
    if profile.separately_licensed_addons_required:
        blockers.add("SEPARATELY_LICENSED_ADDONS_REQUIRED")
    if not profile.documented_vendor_free_event_schema:
        blockers.add("NO_DOCUMENTED_VENDOR_FREE_EVENT_SCHEMA")
    if not profile.vendor_free_streaming_reader_available:
        blockers.add("NO_VENDOR_FREE_STREAMING_READER")
    if profile.undocumented_index_decoding_required:
        blockers.add("UNDOCUMENTED_INDEX_DECODING_REQUIRED")
    if profile.whole_corpus_buffer_required or not profile.bounded_conversion_possible:
        blockers.add("UNBOUNDED_CONVERSION")
    if not profile.source_to_derived_provenance_possible:
        blockers.add("PROVENANCE_NOT_PRESERVABLE")
    if profile.network_service_required:
        blockers.add("NETWORK_SERVICE_REQUIRED_FOR_PARSE")

    verdict = SUPPORTED_LIGHTWEIGHT if not blockers else BLOCKED_DEPENDENCY_COST
    return BOTSFeasibilityReceipt.build(
        profile=profile, verdict=verdict, blocker_codes=tuple(blockers)
    )


def official_bots_v2_profile(variant: str = "attack-only") -> BOTSFeasibilityProfile:
    if variant not in {"attack-only", "full"}:
        raise BOTSFeasibilityError(
            "official BOTS v2 variant must be attack-only or full"
        )
    reviewed_size = "3.2GB" if variant == "attack-only" else "16.4GB"
    return BOTSFeasibilityProfile.from_dict(
        {
            "schema_version": PROFILE_SCHEMA,
            "dataset_id": BOTS_DATASET_ID,
            "variant": variant,
            "distribution_format": "preindexed_splunk",
            "reviewed_size": reviewed_size,
            "license_enterprise_compatible": True,
            "official_integrity_scheme": "md5",
            "vendor_runtime_required": True,
            "separately_licensed_addons_required": True,
            "documented_vendor_free_event_schema": False,
            "vendor_free_streaming_reader_available": False,
            "undocumented_index_decoding_required": False,
            "whole_corpus_buffer_required": False,
            "bounded_conversion_possible": False,
            "source_to_derived_provenance_possible": True,
            "network_service_required": False,
            "source_fact_basis": "reviewed_authoritative",
        }
    )


def synthetic_lightweight_profile() -> BOTSFeasibilityProfile:
    return BOTSFeasibilityProfile.from_dict(
        {
            "schema_version": PROFILE_SCHEMA,
            "dataset_id": BOTS_DATASET_ID,
            "variant": "hypothetical-lightweight-export",
            "distribution_format": "ndjson",
            "reviewed_size": "bounded-fixture",
            "license_enterprise_compatible": True,
            "official_integrity_scheme": "sha256",
            "vendor_runtime_required": False,
            "separately_licensed_addons_required": False,
            "documented_vendor_free_event_schema": True,
            "vendor_free_streaming_reader_available": True,
            "undocumented_index_decoding_required": False,
            "whole_corpus_buffer_required": False,
            "bounded_conversion_possible": True,
            "source_to_derived_provenance_possible": True,
            "network_service_required": False,
            "source_fact_basis": "synthetic_fixture",
        }
    )
