from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

PROFILE_SCHEMA = "workspace-network-real-source-acceptance-profile/v1"
MANIFEST_SCHEMA = "workspace-network-real-source-acceptance-manifest/v1"
RECEIPT_SCHEMA = "workspace-network-real-source-acceptance-receipt/v1"
REGISTRY_SCHEMA = "workspace-network-dataset-registry/v1"
CONTRACT_VERSION = "real-source-acceptance-contract/0.1"

PASS = "PASS"
FAIL_SCHEMA = "FAIL_SCHEMA"
FAIL_INTEGRITY = "FAIL_INTEGRITY"
FAIL_SECURITY = "FAIL_SECURITY"
FAIL_PROVENANCE = "FAIL_PROVENANCE"
FAIL_LICENSE = "FAIL_LICENSE"
FAIL_RESOURCE = "FAIL_RESOURCE"
NOT_ENOUGH_REAL_SOURCE_EVIDENCE = "NOT_ENOUGH_REAL_SOURCE_EVIDENCE"
VERDICTS = frozenset({
    PASS, FAIL_SCHEMA, FAIL_INTEGRITY, FAIL_SECURITY, FAIL_PROVENANCE,
    FAIL_LICENSE, FAIL_RESOURCE, NOT_ENOUGH_REAL_SOURCE_EVIDENCE,
})

REQUIRED_MANIFEST_KEYS = frozenset({
    "schema_version", "acceptance_id", "spec_version", "created_by_role",
    "registry_fingerprint", "policy_fingerprint", "sources", "expected_lanes",
    "bots_direct_adapter_authorized",
})
REQUIRED_SOURCE_KEYS = frozenset({
    "source_id", "dataset_id", "variant", "source_family", "real_source",
    "publisher_reference", "acquisition_mode", "acquisition_receipt_fingerprint",
    "parent_source_object_ref", "parent_source_sha256", "parent_source_size_bytes",
    "bounded_source_object_ref", "bounded_source_sha256",
    "bounded_source_size_bytes", "derivation", "adapter_id", "adapter_version",
    "provenance_ref",
})
REQUIRED_RECEIPT_KEYS = frozenset({
    "schema_version", "acceptance_id", "exact_head_sha", "spec_fingerprint",
    "manifest_fingerprint", "dataset_id", "variant", "source_family",
    "real_source_verified", "publisher_reference_fingerprint",
    "acquisition_receipt_fingerprint", "parent_source_sha256",
    "bounded_source_sha256", "adapter_id", "adapter_version", "records_seen",
    "records_emitted", "records_rejected", "truth_records_emitted",
    "evidence_fingerprint", "truth_fingerprint", "deterministic_replay_pass",
    "visible_schema_pass", "truth_separation_pass", "provenance_pass",
    "resource_pass", "cleanup_pass", "network_calls", "model_calls",
    "subprocess_calls", "peak_rss_delta_bytes", "verdict", "failed_gate_ids",
})
FORBIDDEN_DURABLE_KEYS = frozenset({
    "raw_line", "raw_record", "raw_payload", "exception_text", "password",
    "credential", "signed_url", "cookie", "token", "secret",
})
MAX_DURABLE_OBJECT_BYTES = 1024 * 1024


class RealSourceAcceptanceError(ValueError):
    def __init__(self, verdict: str, gate_id: str, message: str):
        if verdict not in VERDICTS:
            raise ValueError(f"unsupported verdict {verdict!r}")
        self.verdict = verdict
        self.gate_id = gate_id
        super().__init__(f"{gate_id}: {message}")


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _bounded(value: Any, field: str, max_len: int = 512) -> str:
    if not isinstance(value, str):
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "FIELD_TYPE", f"{field} must be string")
    text = value.strip()
    if not text or len(text) > max_len:
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "FIELD_BOUNDS", f"{field} is invalid")
    return text


def _strict_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "FIELD_TYPE", f"{field} must be boolean")
    return value


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "FIELD_TYPE", f"{field} must be integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RealSourceAcceptanceError(
            FAIL_SCHEMA, "FIELD_TYPE", f"{field} must be integer"
        ) from exc
    if parsed < 0:
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "FIELD_BOUNDS", f"{field} must be >= 0")
    return parsed


def _positive_int(value: Any, field: str) -> int:
    parsed = _nonnegative_int(value, field)
    if parsed == 0:
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "FIELD_BOUNDS", f"{field} must be > 0")
    return parsed


def _sha(value: Any, field: str, *, verdict: str = FAIL_PROVENANCE) -> str:
    if not isinstance(value, str):
        raise RealSourceAcceptanceError(verdict, "DIGEST_FORMAT", f"{field} is invalid")
    text = value.strip().lower()
    if len(text) != 71 or not text.startswith("sha256:"):
        raise RealSourceAcceptanceError(verdict, "DIGEST_FORMAT", f"{field} is invalid")
    try:
        int(text[7:], 16)
    except ValueError as exc:
        raise RealSourceAcceptanceError(verdict, "DIGEST_FORMAT", f"{field} is invalid") from exc
    return text


def _logical_ref(value: Any, field: str) -> str:
    text = _bounded(value, field)
    if "\\" in text or text.startswith(("/", "~")):
        raise RealSourceAcceptanceError(
            FAIL_SECURITY, "PATH_OR_SYMLINK_ESCAPE", f"{field} is not a logical ref"
        )
    parts = text.split("/")
    if any(part in {"", ".", ".."} for part in parts) or ":" in parts[0]:
        raise RealSourceAcceptanceError(
            FAIL_SECURITY, "PATH_OR_SYMLINK_ESCAPE", f"{field} has unsafe path segments"
        )
    return text


def _publisher_host(value: Any, field: str) -> tuple[str, str]:
    text = _bounded(value, field, 1024)
    if not text.startswith("https://"):
        raise RealSourceAcceptanceError(
            FAIL_PROVENANCE, "UNREVIEWED_PUBLISHER_OR_MIRROR", f"{field} must use HTTPS"
        )
    if "?" in text or "#" in text:
        raise RealSourceAcceptanceError(
            FAIL_SECURITY, "SIGNED_OR_SECRET_URL", f"{field} may not contain query/fragment"
        )
    authority = text[8:].split("/", 1)[0]
    if not authority or "@" in authority:
        raise RealSourceAcceptanceError(
            FAIL_SECURITY, "SIGNED_OR_SECRET_URL", f"{field} may not contain credentials"
        )
    return text, authority.split(":", 1)[0].casefold()


def _forbid_durable_keys(value: Any, path: str) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).strip().casefold() in FORBIDDEN_DURABLE_KEYS:
                raise RealSourceAcceptanceError(
                    FAIL_SECURITY, "RAW_SOURCE_CONTENT_IN_DURABLE_RECEIPT",
                    f"forbidden durable key {key!r} at {path}",
                )
            _forbid_durable_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _forbid_durable_keys(child, f"{path}[{index}]")


def _size_guard(value: Any, field: str) -> None:
    try:
        encoded = json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RealSourceAcceptanceError(
            FAIL_SCHEMA, "NON_CANONICAL_JSON", f"{field} is not canonical JSON"
        ) from exc
    if len(encoded) > MAX_DURABLE_OBJECT_BYTES:
        raise RealSourceAcceptanceError(
            FAIL_RESOURCE, "DURABLE_OBJECT_TOO_LARGE", f"{field} exceeds 1 MiB"
        )


def _registry_index(registry: Mapping[str, Any]) -> tuple[dict[str, Mapping[str, Any]], str]:
    if registry.get("schema_version") != REGISTRY_SCHEMA:
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "REGISTRY_SCHEMA", "registry schema invalid")
    raw = registry.get("datasets")
    if not isinstance(raw, list):
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "REGISTRY_SCHEMA", "datasets must be list")
    index: dict[str, Mapping[str, Any]] = {}
    for item in raw:
        if not isinstance(item, Mapping):
            raise RealSourceAcceptanceError(FAIL_SCHEMA, "REGISTRY_SCHEMA", "dataset must be object")
        dataset_id = _bounded(item.get("id"), "dataset.id", 80)
        if dataset_id in index:
            raise RealSourceAcceptanceError(FAIL_SCHEMA, "REGISTRY_SCHEMA", "duplicate dataset")
        index[dataset_id] = item
    return index, canonical_sha256(registry)


def _profile_lanes(profile: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    if profile.get("schema_version") != PROFILE_SCHEMA:
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "PROFILE_SCHEMA", "profile schema invalid")
    exclusions = profile.get("explicit_exclusions")
    bots = exclusions.get("splunk-bots-v2") if isinstance(exclusions, Mapping) else None
    if not isinstance(bots, Mapping) or bots.get("direct_adapter_authorized") is not False:
        raise RealSourceAcceptanceError(
            FAIL_SECURITY, "BOTS_DIRECT_ADAPTER_ATTEMPT", "BOTS must remain blocked"
        )
    if bots.get("runtime_verdict") != "BLOCKED_DEPENDENCY_COST":
        raise RealSourceAcceptanceError(
            FAIL_SECURITY, "BOTS_DIRECT_ADAPTER_ATTEMPT", "BOTS feasibility verdict drifted"
        )
    if frozenset(map(str, profile.get("verdicts", []))) != VERDICTS:
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "PROFILE_SCHEMA", "verdict set drifted")
    resource = profile.get("resource_contract")
    if not isinstance(resource, Mapping):
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "PROFILE_SCHEMA", "resource contract missing")
    for field in ("network_calls", "model_calls", "subprocess_calls"):
        if resource.get(field) != 0:
            raise RealSourceAcceptanceError(
                FAIL_SECURITY, "PROFILE_AUTHORITY", f"{field} must be zero"
            )
    raw_lanes = profile.get("authorized_lanes")
    if not isinstance(raw_lanes, list) or not raw_lanes:
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "PROFILE_SCHEMA", "lanes missing")
    lanes: dict[str, Mapping[str, Any]] = {}
    for lane in raw_lanes:
        if not isinstance(lane, Mapping):
            raise RealSourceAcceptanceError(FAIL_SCHEMA, "PROFILE_SCHEMA", "lane must be object")
        lane_id = _bounded(lane.get("lane_id"), "lane_id", 80)
        if lane_id in lanes:
            raise RealSourceAcceptanceError(FAIL_SCHEMA, "PROFILE_SCHEMA", "duplicate lane")
        lanes[lane_id] = lane
    return lanes


@dataclass(frozen=True)
class ValidatedManifest:
    acceptance_id: str
    expected_lanes: tuple[str, ...]
    fingerprint: str


@dataclass(frozen=True)
class LaneObservation:
    lane_id: str
    valid_records: int
    truth_classes: tuple[str, ...] = ()
    exact_redteam_auth_matches: int = 0
    deterministic_replay_pass: bool = True
    visible_schema_pass: bool = True
    truth_separation_pass: bool = True
    provenance_pass: bool = True
    resource_pass: bool = True
    cleanup_pass: bool = True
    network_calls: int = 0
    model_calls: int = 0
    subprocess_calls: int = 0
    peak_rss_delta_bytes: int = 0
    failed_gate_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class AcceptanceDecision:
    verdict: str
    failed_gate_ids: tuple[str, ...]
    fingerprint: str


def validate_manifest(
    manifest: Mapping[str, Any],
    *,
    profile: Mapping[str, Any],
    registry: Mapping[str, Any],
    policy_fingerprint: str,
) -> ValidatedManifest:
    if not isinstance(manifest, Mapping):
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "MANIFEST_SCHEMA", "manifest must be object")
    _forbid_durable_keys(manifest, "manifest")
    _size_guard(manifest, "manifest")
    if frozenset(manifest.keys()) != REQUIRED_MANIFEST_KEYS:
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "MANIFEST_SCHEMA", "manifest field set drifted")
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "MANIFEST_SCHEMA", "manifest schema invalid")
    if _strict_bool(
        manifest.get("bots_direct_adapter_authorized"), "bots_direct_adapter_authorized"
    ):
        raise RealSourceAcceptanceError(
            FAIL_SECURITY, "BOTS_DIRECT_ADAPTER_ATTEMPT", "BOTS cannot be authorized"
        )

    lanes = _profile_lanes(profile)
    registry_index, registry_fp = _registry_index(registry)
    if _sha(manifest.get("registry_fingerprint"), "registry_fingerprint") != registry_fp:
        raise RealSourceAcceptanceError(
            FAIL_PROVENANCE, "REGISTRY_FINGERPRINT_MISMATCH", "registry fingerprint mismatch"
        )
    if _sha(manifest.get("policy_fingerprint"), "policy_fingerprint") != _sha(
        policy_fingerprint, "expected_policy_fingerprint"
    ):
        raise RealSourceAcceptanceError(
            FAIL_PROVENANCE, "POLICY_FINGERPRINT_MISMATCH", "policy fingerprint mismatch"
        )

    expected_raw = manifest.get("expected_lanes")
    if not isinstance(expected_raw, list) or not expected_raw:
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "MANIFEST_SCHEMA", "expected_lanes invalid")
    expected = tuple(_bounded(item, "expected_lane", 80) for item in expected_raw)
    if len(set(expected)) != len(expected) or set(expected) - set(lanes):
        raise RealSourceAcceptanceError(
            FAIL_SCHEMA, "SOURCE_FAMILY_MISMATCH", "expected_lanes invalid"
        )

    sources = manifest.get("sources")
    resource = profile["resource_contract"]
    if not isinstance(sources, list) or not sources:
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "MANIFEST_SCHEMA", "sources invalid")
    if len(sources) > _positive_int(resource.get("max_source_objects"), "max_source_objects"):
        raise RealSourceAcceptanceError(
            FAIL_RESOURCE, "RESOURCE_BOUND_EXCEEDED", "too many sources"
        )

    source_ids: set[str] = set()
    hit_lanes: set[str] = set()
    total_bytes = 0
    max_each = _positive_int(
        resource.get("max_bytes_per_source_object"), "max_bytes_per_source_object"
    )
    max_total = _positive_int(
        resource.get("max_total_bounded_input_bytes"), "max_total_bounded_input_bytes"
    )

    for source in sources:
        if not isinstance(source, Mapping) or frozenset(source.keys()) != REQUIRED_SOURCE_KEYS:
            raise RealSourceAcceptanceError(
                FAIL_SCHEMA, "MANIFEST_SCHEMA", "source field set drifted"
            )
        source_id = _bounded(source.get("source_id"), "source_id", 100)
        if source_id in source_ids:
            raise RealSourceAcceptanceError(FAIL_SCHEMA, "MANIFEST_SCHEMA", "duplicate source_id")
        source_ids.add(source_id)
        if _strict_bool(source.get("real_source"), f"{source_id}.real_source") is not True:
            raise RealSourceAcceptanceError(
                FAIL_SECURITY, "SYNTHETIC_SOURCE_MARKED_REAL", "real source flag is false"
            )
        dataset_id = _bounded(source.get("dataset_id"), f"{source_id}.dataset_id", 80)
        if dataset_id == "splunk-bots-v2":
            raise RealSourceAcceptanceError(
                FAIL_SECURITY, "BOTS_DIRECT_ADAPTER_ATTEMPT", "BOTS is excluded"
            )
        try:
            dataset = registry_index[dataset_id]
        except KeyError as exc:
            raise RealSourceAcceptanceError(
                FAIL_LICENSE, "DATASET_NOT_REVIEWED", f"{dataset_id} not reviewed"
            ) from exc
        license_raw = dataset.get("license")
        acquisition = dataset.get("acquisition")
        variants = dataset.get("variants")
        if not all(isinstance(x, Mapping) for x in (license_raw, acquisition, variants)):
            raise RealSourceAcceptanceError(FAIL_SCHEMA, "REGISTRY_SCHEMA", "dataset sections invalid")
        if dataset.get("status") != "enterprise_approved" or license_raw.get("commercial_use") is not True:
            raise RealSourceAcceptanceError(
                FAIL_LICENSE, "DATASET_NOT_ENTERPRISE_APPROVED", f"{dataset_id} is not eligible"
            )
        variant = _bounded(source.get("variant"), f"{source_id}.variant", 80)
        if variant not in variants:
            raise RealSourceAcceptanceError(
                FAIL_LICENSE, "VARIANT_NOT_REVIEWED", f"{dataset_id}/{variant} not reviewed"
            )
        family_value = source.get("source_family")
        family = _bounded(family_value, f"{source_id}.source_family", 40) if family_value else None
        adapter_id = _bounded(source.get("adapter_id"), f"{source_id}.adapter_id", 100)
        adapter_version = _bounded(
            source.get("adapter_version"), f"{source_id}.adapter_version", 100
        )

        lane_matches = []
        for lane_id, lane in lanes.items():
            if (
                lane.get("dataset_id") == dataset_id
                and lane.get("variant") == variant
                and lane.get("source_family") == family
                and lane.get("adapter_id") == adapter_id
                and lane.get("adapter_version") == adapter_version
            ):
                lane_matches.append(lane_id)
        if len(lane_matches) != 1:
            raise RealSourceAcceptanceError(
                FAIL_SCHEMA, "SOURCE_FAMILY_MISMATCH", f"{source_id} lane binding invalid"
            )
        hit_lanes.add(lane_matches[0])

        publisher_ref, host = _publisher_host(
            source.get("publisher_reference"), f"{source_id}.publisher_reference"
        )
        _, license_host = _publisher_host(license_raw.get("source"), "license.source")
        reviewed_hosts = {
            str(item).strip().casefold()
            for item in acquisition.get("allowlisted_hosts", [])
            if str(item).strip()
        }
        reviewed_hosts.add(license_host)
        if host not in reviewed_hosts:
            raise RealSourceAcceptanceError(
                FAIL_PROVENANCE, "UNREVIEWED_PUBLISHER_OR_MIRROR",
                f"{publisher_ref} is outside reviewed source boundary",
            )
        if _bounded(
            source.get("acquisition_mode"), f"{source_id}.acquisition_mode", 80
        ) != acquisition.get("mode"):
            raise RealSourceAcceptanceError(
                FAIL_PROVENANCE, "ACQUISITION_MODE_MISMATCH", "acquisition mode mismatch"
            )

        _sha(
            source.get("acquisition_receipt_fingerprint"),
            f"{source_id}.acquisition_receipt_fingerprint",
        )
        _sha(source.get("parent_source_sha256"), f"{source_id}.parent_source_sha256")
        _sha(source.get("bounded_source_sha256"), f"{source_id}.bounded_source_sha256")
        _logical_ref(source.get("parent_source_object_ref"), f"{source_id}.parent_source_object_ref")
        _logical_ref(source.get("bounded_source_object_ref"), f"{source_id}.bounded_source_object_ref")
        _logical_ref(source.get("provenance_ref"), f"{source_id}.provenance_ref")

        parent_size = _positive_int(
            source.get("parent_source_size_bytes"), f"{source_id}.parent_source_size_bytes"
        )
        bounded_size = _positive_int(
            source.get("bounded_source_size_bytes"), f"{source_id}.bounded_source_size_bytes"
        )
        if bounded_size > parent_size or bounded_size > max_each:
            raise RealSourceAcceptanceError(
                FAIL_RESOURCE, "RESOURCE_BOUND_EXCEEDED", f"{source_id} size exceeds budget"
            )
        total_bytes += bounded_size
        if total_bytes > max_total:
            raise RealSourceAcceptanceError(
                FAIL_RESOURCE, "RESOURCE_BOUND_EXCEEDED", "total source budget exceeded"
            )

        derivation = source.get("derivation")
        if derivation is not None:
            if not isinstance(derivation, Mapping) or derivation.get("method") != "record_aligned_slice":
                raise RealSourceAcceptanceError(
                    FAIL_PROVENANCE, "NONDETERMINISTIC_SLICE_DERIVATION",
                    f"{source_id} derivation invalid",
                )
            _bounded(derivation.get("selection_rule"), "derivation.selection_rule")
            _bounded(derivation.get("record_boundary_rule"), "derivation.record_boundary_rule")
            derivation_text = json.dumps(derivation, sort_keys=True).casefold()
            if "random" in derivation_text or "shuffle" in derivation_text:
                raise RealSourceAcceptanceError(
                    FAIL_PROVENANCE, "NONDETERMINISTIC_SLICE_DERIVATION",
                    f"{source_id} derivation is nondeterministic",
                )

    if set(expected) - hit_lanes:
        raise RealSourceAcceptanceError(
            FAIL_SCHEMA, "SOURCE_FAMILY_MISMATCH", "expected lane has no bound source"
        )

    identity = {
        "schema_version": MANIFEST_SCHEMA,
        "acceptance_id": _bounded(manifest.get("acceptance_id"), "acceptance_id", 128),
        "spec_version": _bounded(manifest.get("spec_version"), "spec_version", 128),
        "created_by_role": _bounded(manifest.get("created_by_role"), "created_by_role", 80),
        "registry_fingerprint": manifest["registry_fingerprint"],
        "policy_fingerprint": manifest["policy_fingerprint"],
        "sources": sources,
        "expected_lanes": list(expected),
        "bots_direct_adapter_authorized": False,
    }
    return ValidatedManifest(
        acceptance_id=identity["acceptance_id"],
        expected_lanes=expected,
        fingerprint=canonical_sha256(identity),
    )


def _decision(
    manifest: ValidatedManifest,
    profile: Mapping[str, Any],
    verdict: str,
    gates: Sequence[str],
) -> AcceptanceDecision:
    if verdict not in VERDICTS:
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "VERDICT_INVALID", "unsupported verdict")
    gate_tuple = tuple(sorted(set(str(item) for item in gates)))
    identity = {
        "contract_version": CONTRACT_VERSION,
        "manifest_fingerprint": manifest.fingerprint,
        "profile_fingerprint": canonical_sha256(profile),
        "verdict": verdict,
        "failed_gate_ids": list(gate_tuple),
    }
    return AcceptanceDecision(verdict, gate_tuple, canonical_sha256(identity))


def evaluate_coverage(
    manifest: ValidatedManifest,
    *,
    profile: Mapping[str, Any],
    observations: Sequence[LaneObservation],
) -> AcceptanceDecision:
    lanes = _profile_lanes(profile)
    by_lane: dict[str, LaneObservation] = {}
    for observation in observations:
        if observation.lane_id not in lanes or observation.lane_id in by_lane:
            raise RealSourceAcceptanceError(
                FAIL_SCHEMA, "OBSERVATION_LANE_INVALID", f"invalid observation lane {observation.lane_id}"
            )
        by_lane[observation.lane_id] = observation
    missing = set(manifest.expected_lanes) - set(by_lane)
    if missing:
        return _decision(
            manifest, profile, NOT_ENOUGH_REAL_SOURCE_EVIDENCE,
            [f"MISSING_OBSERVATION:{lane}" for lane in sorted(missing)],
        )

    resource = profile["resource_contract"]
    max_records = _positive_int(
        resource.get("max_visible_records_per_adapter_invocation"), "max_visible_records"
    )
    max_rss = _positive_int(
        resource.get("max_linux_peak_rss_delta_bytes"), "max_peak_rss"
    )
    fatal: list[tuple[str, str]] = []
    for lane_id in manifest.expected_lanes:
        observation = by_lane[lane_id]
        fatal.extend((FAIL_SECURITY, gate) for gate in observation.failed_gate_ids)
        if observation.network_calls:
            fatal.append((FAIL_SECURITY, "INTERNET_CALL_OBSERVED"))
        if observation.model_calls:
            fatal.append((FAIL_SECURITY, "MODEL_CALL_OBSERVED"))
        if observation.subprocess_calls:
            fatal.append((FAIL_SECURITY, "SUBPROCESS_CALL_OBSERVED"))
        if not observation.truth_separation_pass:
            fatal.append((FAIL_SECURITY, "HIDDEN_TRUTH_LEAKAGE"))
        if not observation.cleanup_pass:
            fatal.append((FAIL_SECURITY, "HARNESS_OWNED_RAW_LEFTOVER_AFTER_PASS"))
        if not observation.deterministic_replay_pass:
            fatal.append((FAIL_INTEGRITY, "DETERMINISTIC_REPLAY_MISMATCH"))
        if not observation.provenance_pass:
            fatal.append((FAIL_PROVENANCE, "PROVENANCE_INVALID"))
        if not observation.visible_schema_pass:
            fatal.append((FAIL_SCHEMA, "VISIBLE_SCHEMA_INVALID"))
        if (
            not observation.resource_pass
            or observation.peak_rss_delta_bytes > max_rss
            or (
                not bool(lanes[lane_id].get("scorer_only", False))
                and observation.valid_records > max_records
            )
        ):
            fatal.append((FAIL_RESOURCE, "RESOURCE_BOUND_EXCEEDED"))
    if fatal:
        order = {
            FAIL_SECURITY: 0, FAIL_INTEGRITY: 1, FAIL_PROVENANCE: 2,
            FAIL_LICENSE: 3, FAIL_SCHEMA: 4, FAIL_RESOURCE: 5,
        }
        fatal.sort(key=lambda item: (order.get(item[0], 99), item[1]))
        return _decision(manifest, profile, fatal[0][0], [gate for _, gate in fatal])

    coverage = profile["coverage_contract"]
    insufficient: list[str] = []
    if "cic_processed_ml" in manifest.expected_lanes:
        obs = by_lane["cic_processed_ml"]
        cic = coverage["cic_processed_ml"]
        if obs.valid_records < _positive_int(cic.get("minimum_valid_records"), "cic minimum"):
            insufficient.append("CIC_VALID_RECORDS_BELOW_MINIMUM")
        classes = {item.strip().casefold() for item in obs.truth_classes if item.strip()}
        if "benign" not in classes:
            insufficient.append("CIC_MISSING_BENIGN_TRUTH")
        if not any(item != "benign" for item in classes):
            insufficient.append("CIC_MISSING_NON_BENIGN_TRUTH")

    lane_to_profile = {
        "lanl_authentication": "lanl_authentication",
        "lanl_process": "lanl_process",
        "lanl_dns": "lanl_dns",
        "lanl_flow": "lanl_flow",
    }
    for lane_id, coverage_id in lane_to_profile.items():
        if lane_id in manifest.expected_lanes:
            minimum = _positive_int(
                coverage[coverage_id].get("minimum_valid_records"),
                f"{coverage_id}.minimum_valid_records",
            )
            if by_lane[lane_id].valid_records < minimum:
                insufficient.append(f"{coverage_id.upper()}_RECORDS_BELOW_MINIMUM")
    if "lanl_redteam_truth" in manifest.expected_lanes:
        minimum_matches = _positive_int(
            coverage["lanl_redteam_truth"].get("minimum_exact_auth_matches"),
            "lanl_redteam.minimum_exact_auth_matches",
        )
        if by_lane["lanl_redteam_truth"].exact_redteam_auth_matches < minimum_matches:
            insufficient.append("LANL_NO_EXACT_REAL_REDTEAM_AUTH_MATCH")

    if insufficient:
        return _decision(manifest, profile, NOT_ENOUGH_REAL_SOURCE_EVIDENCE, insufficient)
    return _decision(manifest, profile, PASS, ())


def validate_receipt(receipt: Mapping[str, Any]) -> str:
    if not isinstance(receipt, Mapping):
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "RECEIPT_SCHEMA", "receipt must be object")
    _forbid_durable_keys(receipt, "receipt")
    _size_guard(receipt, "receipt")
    if set(REQUIRED_RECEIPT_KEYS) - set(receipt):
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "RECEIPT_SCHEMA", "receipt fields missing")
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "RECEIPT_SCHEMA", "receipt schema invalid")
    head = _bounded(receipt.get("exact_head_sha"), "exact_head_sha", 64).lower()
    if len(head) not in {40, 64}:
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "GIT_SHA_FORMAT", "exact_head_sha invalid")
    try:
        int(head, 16)
    except ValueError as exc:
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "GIT_SHA_FORMAT", "exact_head_sha invalid") from exc
    for field in (
        "spec_fingerprint", "manifest_fingerprint", "publisher_reference_fingerprint",
        "acquisition_receipt_fingerprint", "parent_source_sha256",
        "bounded_source_sha256", "evidence_fingerprint",
    ):
        _sha(receipt.get(field), field)
    if receipt.get("truth_fingerprint") is not None:
        _sha(receipt.get("truth_fingerprint"), "truth_fingerprint")
    for field in (
        "records_seen", "records_emitted", "records_rejected",
        "truth_records_emitted", "network_calls", "model_calls",
        "subprocess_calls", "peak_rss_delta_bytes",
    ):
        _nonnegative_int(receipt.get(field), field)
    for field in (
        "real_source_verified", "deterministic_replay_pass", "visible_schema_pass",
        "truth_separation_pass", "provenance_pass", "resource_pass", "cleanup_pass",
    ):
        _strict_bool(receipt.get(field), field)
    verdict = _bounded(receipt.get("verdict"), "verdict", 64)
    if verdict not in VERDICTS:
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "VERDICT_INVALID", "receipt verdict invalid")
    failed = receipt.get("failed_gate_ids")
    if not isinstance(failed, list):
        raise RealSourceAcceptanceError(FAIL_SCHEMA, "RECEIPT_SCHEMA", "failed_gate_ids invalid")
    if verdict == PASS:
        if failed or receipt.get("real_source_verified") is not True:
            raise RealSourceAcceptanceError(
                FAIL_PROVENANCE, "PASS_CONTRACT_INVALID", "PASS receipt lacks clean real-source state"
            )
        for field in (
            "deterministic_replay_pass", "visible_schema_pass", "truth_separation_pass",
            "provenance_pass", "resource_pass", "cleanup_pass",
        ):
            if receipt.get(field) is not True:
                raise RealSourceAcceptanceError(
                    FAIL_SECURITY, "PASS_GATE_FALSE", f"PASS requires {field}=true"
                )
        if any(receipt.get(field) != 0 for field in ("network_calls", "model_calls", "subprocess_calls")):
            raise RealSourceAcceptanceError(
                FAIL_SECURITY, "PASS_AUTHORITY_NONZERO", "PASS requires zero external authority"
            )
    return canonical_sha256(receipt)
