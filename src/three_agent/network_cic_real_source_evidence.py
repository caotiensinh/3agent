from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote

from .network_cic_adapter import CIC_ADAPTER_ID, CIC_ADAPTER_VERSION
from .network_real_source_acceptance_contract import (
    FAIL_INTEGRITY,
    FAIL_PROVENANCE,
    FAIL_RESOURCE,
    FAIL_SCHEMA,
    FAIL_SECURITY,
    NOT_ENOUGH_REAL_SOURCE_EVIDENCE,
    PASS,
    canonical_sha256,
)
from .network_real_source_runner import OfflineRealSourceRunner, RealSourceRunnerError

PROFILE_SCHEMA = "workspace-network-v3-02e-cic-real-source-ci/v1"
ACQUISITION_SCHEMA = "workspace-network-cic-acquisition-receipt/v1"
RUNNER_OUTPUT_SCHEMA = "workspace-network-cic-runner-output/v1"
SUMMARY_SCHEMA = "workspace-network-cic-real-source-summary/v1"

EXPECTED_DATASET_ID = "cse-cic-ids2018"
EXPECTED_VARIANT = "processed-ml"
EXPECTED_BUCKET = "cse-cic-ids2018"
EXPECTED_REGION = "ca-central-1"
EXPECTED_OBJECT_KEY = (
    "Processed Traffic Data for ML Algorithms/"
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"
)
EXPECTED_ACQUISITION_MODE = "public_s3_unsigned"
EXPECTED_LANE = "cic_processed_ml"
EXPECTED_SOURCE_ID = "cic_thursday_01_03_2018"
EXPECTED_PARENT_LOGICAL_REF = (
    "cic/processed-ml/parent/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"
)
EXPECTED_BOUNDED_LOGICAL_REF = (
    "cic/processed-ml/bounded/"
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.first-250000.csv"
)
EXPECTED_PROVENANCE_REF = "provenance/cic-thursday-01-03-2018-acquisition.json"
PUBLISHER_HOST = "cse-cic-ids2018.s3.amazonaws.com"
MAX_SHA_CHUNK_BYTES = 1024 * 1024
MAX_PARENT_SOURCE_BYTES = 268435456
MAX_BOUNDED_DATA_RECORDS = 250_000
DERIVATION_METHOD = "record_aligned_slice"
DERIVATION_SELECTION_RULE = (
    "header_plus_first_250000_logical_data_records_in_original_order"
)
DERIVATION_RECORD_BOUNDARY_RULE = (
    "python_csv_reader_logical_records_then_csv_writer_lineterminator_lf"
)

FORBIDDEN_DURABLE_KEYS = frozenset(
    {
        "raw_line",
        "raw_record",
        "raw_payload",
        "csv_row",
        "label_values",
        "credential",
        "password",
        "token",
        "signed_url",
        "cookie",
    }
)
ALLOWED_OUTPUT_FILENAMES = frozenset(
    {
        "acquisition-receipt.json",
        "acceptance-manifest.json",
        "runner-receipt.json",
        "evidence-summary.json",
    }
)


class CICRealSourceEvidenceError(RuntimeError):
    def __init__(self, verdict: str, gate_id: str, message: str):
        self.verdict = verdict
        self.gate_id = gate_id
        super().__init__(f"{gate_id}: {message}")


@dataclass(frozen=True)
class PreparedCICEvidence:
    parent_source_path: Path
    bounded_source_path: Path
    parent_source_sha256: str
    parent_source_size_bytes: int
    bounded_source_sha256: str
    bounded_source_size_bytes: int
    bounded_data_record_count: int
    registry_fingerprint: str
    policy_fingerprint: str
    spec_fingerprint: str
    acquisition_receipt: dict[str, Any]
    manifest: dict[str, Any]


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CICRealSourceEvidenceError(
            FAIL_SCHEMA, "CIC_EVIDENCE_JSON_INVALID", "required JSON input is invalid"
        ) from exc
    if not isinstance(value, dict):
        raise CICRealSourceEvidenceError(
            FAIL_SCHEMA, "CIC_EVIDENCE_JSON_INVALID", "required JSON input must be object"
        )
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(MAX_SHA_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _clean_metadata(value: Any, field: str, *, max_len: int = 512) -> str:
    if not isinstance(value, str):
        raise CICRealSourceEvidenceError(
            FAIL_PROVENANCE, "CIC_S3_METADATA_INVALID", f"{field} must be string"
        )
    text = value.strip()
    if not text or len(text) > max_len or any(ord(ch) < 32 for ch in text):
        raise CICRealSourceEvidenceError(
            FAIL_PROVENANCE, "CIC_S3_METADATA_INVALID", f"{field} is invalid"
        )
    return text


def _exact_head(value: str) -> str:
    text = str(value or "").strip().lower()
    if len(text) not in {40, 64}:
        raise CICRealSourceEvidenceError(
            FAIL_SCHEMA, "EXACT_HEAD_LINEAGE_MISMATCH", "exact head SHA is invalid"
        )
    try:
        int(text, 16)
    except ValueError as exc:
        raise CICRealSourceEvidenceError(
            FAIL_SCHEMA, "EXACT_HEAD_LINEAGE_MISMATCH", "exact head SHA is invalid"
        ) from exc
    return text


def _profile_contract(
    profile: Mapping[str, Any],
) -> tuple[int, int, Mapping[str, Any]]:
    if profile.get("schema_version") != PROFILE_SCHEMA:
        raise CICRealSourceEvidenceError(
            FAIL_SCHEMA, "CIC_EVIDENCE_PROFILE_DRIFT", "profile schema mismatch"
        )
    source = profile.get("source")
    derivation = profile.get("bounded_derivation")
    binding = profile.get("production_binding")
    if (
        not isinstance(source, Mapping)
        or not isinstance(derivation, Mapping)
        or not isinstance(binding, Mapping)
    ):
        raise CICRealSourceEvidenceError(
            FAIL_SCHEMA, "CIC_EVIDENCE_PROFILE_DRIFT", "profile sections missing"
        )

    exact_source = {
        "dataset_id": EXPECTED_DATASET_ID,
        "variant": EXPECTED_VARIANT,
        "bucket": EXPECTED_BUCKET,
        "region": EXPECTED_REGION,
        "object_key": EXPECTED_OBJECT_KEY,
        "acquisition_mode": EXPECTED_ACQUISITION_MODE,
        "credentials_allowed": False,
        "mirrors_allowed": False,
        "signed_urls_allowed": False,
        "max_parent_source_bytes": MAX_PARENT_SOURCE_BYTES,
    }
    for field, expected in exact_source.items():
        if source.get(field) != expected:
            verdict = (
                FAIL_SECURITY
                if field
                in {
                    "bucket",
                    "object_key",
                    "credentials_allowed",
                    "mirrors_allowed",
                    "signed_urls_allowed",
                }
                else FAIL_SCHEMA
            )
            raise CICRealSourceEvidenceError(
                verdict, "CIC_EVIDENCE_PROFILE_DRIFT", f"source field {field} drifted"
            )

    if derivation.get("method") != DERIVATION_METHOD:
        raise CICRealSourceEvidenceError(
            FAIL_PROVENANCE,
            "BOUNDED_DERIVATION_INVALID",
            "derivation method drifted",
        )
    if derivation.get("selection_rule") != DERIVATION_SELECTION_RULE:
        raise CICRealSourceEvidenceError(
            FAIL_PROVENANCE,
            "BOUNDED_DERIVATION_INVALID",
            "derivation selection rule drifted",
        )
    if derivation.get("record_boundary_rule") != DERIVATION_RECORD_BOUNDARY_RULE:
        raise CICRealSourceEvidenceError(
            FAIL_PROVENANCE,
            "BOUNDED_DERIVATION_INVALID",
            "derivation record-boundary rule drifted",
        )
    if derivation.get("maximum_data_records") != MAX_BOUNDED_DATA_RECORDS:
        raise CICRealSourceEvidenceError(
            FAIL_RESOURCE,
            "BOUNDED_RECORD_LIMIT_EXCEEDED",
            "bounded record budget drifted",
        )
    for field in (
        "label_aware_selection_allowed",
        "random_selection_allowed",
        "shuffle_allowed",
        "wall_clock_selection_allowed",
    ):
        if derivation.get(field) is not False:
            raise CICRealSourceEvidenceError(
                FAIL_SECURITY,
                "LABEL_AWARE_SELECTION_ATTEMPT",
                f"unsafe derivation authority enabled: {field}",
            )

    if binding.get("adapter_id") != CIC_ADAPTER_ID:
        raise CICRealSourceEvidenceError(
            FAIL_SCHEMA, "ADAPTER_BINDING_DRIFT", "CIC adapter ID drifted"
        )
    if binding.get("adapter_version") != CIC_ADAPTER_VERSION:
        raise CICRealSourceEvidenceError(
            FAIL_SCHEMA, "ADAPTER_BINDING_DRIFT", "CIC adapter version drifted"
        )
    if binding.get("expected_lane") != EXPECTED_LANE:
        raise CICRealSourceEvidenceError(
            FAIL_SCHEMA, "ADAPTER_BINDING_DRIFT", "CIC lane binding drifted"
        )
    return MAX_PARENT_SOURCE_BYTES, MAX_BOUNDED_DATA_RECORDS, binding


def _publisher_reference() -> str:
    encoded_key = quote(EXPECTED_OBJECT_KEY, safe="/")
    return f"https://{PUBLISHER_HOST}/{encoded_key}"


def _forbid_durable_keys(value: Any, path: str = "root") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).strip().casefold()
            if normalized in FORBIDDEN_DURABLE_KEYS:
                raise CICRealSourceEvidenceError(
                    FAIL_SECURITY,
                    "RAW_SOURCE_IN_DURABLE_ARTIFACT",
                    f"forbidden durable key at {path}",
                )
            _forbid_durable_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _forbid_durable_keys(child, f"{path}[{index}]")


def _validate_regular_source(path: Path, maximum: int, *, size_gate: str) -> tuple[int, str]:
    if path.is_symlink():
        raise CICRealSourceEvidenceError(
            FAIL_SECURITY, "SOURCE_PATH_ESCAPE", "source must not be symlink"
        )
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CICRealSourceEvidenceError(
            FAIL_INTEGRITY,
            "SOURCE_DIGEST_OR_SIZE_BINDING_FAILED",
            "source is missing",
        ) from exc
    if not resolved.is_file():
        raise CICRealSourceEvidenceError(
            FAIL_SECURITY, "SOURCE_PATH_ESCAPE", "source must be regular file"
        )
    size = resolved.stat().st_size
    if size <= 0:
        raise CICRealSourceEvidenceError(
            FAIL_INTEGRITY,
            "SOURCE_DIGEST_OR_SIZE_BINDING_FAILED",
            "source is empty",
        )
    if size > maximum:
        raise CICRealSourceEvidenceError(
            FAIL_RESOURCE, size_gate, "source exceeds frozen byte bound"
        )
    return size, _sha256_file(resolved)


def derive_bounded_cic_source(
    *,
    parent_source_path: Path,
    bounded_source_path: Path,
    maximum_data_records: int = MAX_BOUNDED_DATA_RECORDS,
) -> int:
    if maximum_data_records != MAX_BOUNDED_DATA_RECORDS:
        raise CICRealSourceEvidenceError(
            FAIL_RESOURCE,
            "BOUNDED_RECORD_LIMIT_EXCEEDED",
            "bounded record budget may not drift",
        )
    parent = parent_source_path.resolve(strict=True)
    bounded = bounded_source_path.resolve(strict=False)
    if bounded == parent:
        raise CICRealSourceEvidenceError(
            FAIL_SECURITY, "SOURCE_PATH_ESCAPE", "bounded source may not replace parent"
        )
    if bounded_source_path.is_symlink():
        raise CICRealSourceEvidenceError(
            FAIL_SECURITY, "SOURCE_PATH_ESCAPE", "bounded source must not be symlink"
        )
    bounded.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    try:
        with parent.open("r", encoding="utf-8-sig", newline="") as source_handle, bounded.open(
            "w", encoding="utf-8", newline=""
        ) as bounded_handle:
            reader = csv.reader(source_handle)
            writer = csv.writer(bounded_handle, lineterminator="\n")
            try:
                header = next(reader)
            except StopIteration as exc:
                raise CICRealSourceEvidenceError(
                    FAIL_SCHEMA,
                    "BOUNDED_DERIVATION_INVALID",
                    "parent CSV is empty",
                ) from exc
            writer.writerow(header)
            for row in reader:
                if count >= maximum_data_records:
                    break
                writer.writerow(row)
                count += 1
    except CICRealSourceEvidenceError:
        if bounded.exists():
            bounded.unlink()
        raise
    except (OSError, UnicodeError, csv.Error) as exc:
        if bounded.exists():
            bounded.unlink()
        raise CICRealSourceEvidenceError(
            FAIL_SCHEMA,
            "BOUNDED_DERIVATION_INVALID",
            "parent CSV could not be deterministically sliced",
        ) from exc
    if count <= 0:
        if bounded.exists():
            bounded.unlink()
        raise CICRealSourceEvidenceError(
            FAIL_INTEGRITY,
            "BOUNDED_DERIVATION_INVALID",
            "bounded shard contains no data records",
        )
    if count > maximum_data_records:
        if bounded.exists():
            bounded.unlink()
        raise CICRealSourceEvidenceError(
            FAIL_RESOURCE,
            "BOUNDED_RECORD_LIMIT_EXCEEDED",
            "bounded shard exceeds record budget",
        )
    return count


def prepare_cic_evidence(
    *,
    parent_source_path: Path,
    bounded_source_path: Path,
    exact_head_sha: str,
    s3_etag: str,
    s3_last_modified: str,
    profile: Mapping[str, Any],
    registry: Mapping[str, Any],
    policy: Mapping[str, Any],
    spec_path: Path,
) -> PreparedCICEvidence:
    maximum_parent_bytes, maximum_records, _ = _profile_contract(profile)
    head = _exact_head(exact_head_sha)
    etag = _clean_metadata(s3_etag, "s3_etag", max_len=256)
    last_modified = _clean_metadata(
        s3_last_modified, "s3_last_modified", max_len=256
    )
    parent_size, parent_sha = _validate_regular_source(
        parent_source_path, maximum_parent_bytes, size_gate="SOURCE_TOO_LARGE"
    )
    bounded_count = derive_bounded_cic_source(
        parent_source_path=parent_source_path,
        bounded_source_path=bounded_source_path,
        maximum_data_records=maximum_records,
    )
    bounded_size, bounded_sha = _validate_regular_source(
        bounded_source_path, parent_size, size_gate="SOURCE_TOO_LARGE"
    )
    if bounded_count > maximum_records:
        raise CICRealSourceEvidenceError(
            FAIL_RESOURCE,
            "BOUNDED_RECORD_LIMIT_EXCEEDED",
            "bounded record count exceeds production adapter limit",
        )

    registry_fp = canonical_sha256(registry)
    policy_fp = canonical_sha256(policy)
    spec_fp = _sha256_file(spec_path)
    derivation = {
        "method": DERIVATION_METHOD,
        "selection_rule": DERIVATION_SELECTION_RULE,
        "record_boundary_rule": DERIVATION_RECORD_BOUNDARY_RULE,
    }
    receipt_identity = {
        "schema_version": ACQUISITION_SCHEMA,
        "dataset_id": EXPECTED_DATASET_ID,
        "variant": EXPECTED_VARIANT,
        "bucket": EXPECTED_BUCKET,
        "region": EXPECTED_REGION,
        "object_key": EXPECTED_OBJECT_KEY,
        "acquisition_mode": EXPECTED_ACQUISITION_MODE,
        "parent_source_size_bytes": parent_size,
        "parent_source_sha256": parent_sha,
        "bounded_source_size_bytes": bounded_size,
        "bounded_source_sha256": bounded_sha,
        "bounded_data_record_count": bounded_count,
        "derivation": derivation,
        "s3_etag": etag,
        "s3_last_modified": last_modified,
        "exact_head_sha": head,
        "registry_fingerprint": registry_fp,
        "policy_fingerprint": policy_fp,
    }
    acquisition_receipt = dict(receipt_identity)
    acquisition_receipt["receipt_fingerprint"] = canonical_sha256(receipt_identity)

    manifest = {
        "schema_version": "workspace-network-real-source-acceptance-manifest/v1",
        "acceptance_id": "v3-02e-cic-real-" + bounded_sha[7:23],
        "spec_version": "WORKSPACE_NETWORK_V3_02E_CIC_REAL_SOURCE_CI_SPEC_V1",
        "created_by_role": "CIC_REAL_SOURCE_CI",
        "registry_fingerprint": registry_fp,
        "policy_fingerprint": policy_fp,
        "sources": [
            {
                "source_id": EXPECTED_SOURCE_ID,
                "dataset_id": EXPECTED_DATASET_ID,
                "variant": EXPECTED_VARIANT,
                "source_family": None,
                "real_source": True,
                "publisher_reference": _publisher_reference(),
                "acquisition_mode": EXPECTED_ACQUISITION_MODE,
                "acquisition_receipt_fingerprint": acquisition_receipt[
                    "receipt_fingerprint"
                ],
                "parent_source_object_ref": EXPECTED_PARENT_LOGICAL_REF,
                "parent_source_sha256": parent_sha,
                "parent_source_size_bytes": parent_size,
                "bounded_source_object_ref": EXPECTED_BOUNDED_LOGICAL_REF,
                "bounded_source_sha256": bounded_sha,
                "bounded_source_size_bytes": bounded_size,
                "derivation": derivation,
                "adapter_id": CIC_ADAPTER_ID,
                "adapter_version": CIC_ADAPTER_VERSION,
                "provenance_ref": EXPECTED_PROVENANCE_REF,
            }
        ],
        "expected_lanes": [EXPECTED_LANE],
        "bots_direct_adapter_authorized": False,
    }
    _forbid_durable_keys(acquisition_receipt)
    _forbid_durable_keys(manifest)
    return PreparedCICEvidence(
        parent_source_path=parent_source_path.resolve(strict=True),
        bounded_source_path=bounded_source_path.resolve(strict=True),
        parent_source_sha256=parent_sha,
        parent_source_size_bytes=parent_size,
        bounded_source_sha256=bounded_sha,
        bounded_source_size_bytes=bounded_size,
        bounded_data_record_count=bounded_count,
        registry_fingerprint=registry_fp,
        policy_fingerprint=policy_fp,
        spec_fingerprint=spec_fp,
        acquisition_receipt=acquisition_receipt,
        manifest=manifest,
    )


def verify_prepared_source(prepared: PreparedCICEvidence) -> None:
    checks = (
        (
            prepared.parent_source_path,
            prepared.parent_source_size_bytes,
            prepared.parent_source_sha256,
        ),
        (
            prepared.bounded_source_path,
            prepared.bounded_source_size_bytes,
            prepared.bounded_source_sha256,
        ),
    )
    for path, expected_size, expected_sha in checks:
        if path.is_symlink() or not path.is_file():
            raise CICRealSourceEvidenceError(
                FAIL_INTEGRITY,
                "SOURCE_DIGEST_OR_SIZE_BINDING_FAILED",
                "prepared source disappeared or changed type",
            )
        current_size = path.stat().st_size
        current_sha = _sha256_file(path)
        if current_size != expected_size or current_sha != expected_sha:
            raise CICRealSourceEvidenceError(
                FAIL_INTEGRITY,
                "SOURCE_DIGEST_OR_SIZE_BINDING_FAILED",
                "source changed after acquisition/derivation binding",
            )


def _safe_write_json(output_dir: Path, filename: str, value: Any) -> None:
    if filename not in ALLOWED_OUTPUT_FILENAMES:
        raise CICRealSourceEvidenceError(
            FAIL_SECURITY,
            "RAW_SOURCE_IN_DURABLE_ARTIFACT",
            "output filename not allowed",
        )
    _forbid_durable_keys(value)
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / filename
    if target.is_symlink():
        raise CICRealSourceEvidenceError(
            FAIL_SECURITY,
            "RAW_SOURCE_IN_DURABLE_ARTIFACT",
            "output target may not be symlink",
        )
    target.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _lane_summary(result: Any) -> dict[str, Any]:
    lane = result.lane_executions[0]
    normalized_classes = {item.strip().casefold() for item in lane.truth_classes}
    return {
        "lane_id": lane.lane_id,
        "records_seen": lane.records_seen,
        "records_emitted": lane.records_emitted,
        "records_rejected": lane.records_rejected,
        "truth_records_emitted": lane.truth_records_emitted,
        "benign_truth_present": "benign" in normalized_classes,
        "non_benign_truth_present": any(
            item and item != "benign" for item in normalized_classes
        ),
        "evidence_fingerprint": lane.evidence_fingerprint,
        "truth_fingerprint": lane.truth_fingerprint,
    }


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def execute_cic_evidence(
    *,
    prepared: PreparedCICEvidence,
    exact_head_sha: str,
    source_root: Path,
    scratch_root: Path,
    output_dir: Path,
    acceptance_profile: Mapping[str, Any],
    runner_profile: Mapping[str, Any],
    runner_binding: Mapping[str, Any],
    registry: Mapping[str, Any],
) -> str:
    verify_prepared_source(prepared)
    source_root_resolved = source_root.resolve(strict=True)
    for source_path in (
        prepared.parent_source_path,
        prepared.bounded_source_path,
    ):
        if not _is_relative_to(source_path, source_root_resolved):
            raise CICRealSourceEvidenceError(
                FAIL_SECURITY,
                "SOURCE_PATH_ESCAPE",
                "prepared source resolves outside source root",
            )

    output_resolved = output_dir.resolve(strict=False)
    if _is_relative_to(output_resolved, source_root_resolved) or _is_relative_to(
        source_root_resolved, output_resolved
    ):
        raise CICRealSourceEvidenceError(
            FAIL_SECURITY,
            "RAW_SOURCE_IN_DURABLE_ARTIFACT",
            "output and source roots must be disjoint",
        )

    _safe_write_json(
        output_dir, "acquisition-receipt.json", prepared.acquisition_receipt
    )
    _safe_write_json(output_dir, "acceptance-manifest.json", prepared.manifest)

    runner = OfflineRealSourceRunner(profile=runner_profile, binding=runner_binding)
    try:
        result = runner.run(
            manifest=prepared.manifest,
            acceptance_profile=acceptance_profile,
            registry=registry,
            policy_fingerprint=prepared.policy_fingerprint,
            source_paths={EXPECTED_SOURCE_ID: prepared.bounded_source_path.name},
            authorized_root=source_root_resolved,
            scratch_root=scratch_root,
            exact_head_sha=_exact_head(exact_head_sha),
            spec_fingerprint=prepared.spec_fingerprint,
        )
    except RealSourceRunnerError as exc:
        failure = {
            "schema_version": RUNNER_OUTPUT_SCHEMA,
            "overall_verdict": exc.verdict,
            "failed_gate_id": exc.gate_id,
            "exact_head_sha": _exact_head(exact_head_sha),
            "parent_source_sha256": prepared.parent_source_sha256,
            "bounded_source_sha256": prepared.bounded_source_sha256,
        }
        _safe_write_json(output_dir, "runner-receipt.json", failure)
        _safe_write_json(
            output_dir,
            "evidence-summary.json",
            {
                "schema_version": SUMMARY_SCHEMA,
                "verdict": exc.verdict,
                "failed_gate_ids": [exc.gate_id],
                "exact_head_sha": _exact_head(exact_head_sha),
                "parent_source_sha256": prepared.parent_source_sha256,
                "bounded_source_sha256": prepared.bounded_source_sha256,
            },
        )
        raise CICRealSourceEvidenceError(
            exc.verdict, exc.gate_id, "production runner rejected real CIC source"
        ) from exc

    runner_output = {
        "schema_version": RUNNER_OUTPUT_SCHEMA,
        "overall_verdict": result.decision.verdict,
        "overall_failed_gate_ids": list(result.decision.failed_gate_ids),
        "runner_fingerprint": result.runner_fingerprint,
        "manifest_fingerprint": result.manifest_fingerprint,
        "exact_head_sha": result.exact_head_sha,
        "peak_rss_delta_bytes": result.peak_rss_delta_bytes,
        "cleanup_pass": result.cleanup_pass,
        "lane_receipts": list(result.receipts),
    }
    lane_summary = _lane_summary(result)
    summary = {
        "schema_version": SUMMARY_SCHEMA,
        "verdict": result.decision.verdict,
        "failed_gate_ids": list(result.decision.failed_gate_ids),
        "exact_head_sha": result.exact_head_sha,
        "parent_source_sha256": prepared.parent_source_sha256,
        "parent_source_size_bytes": prepared.parent_source_size_bytes,
        "bounded_source_sha256": prepared.bounded_source_sha256,
        "bounded_source_size_bytes": prepared.bounded_source_size_bytes,
        "bounded_data_record_count": prepared.bounded_data_record_count,
        "runner_fingerprint": result.runner_fingerprint,
        "manifest_fingerprint": result.manifest_fingerprint,
        "peak_rss_delta_bytes": result.peak_rss_delta_bytes,
        "cleanup_pass": result.cleanup_pass,
        "lane": lane_summary,
    }
    _safe_write_json(output_dir, "runner-receipt.json", runner_output)
    _safe_write_json(output_dir, "evidence-summary.json", summary)
    return result.decision.verdict


def _resolve_binding_path(repo_root: Path, binding: Mapping[str, Any], key: str) -> Path:
    value = binding.get(key)
    if not isinstance(value, str) or not value.strip():
        raise CICRealSourceEvidenceError(
            FAIL_SCHEMA, "CIC_EVIDENCE_PROFILE_DRIFT", f"binding {key} missing"
        )
    path = (repo_root / value).resolve(strict=True)
    try:
        path.relative_to(repo_root.resolve(strict=True))
    except ValueError as exc:
        raise CICRealSourceEvidenceError(
            FAIL_SECURITY, "SOURCE_PATH_ESCAPE", f"binding {key} escapes repo"
        ) from exc
    return path


def run_from_cli(args: argparse.Namespace) -> str:
    repo_root = Path(args.repo_root).resolve(strict=True)
    profile_path = Path(args.profile).resolve(strict=True)
    profile = _read_json(profile_path)
    _, _, binding = _profile_contract(profile)
    registry_path = _resolve_binding_path(repo_root, binding, "registry_path")
    policy_path = _resolve_binding_path(repo_root, binding, "policy_path")
    acceptance_profile_path = _resolve_binding_path(
        repo_root, binding, "acceptance_profile_path"
    )
    runner_profile_path = _resolve_binding_path(repo_root, binding, "runner_profile_path")
    runner_binding_path = _resolve_binding_path(repo_root, binding, "runner_binding_path")
    spec_path = (repo_root / str(profile.get("spec_path"))).resolve(strict=True)

    registry = _read_json(registry_path)
    policy = _read_json(policy_path)
    acceptance_profile = _read_json(acceptance_profile_path)
    runner_profile = _read_json(runner_profile_path)
    runner_binding = _read_json(runner_binding_path)

    source_root = Path(args.source_root).resolve(strict=True)
    parent_source_path = Path(args.parent_source).resolve(strict=True)
    bounded_source_path = Path(args.bounded_source).resolve(strict=False)
    scratch_root = Path(args.scratch_root)
    output_dir = Path(args.output_dir)
    scratch_root.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    prepared = prepare_cic_evidence(
        parent_source_path=parent_source_path,
        bounded_source_path=bounded_source_path,
        exact_head_sha=args.exact_head,
        s3_etag=args.s3_etag,
        s3_last_modified=args.s3_last_modified,
        profile=profile,
        registry=registry,
        policy=policy,
        spec_path=spec_path,
    )
    return execute_cic_evidence(
        prepared=prepared,
        exact_head_sha=args.exact_head,
        source_root=source_root,
        scratch_root=scratch_root,
        output_dir=output_dir,
        acceptance_profile=acceptance_profile,
        runner_profile=runner_profile,
        runner_binding=runner_binding,
        registry=registry,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline V3-02E CIC real publisher-source evidence executor"
    )
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--parent-source", required=True)
    parser.add_argument("--bounded-source", required=True)
    parser.add_argument("--scratch-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--exact-head", required=True)
    parser.add_argument("--s3-etag", required=True)
    parser.add_argument("--s3-last-modified", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        verdict = run_from_cli(args)
    except CICRealSourceEvidenceError as exc:
        print(
            json.dumps(
                {"verdict": exc.verdict, "gate_id": exc.gate_id},
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps({"verdict": verdict}, sort_keys=True))
    if verdict == PASS:
        return 0
    if verdict == NOT_ENOUGH_REAL_SOURCE_EVIDENCE:
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
