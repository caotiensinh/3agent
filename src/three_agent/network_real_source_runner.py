from __future__ import annotations

import hashlib
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .network_cic_adapter import (
    CICAdapterResourceError,
    CICAdapterSchemaError,
    CSECICIDS2018Adapter,
)
from .network_corpus_adapter import (
    AdapterInputContract,
    EvidenceRecord,
    NetworkAdapterError,
    NetworkAdapterIntegrityError,
    NetworkAdapterSecurityError,
    TruthRecord,
    canonical_sha256 as adapter_canonical_sha256,
)
from .network_lanl_adapter import (
    LANLAdapterResourceError,
    LANLAdapterSchemaError,
    LANLAuthAdapter,
)
from .network_lanl_dns_adapter import LANLDNSAdapter
from .network_lanl_flow_adapter import LANLFlowAdapter
from .network_lanl_process_adapter import LANLProcessAdapter
from .network_lanl_redteam_matcher import LANLRedTeamTruthMatcher
from .network_real_source_acceptance_contract import (
    FAIL_INTEGRITY,
    FAIL_RESOURCE,
    FAIL_SCHEMA,
    FAIL_SECURITY,
    PASS,
    AcceptanceDecision,
    LaneObservation,
    RealSourceAcceptanceError,
    ValidatedManifest,
    canonical_sha256 as acceptance_canonical_sha256,
    evaluate_coverage,
    validate_manifest,
    validate_receipt,
)

RUNNER_PROFILE_SCHEMA = "workspace-network-real-source-runner-profile/v1"
RUNNER_BINDING_SCHEMA = "workspace-network-real-source-runner-binding/v1"
RUNNER_VERSION = "workspace-network-real-source-runner/0.1"
STREAM_SCHEMA = "workspace-network-record-stream-fingerprint/v1"


class RealSourceRunnerError(RuntimeError):
    """Stable runner failure without embedding untrusted source content."""

    def __init__(self, verdict: str, gate_id: str, message: str):
        self.verdict = verdict
        self.gate_id = gate_id
        super().__init__(f"{gate_id}: {message}")


@dataclass(frozen=True)
class VerifiedRunnerSource:
    source_id: str
    lane_id: str
    source_path: Path
    source_manifest: Mapping[str, Any]
    adapter_contract: AdapterInputContract


@dataclass(frozen=True)
class LaneExecution:
    lane_id: str
    inspection_fingerprint: str
    evidence_fingerprint: str | None
    truth_fingerprint: str | None
    records_seen: int
    records_emitted: int
    records_rejected: int
    truth_records_emitted: int
    first_error_code: str | None
    truth_classes: tuple[str, ...] = ()
    redteam_unmatched: int = 0
    redteam_ambiguous: int = 0
    redteam_exact_matches: int = 0
    auth_evidence: tuple[EvidenceRecord, ...] = ()

    def replay_identity(self) -> dict[str, Any]:
        return {
            "lane_id": self.lane_id,
            "inspection_fingerprint": self.inspection_fingerprint,
            "evidence_fingerprint": self.evidence_fingerprint,
            "truth_fingerprint": self.truth_fingerprint,
            "records_seen": self.records_seen,
            "records_emitted": self.records_emitted,
            "records_rejected": self.records_rejected,
            "truth_records_emitted": self.truth_records_emitted,
            "first_error_code": self.first_error_code,
            "truth_classes": list(self.truth_classes),
            "redteam_unmatched": self.redteam_unmatched,
            "redteam_ambiguous": self.redteam_ambiguous,
            "redteam_exact_matches": self.redteam_exact_matches,
        }


@dataclass(frozen=True)
class RunnerResult:
    acceptance_id: str
    manifest_fingerprint: str
    exact_head_sha: str
    lane_executions: tuple[LaneExecution, ...]
    observations: tuple[LaneObservation, ...]
    decision: AcceptanceDecision
    receipts: tuple[dict[str, Any], ...]
    peak_rss_delta_bytes: int
    cleanup_pass: bool
    runner_fingerprint: str


class _StreamFingerprint:
    def __init__(self, domain: str):
        if not isinstance(domain, str) or not domain.strip():
            raise RealSourceRunnerError(
                FAIL_SCHEMA, "RUNNER_STREAM_DOMAIN_INVALID", "stream domain invalid"
            )
        self._digest = hashlib.sha256()
        self._digest.update(STREAM_SCHEMA.encode("ascii"))
        self._digest.update(b"\0")
        self._digest.update(domain.strip().encode("utf-8"))
        self._digest.update(b"\0")
        self.count = 0

    def add_record(self, record: EvidenceRecord | TruthRecord) -> None:
        encoded = adapter_canonical_sha256(record.as_dict()).encode("ascii")
        self._digest.update(len(encoded).to_bytes(4, "big"))
        self._digest.update(encoded)
        self.count += 1

    def finish(self) -> str:
        final = self._digest.copy()
        final.update(b"\0count=")
        final.update(str(self.count).encode("ascii"))
        return "sha256:" + final.hexdigest()


def _sha256_file(path: Path, *, chunk_bytes: int) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_bytes)
            if not chunk:
                break
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _peak_rss_bytes() -> int | None:
    if not sys.platform.startswith("linux"):
        return None
    try:
        import resource
    except ImportError:
        return None
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _require_sha(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise RealSourceRunnerError(
            FAIL_SCHEMA, "RUNNER_BINDING_INVALID", f"{field} must be sha256"
        )
    text = value.strip().lower()
    if len(text) != 71 or not text.startswith("sha256:"):
        raise RealSourceRunnerError(
            FAIL_SCHEMA, "RUNNER_BINDING_INVALID", f"{field} must be sha256"
        )
    try:
        int(text[7:], 16)
    except ValueError as exc:
        raise RealSourceRunnerError(
            FAIL_SCHEMA, "RUNNER_BINDING_INVALID", f"{field} must be sha256"
        ) from exc
    return text


def _require_positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise RealSourceRunnerError(
            FAIL_SCHEMA, "RUNNER_BINDING_INVALID", f"{field} must be integer"
        )
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RealSourceRunnerError(
            FAIL_SCHEMA, "RUNNER_BINDING_INVALID", f"{field} must be integer"
        ) from exc
    if parsed <= 0:
        raise RealSourceRunnerError(
            FAIL_SCHEMA, "RUNNER_BINDING_INVALID", f"{field} must be > 0"
        )
    return parsed


def _require_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RealSourceRunnerError(
            FAIL_SCHEMA, "RUNNER_BINDING_INVALID", f"{field} must be object"
        )
    return value


class OfflineRealSourceRunner:
    """Offline deterministic V3-02E runner around reviewed production adapters."""

    _STATIC_RUNTIME_CLASSES = {
        "cic_processed_ml": CSECICIDS2018Adapter,
        "lanl_authentication": LANLAuthAdapter,
        "lanl_process": LANLProcessAdapter,
        "lanl_dns": LANLDNSAdapter,
        "lanl_flow": LANLFlowAdapter,
        "lanl_redteam_truth": LANLRedTeamTruthMatcher,
    }

    def __init__(self, *, profile: Mapping[str, Any], binding: Mapping[str, Any]):
        self.profile = dict(profile)
        self.binding = dict(binding)
        self._validate_runner_contracts()

    def _profile_lane_index(self) -> dict[str, Mapping[str, Any]]:
        return {
            str(item["lane_id"]): item
            for item in self.profile["authorized_lanes"]
            if isinstance(item, Mapping)
        }

    @staticmethod
    def _runtime_identity(runtime_class: type) -> tuple[str | None, str | None]:
        runtime_id = getattr(
            runtime_class, "adapter_id", getattr(runtime_class, "matcher_id", None)
        )
        version = getattr(
            runtime_class,
            "adapter_version",
            getattr(runtime_class, "matcher_version", None),
        )
        return runtime_id, version

    def _validate_runner_contracts(self) -> None:
        if self.profile.get("schema_version") != RUNNER_PROFILE_SCHEMA:
            raise RealSourceRunnerError(
                FAIL_SCHEMA, "RUNNER_PROFILE_INVALID", "runner profile schema invalid"
            )
        if self.binding.get("schema_version") != RUNNER_BINDING_SCHEMA:
            raise RealSourceRunnerError(
                FAIL_SCHEMA, "RUNNER_BINDING_INVALID", "runner binding schema invalid"
            )
        authority = _require_mapping(
            self.profile.get("execution_authority"), "execution_authority"
        )
        for field in (
            "network_calls",
            "model_calls",
            "subprocess_calls",
            "package_installs",
        ):
            if authority.get(field) != 0:
                raise RealSourceRunnerError(
                    FAIL_SECURITY, "RUNNER_AUTHORITY_INVALID", f"{field} must be zero"
                )
        if authority.get("dynamic_imports_from_manifest") is not False:
            raise RealSourceRunnerError(
                FAIL_SECURITY,
                "RUNNER_AUTHORITY_INVALID",
                "dynamic imports must be disabled",
            )
        if authority.get("recursive_source_discovery") is not False:
            raise RealSourceRunnerError(
                FAIL_SECURITY,
                "RUNNER_AUTHORITY_INVALID",
                "source discovery must be disabled",
            )

        lanes = self.profile.get("authorized_lanes")
        if not isinstance(lanes, list) or not lanes:
            raise RealSourceRunnerError(
                FAIL_SCHEMA, "RUNNER_PROFILE_INVALID", "authorized lanes missing"
            )
        actual_ids = {
            str(item.get("lane_id")) for item in lanes if isinstance(item, Mapping)
        }
        if actual_ids != set(self._STATIC_RUNTIME_CLASSES):
            raise RealSourceRunnerError(
                FAIL_SECURITY,
                "RUNNER_ADAPTER_NOT_AUTHORIZED",
                "static runner lane set drifted",
            )
        for lane_id, lane in self._profile_lane_index().items():
            runtime_class = self._STATIC_RUNTIME_CLASSES[lane_id]
            runtime_id, runtime_version = self._runtime_identity(runtime_class)
            if lane.get("runtime_class") != runtime_class.__name__:
                raise RealSourceRunnerError(
                    FAIL_SECURITY,
                    "RUNNER_ADAPTER_NOT_AUTHORIZED",
                    "runtime class binding drifted",
                )
            if lane.get("adapter_id") != runtime_id:
                raise RealSourceRunnerError(
                    FAIL_SECURITY,
                    "RUNNER_ADAPTER_NOT_AUTHORIZED",
                    "adapter ID binding drifted",
                )
            if lane.get("adapter_version") != runtime_version:
                raise RealSourceRunnerError(
                    FAIL_SCHEMA,
                    "RUNNER_ADAPTER_VERSION_MISMATCH",
                    "adapter version binding drifted",
                )

        exclusions = _require_mapping(
            self.profile.get("explicit_exclusions"), "explicit_exclusions"
        )
        if exclusions.get("splunk-bots-v2") != "BLOCKED_DEPENDENCY_COST":
            raise RealSourceRunnerError(
                FAIL_SECURITY,
                "BOTS_DIRECT_ADAPTER_ATTEMPT",
                "BOTS must remain blocked",
            )
        if self.binding.get("one_source_per_expected_lane") is not True:
            raise RealSourceRunnerError(
                FAIL_SCHEMA,
                "RUNNER_BINDING_INVALID",
                "V1 requires one source per lane",
            )

    def _preflight_manifest_authority(self, manifest: Mapping[str, Any]) -> None:
        """Reject unauthorized adapter authority before general manifest scoring.

        This is metadata-only. It intentionally does not touch source paths or bytes.
        """
        sources = manifest.get("sources") if isinstance(manifest, Mapping) else None
        if not isinstance(sources, list):
            return
        by_adapter = {
            str(lane.get("adapter_id")): lane
            for lane in self._profile_lane_index().values()
        }
        for source in sources:
            if not isinstance(source, Mapping):
                continue
            dataset_id = str(source.get("dataset_id") or "").strip()
            adapter_id = str(source.get("adapter_id") or "").strip()
            if dataset_id == "splunk-bots-v2" or adapter_id.startswith("splunk-bots"):
                raise RealSourceRunnerError(
                    FAIL_SECURITY,
                    "BOTS_DIRECT_ADAPTER_ATTEMPT",
                    "BOTS direct execution is blocked",
                )
            lane = by_adapter.get(adapter_id)
            if lane is None:
                raise RealSourceRunnerError(
                    FAIL_SECURITY,
                    "RUNNER_ADAPTER_NOT_AUTHORIZED",
                    "manifest requests an unauthorized adapter",
                )
            if source.get("adapter_version") != lane.get("adapter_version"):
                raise RealSourceRunnerError(
                    FAIL_SCHEMA,
                    "RUNNER_ADAPTER_VERSION_MISMATCH",
                    "manifest adapter version is not authorized",
                )

    def _manifest_source_lane(self, source: Mapping[str, Any]) -> str:
        matches: list[str] = []
        for lane_id, lane in self._profile_lane_index().items():
            if (
                lane.get("dataset_id") == source.get("dataset_id")
                and lane.get("variant") == source.get("variant")
                and lane.get("source_family") == source.get("source_family")
                and lane.get("adapter_id") == source.get("adapter_id")
                and lane.get("adapter_version") == source.get("adapter_version")
            ):
                matches.append(lane_id)
        if len(matches) != 1:
            raise RealSourceRunnerError(
                FAIL_SCHEMA,
                "RUNNER_SOURCE_MAPPING_INVALID",
                "source does not bind exactly one authorized lane",
            )
        return matches[0]

    def _validate_root(self, value: str | Path, gate: str) -> Path:
        raw = Path(value)
        if raw.is_symlink():
            raise RealSourceRunnerError(
                FAIL_SECURITY, gate, "root must not be a symlink"
            )
        try:
            resolved = raw.resolve(strict=True)
        except OSError as exc:
            raise RealSourceRunnerError(
                FAIL_SECURITY, gate, "root does not exist"
            ) from exc
        if not resolved.is_dir():
            raise RealSourceRunnerError(
                FAIL_SECURITY, gate, "root must be a directory"
            )
        return resolved

    def _prepare_roots(
        self,
        *,
        authorized_root: str | Path,
        scratch_root: str | Path,
        acceptance_id: str,
    ) -> tuple[Path, Path, Path]:
        source_root = self._validate_root(
            authorized_root, "RUNNER_AUTHORIZED_ROOT_INVALID"
        )
        scratch = self._validate_root(
            scratch_root, "RUNNER_SCRATCH_ROOT_INVALID"
        )
        if (
            source_root == scratch
            or _is_relative_to(scratch, source_root)
            or _is_relative_to(source_root, scratch)
        ):
            raise RealSourceRunnerError(
                FAIL_SECURITY,
                "RUNNER_SCRATCH_ROOT_INVALID",
                "source and scratch roots must be disjoint",
            )
        if any(scratch.iterdir()):
            raise RealSourceRunnerError(
                FAIL_SECURITY,
                "RUNNER_SCRATCH_ROOT_INVALID",
                "scratch root must be empty before run",
            )
        safe_id = acceptance_id.strip()
        allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
        if not safe_id or any(ch not in allowed for ch in safe_id):
            raise RealSourceRunnerError(
                FAIL_SCHEMA,
                "RUNNER_MANIFEST_INVALID",
                "acceptance_id is not filesystem-safe",
            )
        session = scratch / safe_id
        session.mkdir(mode=0o700)
        return source_root, scratch, session

    def _resolve_source_path(self, root: Path, relative_value: Any) -> Path:
        if not isinstance(relative_value, (str, Path)):
            raise RealSourceRunnerError(
                FAIL_SCHEMA,
                "RUNNER_SOURCE_MAPPING_INVALID",
                "source mapping path must be relative",
            )
        relative = Path(relative_value)
        if relative.is_absolute() or ".." in relative.parts:
            raise RealSourceRunnerError(
                FAIL_SECURITY,
                "RUNNER_SOURCE_ESCAPE",
                "source mapping escapes authorized root",
            )
        cursor = root
        for part in relative.parts:
            if part in {"", "."}:
                continue
            cursor = cursor / part
            if cursor.is_symlink():
                raise RealSourceRunnerError(
                    FAIL_SECURITY,
                    "RUNNER_SOURCE_SYMLINK",
                    "source path contains a symlink",
                )
        candidate = root / relative
        if candidate.is_symlink():
            raise RealSourceRunnerError(
                FAIL_SECURITY, "RUNNER_SOURCE_SYMLINK", "source must not be a symlink"
            )
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise RealSourceRunnerError(
                FAIL_INTEGRITY,
                "RUNNER_SOURCE_MISSING",
                "manifest-bound source is missing",
            ) from exc
        if not _is_relative_to(resolved, root):
            raise RealSourceRunnerError(
                FAIL_SECURITY,
                "RUNNER_SOURCE_ESCAPE",
                "source resolves outside authorized root",
            )
        if not resolved.is_file():
            raise RealSourceRunnerError(
                FAIL_SECURITY,
                "RUNNER_SOURCE_MAPPING_INVALID",
                "source must be a regular file",
            )
        return resolved

    def _bind_sources(
        self,
        *,
        manifest: Mapping[str, Any],
        validated: ValidatedManifest,
        source_root: Path,
        source_paths: Mapping[str, str | Path],
    ) -> dict[str, VerifiedRunnerSource]:
        sources_raw = manifest.get("sources")
        if not isinstance(sources_raw, list):
            raise RealSourceRunnerError(
                FAIL_SCHEMA, "RUNNER_MANIFEST_INVALID", "manifest sources missing"
            )
        source_by_id: dict[str, Mapping[str, Any]] = {}
        lane_to_source: dict[str, Mapping[str, Any]] = {}
        for raw in sources_raw:
            source = _require_mapping(raw, "manifest.source")
            source_id = str(source.get("source_id", "")).strip()
            if not source_id or source_id in source_by_id:
                raise RealSourceRunnerError(
                    FAIL_SCHEMA,
                    "RUNNER_SOURCE_MAPPING_INVALID",
                    "source IDs must be unique",
                )
            lane_id = self._manifest_source_lane(source)
            if lane_id in lane_to_source:
                raise RealSourceRunnerError(
                    FAIL_SCHEMA,
                    "RUNNER_SOURCE_MAPPING_INVALID",
                    "V1 permits one source per lane",
                )
            source_by_id[source_id] = source
            lane_to_source[lane_id] = source

        if set(source_paths) != set(source_by_id):
            raise RealSourceRunnerError(
                FAIL_SECURITY,
                "RUNNER_SOURCE_MAPPING_INVALID",
                "source mapping must exactly match manifest source IDs",
            )
        if set(validated.expected_lanes) != set(lane_to_source):
            raise RealSourceRunnerError(
                FAIL_SCHEMA,
                "RUNNER_SOURCE_MAPPING_INVALID",
                "expected lanes and source lanes differ",
            )
        if (
            "lanl_redteam_truth" in validated.expected_lanes
            and "lanl_authentication" not in validated.expected_lanes
        ):
            raise RealSourceRunnerError(
                FAIL_SCHEMA,
                "RUNNER_SOURCE_MAPPING_INVALID",
                "red-team lane requires authentication lane",
            )

        resource = _require_mapping(
            self.profile.get("resource_contract"), "resource_contract"
        )
        max_each = _require_positive_int(
            resource.get("max_bytes_per_source_object"), "max_bytes_per_source_object"
        )
        hash_chunk = _require_positive_int(
            resource.get("hash_chunk_bytes"), "hash_chunk_bytes"
        )
        bound: dict[str, VerifiedRunnerSource] = {}
        for lane_id in validated.expected_lanes:
            source = lane_to_source[lane_id]
            source_id = str(source["source_id"])
            path = self._resolve_source_path(source_root, source_paths[source_id])
            expected_size = _require_positive_int(
                source.get("bounded_source_size_bytes"), "bounded_source_size_bytes"
            )
            observed_size = path.stat().st_size
            if observed_size != expected_size:
                raise RealSourceRunnerError(
                    FAIL_INTEGRITY,
                    "RUNNER_SOURCE_SIZE_MISMATCH",
                    "bounded source size mismatch",
                )
            expected_sha = _require_sha(
                source.get("bounded_source_sha256"), "bounded_source_sha256"
            )
            if _sha256_file(path, chunk_bytes=hash_chunk) != expected_sha:
                raise RealSourceRunnerError(
                    FAIL_INTEGRITY,
                    "RUNNER_SOURCE_DIGEST_MISMATCH",
                    "bounded source digest mismatch",
                )
            if observed_size > max_each:
                raise RealSourceRunnerError(
                    FAIL_RESOURCE,
                    "RUNNER_ADAPTER_RESOURCE_FAILURE",
                    "source exceeds runner budget",
                )
            try:
                contract = AdapterInputContract.from_dict(
                    {
                        "dataset_id": source.get("dataset_id"),
                        "variant": source.get("variant"),
                        "source_object_ref": source.get("bounded_source_object_ref"),
                        "source_sha256": expected_sha,
                        "actual_source_size_bytes": observed_size,
                        "max_plan_bytes": max_each,
                        "acquisition_plan_fingerprint": validated.fingerprint,
                        "registry_fingerprint": manifest.get("registry_fingerprint"),
                        "policy_fingerprint": manifest.get("policy_fingerprint"),
                        "provenance_ref": source.get("provenance_ref"),
                        "adapter_version": source.get("adapter_version"),
                    }
                )
            except NetworkAdapterError as exc:
                raise RealSourceRunnerError(
                    FAIL_SCHEMA,
                    "RUNNER_BINDING_INVALID",
                    "adapter input binding invalid",
                ) from exc
            bound[lane_id] = VerifiedRunnerSource(
                source_id=source_id,
                lane_id=lane_id,
                source_path=path,
                source_manifest=source,
                adapter_contract=contract,
            )
        return bound

    def _new_adapter(self, lane_id: str):
        if lane_id not in self._STATIC_RUNTIME_CLASSES:
            raise RealSourceRunnerError(
                FAIL_SECURITY,
                "RUNNER_ADAPTER_NOT_AUTHORIZED",
                "lane adapter is not statically authorized",
            )
        runtime_class = self._STATIC_RUNTIME_CLASSES[lane_id]
        if lane_id == "lanl_redteam_truth":
            maximum = _require_positive_int(
                self.profile["resource_contract"].get(
                    "max_lanl_auth_evidence_for_redteam_matcher"
                ),
                "max_lanl_auth_evidence_for_redteam_matcher",
            )
            return runtime_class(max_auth_evidence=maximum)
        maximum = _require_positive_int(
            self.profile["resource_contract"].get(
                "max_visible_records_per_adapter_invocation"
            ),
            "max_visible_records_per_adapter_invocation",
        )
        return runtime_class(max_visible_records=maximum)

    def _execute_visible_lane(
        self, source: VerifiedRunnerSource, *, source_root: Path
    ) -> LaneExecution:
        adapter = self._new_adapter(source.lane_id)
        inspection = adapter.inspect(
            source.source_path,
            authorized_root=source_root,
            contract=source.adapter_contract,
        )
        evidence_hash = _StreamFingerprint(f"{source.lane_id}:evidence")
        truth_hash = _StreamFingerprint(f"{source.lane_id}:truth")
        truth_classes: set[str] = set()
        auth_evidence: list[EvidenceRecord] = []

        if source.lane_id == "cic_processed_ml":
            for output in adapter.iterate(source.source_path, inspection=inspection):
                evidence_hash.add_record(output.evidence)
                truth_hash.add_record(output.truth)
                attack_class = output.truth.truth_fields.get("attack_class")
                if isinstance(attack_class, str) and attack_class.strip():
                    truth_classes.add(attack_class.strip())
            counters = adapter.counters()
            return LaneExecution(
                lane_id=source.lane_id,
                inspection_fingerprint=inspection.inspection_fingerprint,
                evidence_fingerprint=evidence_hash.finish(),
                truth_fingerprint=truth_hash.finish(),
                records_seen=counters.records_seen,
                records_emitted=counters.records_emitted,
                records_rejected=counters.records_rejected,
                truth_records_emitted=counters.truth_records_emitted,
                first_error_code=counters.first_error_code,
                truth_classes=tuple(sorted(truth_classes, key=str.casefold)),
            )

        for evidence in adapter.iterate(source.source_path, inspection=inspection):
            evidence_hash.add_record(evidence)
            if source.lane_id == "lanl_authentication":
                auth_evidence.append(evidence)
        counters = adapter.counters()
        return LaneExecution(
            lane_id=source.lane_id,
            inspection_fingerprint=inspection.inspection_fingerprint,
            evidence_fingerprint=evidence_hash.finish(),
            truth_fingerprint=None,
            records_seen=counters.records_seen,
            records_emitted=counters.records_emitted,
            records_rejected=counters.records_rejected,
            truth_records_emitted=0,
            first_error_code=counters.first_error_code,
            auth_evidence=tuple(auth_evidence),
        )

    def _execute_redteam_lane(
        self,
        source: VerifiedRunnerSource,
        *,
        source_root: Path,
        auth: LaneExecution,
    ) -> LaneExecution:
        matcher = self._new_adapter(source.lane_id)
        inspection = matcher.inspect(
            source.source_path,
            authorized_root=source_root,
            contract=source.adapter_contract,
        )
        truth_hash = _StreamFingerprint(f"{source.lane_id}:truth")
        for truth in matcher.match(
            source.source_path,
            inspection=inspection,
            auth_evidence=auth.auth_evidence,
        ):
            truth_hash.add_record(truth)
        counters = matcher.counters()
        return LaneExecution(
            lane_id=source.lane_id,
            inspection_fingerprint=inspection.inspection_fingerprint,
            evidence_fingerprint=None,
            truth_fingerprint=truth_hash.finish(),
            records_seen=counters.records_seen,
            records_emitted=0,
            records_rejected=counters.records_rejected,
            truth_records_emitted=counters.truth_records_emitted,
            first_error_code=counters.first_error_code,
            redteam_unmatched=counters.unmatched_truth,
            redteam_ambiguous=counters.ambiguous_truth,
            redteam_exact_matches=counters.truth_records_emitted,
        )

    def _execute_pass(
        self,
        *,
        validated: ValidatedManifest,
        bound: Mapping[str, VerifiedRunnerSource],
        source_root: Path,
    ) -> dict[str, LaneExecution]:
        ordered = [
            str(item["lane_id"])
            for item in self.profile["authorized_lanes"]
            if str(item["lane_id"]) in validated.expected_lanes
        ]
        output: dict[str, LaneExecution] = {}
        try:
            for lane_id in ordered:
                if lane_id == "lanl_redteam_truth":
                    auth = output.get("lanl_authentication")
                    if auth is None:
                        raise RealSourceRunnerError(
                            FAIL_SCHEMA,
                            "RUNNER_SOURCE_MAPPING_INVALID",
                            "red-team execution lacks auth evidence",
                        )
                    output[lane_id] = self._execute_redteam_lane(
                        bound[lane_id], source_root=source_root, auth=auth
                    )
                else:
                    output[lane_id] = self._execute_visible_lane(
                        bound[lane_id], source_root=source_root
                    )
        except RealSourceRunnerError:
            raise
        except NetworkAdapterSecurityError as exc:
            raise RealSourceRunnerError(
                FAIL_SECURITY,
                "RUNNER_SOURCE_ESCAPE",
                "production adapter rejected source boundary",
            ) from exc
        except NetworkAdapterIntegrityError as exc:
            raise RealSourceRunnerError(
                FAIL_INTEGRITY,
                "RUNNER_ADAPTER_INTEGRITY_FAILURE",
                "production adapter integrity check failed",
            ) from exc
        except (CICAdapterResourceError, LANLAdapterResourceError) as exc:
            raise RealSourceRunnerError(
                FAIL_RESOURCE,
                "RUNNER_ADAPTER_RESOURCE_FAILURE",
                "production adapter resource contract failed",
            ) from exc
        except (
            CICAdapterSchemaError,
            LANLAdapterSchemaError,
            NetworkAdapterError,
        ) as exc:
            raise RealSourceRunnerError(
                FAIL_SCHEMA,
                "RUNNER_ADAPTER_SCHEMA_FAILURE",
                "production adapter schema contract failed",
            ) from exc
        return output

    def _compare_replay(
        self,
        first: Mapping[str, LaneExecution],
        second: Mapping[str, LaneExecution],
    ) -> None:
        if set(first) != set(second):
            raise RealSourceRunnerError(
                FAIL_INTEGRITY, "RUNNER_REPLAY_MISMATCH", "replay lane set differs"
            )
        for lane_id in sorted(first):
            if first[lane_id].replay_identity() != second[lane_id].replay_identity():
                raise RealSourceRunnerError(
                    FAIL_INTEGRITY,
                    "RUNNER_REPLAY_MISMATCH",
                    f"replay differs for {lane_id}",
                )

    def _lane_observations(
        self,
        executions: Mapping[str, LaneExecution],
        *,
        peak_rss_delta_bytes: int,
    ) -> tuple[LaneObservation, ...]:
        return tuple(
            LaneObservation(
                lane_id=lane_id,
                valid_records=execution.records_emitted,
                truth_classes=execution.truth_classes,
                exact_redteam_auth_matches=execution.redteam_exact_matches,
                deterministic_replay_pass=True,
                visible_schema_pass=True,
                truth_separation_pass=True,
                provenance_pass=True,
                resource_pass=True,
                cleanup_pass=True,
                network_calls=0,
                model_calls=0,
                subprocess_calls=0,
                peak_rss_delta_bytes=peak_rss_delta_bytes,
                failed_gate_ids=(),
            )
            for lane_id, execution in executions.items()
        )

    def _build_lane_receipt(
        self,
        *,
        exact_head_sha: str,
        spec_fingerprint: str,
        validated: ValidatedManifest,
        source: VerifiedRunnerSource,
        execution: LaneExecution,
        peak_rss_delta_bytes: int,
    ) -> dict[str, Any]:
        publisher_fp = acceptance_canonical_sha256(
            {"publisher_reference": source.source_manifest.get("publisher_reference")}
        )
        receipt = {
            "schema_version": "workspace-network-real-source-acceptance-receipt/v1",
            "acceptance_id": validated.acceptance_id,
            "exact_head_sha": exact_head_sha,
            "spec_fingerprint": spec_fingerprint,
            "manifest_fingerprint": validated.fingerprint,
            "dataset_id": source.source_manifest.get("dataset_id"),
            "variant": source.source_manifest.get("variant"),
            "source_family": source.source_manifest.get("source_family"),
            "real_source_verified": True,
            "publisher_reference_fingerprint": publisher_fp,
            "acquisition_receipt_fingerprint": source.source_manifest.get(
                "acquisition_receipt_fingerprint"
            ),
            "parent_source_sha256": source.source_manifest.get("parent_source_sha256"),
            "bounded_source_sha256": source.source_manifest.get("bounded_source_sha256"),
            "adapter_id": source.source_manifest.get("adapter_id"),
            "adapter_version": source.source_manifest.get("adapter_version"),
            "records_seen": execution.records_seen,
            "records_emitted": execution.records_emitted,
            "records_rejected": execution.records_rejected,
            "truth_records_emitted": execution.truth_records_emitted,
            "evidence_fingerprint": execution.evidence_fingerprint
            or acceptance_canonical_sha256(
                {"lane": execution.lane_id, "evidence": "none"}
            ),
            "truth_fingerprint": execution.truth_fingerprint,
            "deterministic_replay_pass": True,
            "visible_schema_pass": True,
            "truth_separation_pass": True,
            "provenance_pass": True,
            "resource_pass": True,
            "cleanup_pass": True,
            "network_calls": 0,
            "model_calls": 0,
            "subprocess_calls": 0,
            "peak_rss_delta_bytes": peak_rss_delta_bytes,
            "verdict": PASS,
            "failed_gate_ids": [],
        }
        validate_receipt(receipt)
        return receipt

    def run(
        self,
        *,
        manifest: Mapping[str, Any],
        acceptance_profile: Mapping[str, Any],
        registry: Mapping[str, Any],
        policy_fingerprint: str,
        source_paths: Mapping[str, str | Path],
        authorized_root: str | Path,
        scratch_root: str | Path,
        exact_head_sha: str,
        spec_fingerprint: str,
    ) -> RunnerResult:
        # Authority preflight and manifest validation are metadata-only. No source
        # bytes are opened before both checks complete.
        self._preflight_manifest_authority(manifest)
        try:
            validated = validate_manifest(
                manifest,
                profile=acceptance_profile,
                registry=registry,
                policy_fingerprint=policy_fingerprint,
            )
        except RealSourceAcceptanceError as exc:
            raise RealSourceRunnerError(
                exc.verdict,
                "RUNNER_MANIFEST_INVALID",
                "acceptance manifest rejected",
            ) from exc

        _require_sha(spec_fingerprint, "spec_fingerprint")
        if not isinstance(exact_head_sha, str) or len(exact_head_sha.strip()) not in {
            40,
            64,
        }:
            raise RealSourceRunnerError(
                FAIL_SCHEMA, "RUNNER_BINDING_INVALID", "exact_head_sha invalid"
            )
        try:
            int(exact_head_sha.strip(), 16)
        except ValueError as exc:
            raise RealSourceRunnerError(
                FAIL_SCHEMA, "RUNNER_BINDING_INVALID", "exact_head_sha invalid"
            ) from exc

        source_root, scratch, session = self._prepare_roots(
            authorized_root=authorized_root,
            scratch_root=scratch_root,
            acceptance_id=validated.acceptance_id,
        )
        error: BaseException | None = None
        result_payload: tuple[
            dict[str, VerifiedRunnerSource],
            dict[str, LaneExecution],
            int,
        ] | None = None
        before_rss = _peak_rss_bytes()
        try:
            bound = self._bind_sources(
                manifest=manifest,
                validated=validated,
                source_root=source_root,
                source_paths=source_paths,
            )
            first = self._execute_pass(
                validated=validated, bound=bound, source_root=source_root
            )
            second = self._execute_pass(
                validated=validated, bound=bound, source_root=source_root
            )
            self._compare_replay(first, second)
            after_rss = _peak_rss_bytes()
            if before_rss is None or after_rss is None:
                raise RealSourceRunnerError(
                    FAIL_RESOURCE,
                    "RUNNER_RESOURCE_MEASUREMENT_UNAVAILABLE",
                    "Linux peak RSS measurement is required",
                )
            peak_delta = max(0, after_rss - before_rss)
            maximum = _require_positive_int(
                self.profile["resource_contract"].get(
                    "max_linux_peak_rss_delta_bytes"
                ),
                "max_linux_peak_rss_delta_bytes",
            )
            if peak_delta > maximum:
                raise RealSourceRunnerError(
                    FAIL_RESOURCE,
                    "RUNNER_ADAPTER_RESOURCE_FAILURE",
                    "runner peak RSS budget exceeded",
                )
            result_payload = (bound, first, peak_delta)
        except BaseException as exc:
            error = exc
        finally:
            cleanup_error = False
            try:
                if session.exists():
                    shutil.rmtree(session)
                if any(scratch.iterdir()):
                    cleanup_error = True
            except OSError:
                cleanup_error = True
            if cleanup_error:
                error = RealSourceRunnerError(
                    FAIL_SECURITY,
                    "RUNNER_CLEANUP_FAILED",
                    "runner-owned scratch cleanup failed",
                )

        if error is not None:
            if isinstance(error, RealSourceRunnerError):
                raise error
            raise RealSourceRunnerError(
                FAIL_SCHEMA,
                "RUNNER_ADAPTER_SCHEMA_FAILURE",
                "unexpected runner execution failure",
            ) from error
        if result_payload is None:
            raise RealSourceRunnerError(
                FAIL_SCHEMA,
                "RUNNER_ADAPTER_SCHEMA_FAILURE",
                "runner produced no result",
            )

        bound, executions, peak_delta = result_payload
        observations = self._lane_observations(
            executions, peak_rss_delta_bytes=peak_delta
        )
        decision = evaluate_coverage(
            validated, profile=acceptance_profile, observations=observations
        )
        receipts = tuple(
            self._build_lane_receipt(
                exact_head_sha=exact_head_sha.strip().lower(),
                spec_fingerprint=spec_fingerprint,
                validated=validated,
                source=bound[lane_id],
                execution=executions[lane_id],
                peak_rss_delta_bytes=peak_delta,
            )
            for lane_id in validated.expected_lanes
        )

        # Content identity excludes runtime resource measurements and receipt
        # hashes. Evidence/truth/replay identity remains deterministic.
        deterministic_identity = {
            "runner_version": RUNNER_VERSION,
            "acceptance_id": validated.acceptance_id,
            "manifest_fingerprint": validated.fingerprint,
            "exact_head_sha": exact_head_sha.strip().lower(),
            "lane_replay_identities": [
                executions[lane].replay_identity() for lane in validated.expected_lanes
            ],
            "decision_fingerprint": decision.fingerprint,
            "cleanup_pass": True,
        }
        return RunnerResult(
            acceptance_id=validated.acceptance_id,
            manifest_fingerprint=validated.fingerprint,
            exact_head_sha=exact_head_sha.strip().lower(),
            lane_executions=tuple(
                executions[lane] for lane in validated.expected_lanes
            ),
            observations=observations,
            decision=decision,
            receipts=receipts,
            peak_rss_delta_bytes=peak_delta,
            cleanup_pass=True,
            runner_fingerprint=acceptance_canonical_sha256(deterministic_identity),
        )
