from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

POLICY_SCHEMA = "workspace-network-data-policy/v1"
REGISTRY_SCHEMA = "workspace-network-dataset-registry/v1"
PLAN_SCHEMA = "workspace-network-acquisition-plan/v1"

# Public datasets are source evidence. The primary enterprise purpose is to
# distill evidence-backed operational experience, not to retain raw logs.
PURPOSES = {"experience_extraction", "training", "evaluation", "research"}
ENTERPRISE_PURPOSES = {"experience_extraction", "training", "evaluation"}
STATUSES = {"enterprise_approved", "research_only", "review_required", "blocked"}


class NetworkDatasetPolicyError(ValueError):
    """Base error for invalid registry/policy material."""


class NetworkDatasetDenied(PermissionError):
    """A requested dataset action is denied by deterministic policy."""

    def __init__(self, reason_code: str, message: str):
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _positive_int(value: Any, field: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise NetworkDatasetPolicyError(f"{field} must be an integer") from exc
    if parsed <= 0:
        raise NetworkDatasetPolicyError(f"{field} must be > 0")
    return parsed


def _bounded_string(value: Any, field: str, *, max_len: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len:
        raise NetworkDatasetPolicyError(f"{field} must be a non-empty bounded string")
    return text


@dataclass(frozen=True)
class DatasetRecord:
    dataset_id: str
    name: str
    status: str
    commercial_use: bool | None
    license_source: str
    acquisition_mode: str
    allowlisted_hosts: tuple[str, ...]
    allowlisted_path_prefixes: tuple[str, ...]
    variants: dict[str, dict[str, Any]]
    raw: dict[str, Any]

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DatasetRecord":
        dataset_id = _bounded_string(value.get("id"), "dataset.id", max_len=80)
        name = _bounded_string(value.get("name"), "dataset.name")
        status = _bounded_string(value.get("status"), "dataset.status", max_len=40)
        if status not in STATUSES:
            raise NetworkDatasetPolicyError(
                f"dataset {dataset_id}: unsupported status {status!r}"
            )

        license_raw = value.get("license")
        if not isinstance(license_raw, dict):
            raise NetworkDatasetPolicyError(
                f"dataset {dataset_id}: license must be an object"
            )
        commercial_use = license_raw.get("commercial_use")
        if commercial_use not in {True, False, None}:
            raise NetworkDatasetPolicyError(
                f"dataset {dataset_id}: license.commercial_use must be true/false/null"
            )
        license_source = _bounded_string(
            license_raw.get("source"), f"{dataset_id}.license.source", max_len=512
        )
        if not license_source.startswith("https://"):
            raise NetworkDatasetPolicyError(
                f"dataset {dataset_id}: license source must use HTTPS"
            )

        acquisition = value.get("acquisition")
        if not isinstance(acquisition, dict):
            raise NetworkDatasetPolicyError(
                f"dataset {dataset_id}: acquisition must be an object"
            )
        acquisition_mode = _bounded_string(
            acquisition.get("mode"), f"{dataset_id}.acquisition.mode", max_len=80
        )
        if acquisition.get("credentials") not in {False, None}:
            raise NetworkDatasetPolicyError(
                f"dataset {dataset_id}: credentialed acquisition is unsupported in v1"
            )
        hosts = tuple(
            _bounded_string(x, f"{dataset_id}.allowlisted_host", max_len=253).casefold()
            for x in acquisition.get("allowlisted_hosts", [])
        )
        prefixes = tuple(
            _bounded_string(x, f"{dataset_id}.allowlisted_path_prefix", max_len=512)
            for x in acquisition.get("allowlisted_path_prefixes", [])
        )
        for prefix in prefixes:
            if not prefix.startswith("/"):
                raise NetworkDatasetPolicyError(
                    f"dataset {dataset_id}: path prefix must begin with '/'"
                )

        variants_raw = value.get("variants", {})
        if not isinstance(variants_raw, dict):
            raise NetworkDatasetPolicyError(
                f"dataset {dataset_id}: variants must be an object"
            )
        variants: dict[str, dict[str, Any]] = {}
        for variant_name, variant_value in variants_raw.items():
            variant = _bounded_string(
                variant_name, f"{dataset_id}.variant", max_len=80
            )
            if not isinstance(variant_value, dict):
                raise NetworkDatasetPolicyError(
                    f"dataset {dataset_id}: variant {variant} must be an object"
                )
            variant_purposes = variant_value.get("purpose", [])
            if not isinstance(variant_purposes, list):
                raise NetworkDatasetPolicyError(
                    f"dataset {dataset_id}: variant {variant}.purpose must be a list"
                )
            invalid = set(map(str, variant_purposes)) - PURPOSES
            if invalid:
                raise NetworkDatasetPolicyError(
                    f"dataset {dataset_id}: variant {variant} has invalid purposes {sorted(invalid)}"
                )
            variants[variant] = dict(variant_value)

        return cls(
            dataset_id=dataset_id,
            name=name,
            status=status,
            commercial_use=commercial_use,
            license_source=license_source,
            acquisition_mode=acquisition_mode,
            allowlisted_hosts=hosts,
            allowlisted_path_prefixes=prefixes,
            variants=variants,
            raw=dict(value),
        )


@dataclass(frozen=True)
class DataPlanePolicy:
    max_cache_bytes: int
    max_job_bytes: int
    max_objects_per_job: int
    allow_full_sync: bool
    enterprise_allowed_statuses: tuple[str, ...]
    research_allowed_statuses: tuple[str, ...]
    deny_statuses: tuple[str, ...]
    incoming_cache_root: Path
    normalized_staging_root: Path
    experience_root: Path
    candidate_skill_root: Path
    research_root: Path
    provenance_root: Path
    raw_logs_durable: bool
    normalized_events_durable: bool
    candidate_skills_auto_approve: bool
    minimum_independent_cases_for_pattern: int
    raw: dict[str, Any]

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DataPlanePolicy":
        if value.get("schema_version") != POLICY_SCHEMA:
            raise NetworkDatasetPolicyError(f"policy schema must be {POLICY_SCHEMA}")
        paths = value.get("paths")
        cache = value.get("cache")
        promotion = value.get("promotion")
        if not all(isinstance(x, dict) for x in (paths, cache, promotion)):
            raise NetworkDatasetPolicyError(
                "policy paths/cache/promotion sections must be objects"
            )
        if cache.get("raw_retention") != "ephemeral":
            raise NetworkDatasetPolicyError("v1 requires cache.raw_retention=ephemeral")
        if cache.get("normalized_retention") != "until_experience_extracted":
            raise NetworkDatasetPolicyError(
                "v1 requires cache.normalized_retention=until_experience_extracted"
            )
        if cache.get("eviction_policy") != "lru_unpinned":
            raise NetworkDatasetPolicyError(
                "v1 requires cache.eviction_policy=lru_unpinned"
            )
        if promotion.get("required_digest") != "sha256":
            raise NetworkDatasetPolicyError(
                "v1 requires promotion.required_digest=sha256"
            )
        if promotion.get("raw_logs_durable") is not False:
            raise NetworkDatasetPolicyError(
                "v1 forbids durable raw logs; promotion.raw_logs_durable must be false"
            )
        if promotion.get("normalized_events_durable") is not False:
            raise NetworkDatasetPolicyError(
                "v1 forbids normalized event retention after experience extraction"
            )
        if promotion.get("candidate_skills_auto_approve") is not False:
            raise NetworkDatasetPolicyError(
                "dataset-derived skills must remain candidates until independent review"
            )
        durable_outputs = set(map(str, promotion.get("durable_outputs", [])))
        required_outputs = {"experience_case", "evidence_pattern", "provenance"}
        if not required_outputs.issubset(durable_outputs):
            raise NetworkDatasetPolicyError(
                "promotion.durable_outputs must include experience_case, evidence_pattern and provenance"
            )

        def statuses(field: str) -> tuple[str, ...]:
            raw_statuses = promotion.get(field, [])
            if not isinstance(raw_statuses, list):
                raise NetworkDatasetPolicyError(f"promotion.{field} must be a list")
            parsed = tuple(str(x) for x in raw_statuses)
            invalid = set(parsed) - STATUSES
            if invalid:
                raise NetworkDatasetPolicyError(
                    f"promotion.{field} has invalid statuses {sorted(invalid)}"
                )
            return parsed

        parsed_paths: dict[str, Path] = {}
        for field in (
            "incoming_cache_root",
            "normalized_staging_root",
            "experience_root",
            "candidate_skill_root",
            "research_root",
            "provenance_root",
        ):
            raw_path = _bounded_string(paths.get(field), f"paths.{field}", max_len=512)
            path = Path(raw_path)
            if not path.is_absolute():
                raise NetworkDatasetPolicyError(f"paths.{field} must be absolute")
            parsed_paths[field] = path

        return cls(
            max_cache_bytes=_positive_int(cache.get("max_bytes"), "cache.max_bytes"),
            max_job_bytes=_positive_int(cache.get("max_job_bytes"), "cache.max_job_bytes"),
            max_objects_per_job=_positive_int(
                cache.get("max_objects_per_job"), "cache.max_objects_per_job"
            ),
            allow_full_sync=bool(cache.get("allow_full_sync", False)),
            enterprise_allowed_statuses=statuses("enterprise_allowed_statuses"),
            research_allowed_statuses=statuses("research_allowed_statuses"),
            deny_statuses=statuses("deny_statuses"),
            incoming_cache_root=parsed_paths["incoming_cache_root"],
            normalized_staging_root=parsed_paths["normalized_staging_root"],
            experience_root=parsed_paths["experience_root"],
            candidate_skill_root=parsed_paths["candidate_skill_root"],
            research_root=parsed_paths["research_root"],
            provenance_root=parsed_paths["provenance_root"],
            raw_logs_durable=False,
            normalized_events_durable=False,
            candidate_skills_auto_approve=False,
            minimum_independent_cases_for_pattern=max(
                2,
                _positive_int(
                    promotion.get("minimum_independent_cases_for_pattern", 2),
                    "promotion.minimum_independent_cases_for_pattern",
                ),
            ),
            raw=dict(value),
        )


@dataclass(frozen=True)
class AcquisitionPlan:
    dataset_id: str
    dataset_name: str
    purpose: str
    variant: str | None
    estimated_bytes: int
    object_count: int
    acquisition_mode: str
    allowlisted_hosts: tuple[str, ...]
    allowlisted_path_prefixes: tuple[str, ...]
    destination_class: str
    registry_fingerprint: str
    policy_fingerprint: str
    full_sync: bool
    schema_version: str = PLAN_SCHEMA

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "dataset_id": self.dataset_id,
            "dataset_name": self.dataset_name,
            "purpose": self.purpose,
            "variant": self.variant,
            "estimated_bytes": self.estimated_bytes,
            "object_count": self.object_count,
            "acquisition_mode": self.acquisition_mode,
            "allowlisted_hosts": list(self.allowlisted_hosts),
            "allowlisted_path_prefixes": list(self.allowlisted_path_prefixes),
            "destination_class": self.destination_class,
            "registry_fingerprint": self.registry_fingerprint,
            "policy_fingerprint": self.policy_fingerprint,
            "full_sync": self.full_sync,
        }


@dataclass(frozen=True)
class CacheEntry:
    key: str
    size_bytes: int
    last_access_epoch: float
    pinned: bool = False
    active: bool = False


class NetworkDatasetManager:
    """Deterministic dataset admission and bounded temporary-storage control plane.

    This class performs no network I/O. Public bytes are acquired only as source
    evidence. Raw and normalized logs are staging material; durable enterprise
    outputs are compact evidence-backed experience artifacts produced later.
    """

    def __init__(
        self,
        policy: DataPlanePolicy,
        datasets: dict[str, DatasetRecord],
        *,
        registry_fingerprint: str,
        policy_fingerprint: str,
    ):
        self.policy = policy
        self.datasets = datasets
        self.registry_fingerprint = registry_fingerprint
        self.policy_fingerprint = policy_fingerprint

    @classmethod
    def load(
        cls,
        *,
        policy_path: str | Path,
        registry_path: str | Path,
    ) -> "NetworkDatasetManager":
        policy_raw = json.loads(Path(policy_path).read_text(encoding="utf-8"))
        registry_raw = json.loads(Path(registry_path).read_text(encoding="utf-8"))
        if registry_raw.get("schema_version") != REGISTRY_SCHEMA:
            raise NetworkDatasetPolicyError(
                f"registry schema must be {REGISTRY_SCHEMA}"
            )
        dataset_values = registry_raw.get("datasets")
        if not isinstance(dataset_values, list):
            raise NetworkDatasetPolicyError("registry.datasets must be a list")

        records: dict[str, DatasetRecord] = {}
        for value in dataset_values:
            if not isinstance(value, dict):
                raise NetworkDatasetPolicyError(
                    "every registry dataset must be an object"
                )
            record = DatasetRecord.from_dict(value)
            if record.dataset_id in records:
                raise NetworkDatasetPolicyError(f"duplicate dataset id {record.dataset_id}")
            records[record.dataset_id] = record

        return cls(
            DataPlanePolicy.from_dict(policy_raw),
            records,
            registry_fingerprint=_canonical_digest(registry_raw),
            policy_fingerprint=_canonical_digest(policy_raw),
        )

    def list_datasets(self) -> tuple[DatasetRecord, ...]:
        return tuple(self.datasets[key] for key in sorted(self.datasets))

    def _record(self, dataset_id: str) -> DatasetRecord:
        try:
            return self.datasets[dataset_id]
        except KeyError as exc:
            raise NetworkDatasetDenied(
                "DATASET_UNKNOWN",
                f"dataset {dataset_id!r} is not in the reviewed registry",
            ) from exc

    def plan(
        self,
        dataset_id: str,
        *,
        purpose: str,
        estimated_bytes: int,
        object_count: int = 1,
        variant: str | None = None,
        full_sync: bool = False,
    ) -> AcquisitionPlan:
        purpose = str(purpose).strip().lower()
        if purpose not in PURPOSES:
            raise NetworkDatasetDenied(
                "PURPOSE_INVALID", f"purpose must be one of {sorted(PURPOSES)}"
            )
        estimated_bytes = _positive_int(estimated_bytes, "estimated_bytes")
        object_count = _positive_int(object_count, "object_count")
        record = self._record(dataset_id)

        if record.status in self.policy.deny_statuses:
            raise NetworkDatasetDenied(
                "DATASET_STATUS_DENIED",
                f"{record.dataset_id} is {record.status}; operator review is required",
            )

        if purpose in ENTERPRISE_PURPOSES:
            if record.status not in self.policy.enterprise_allowed_statuses:
                raise NetworkDatasetDenied(
                    "ENTERPRISE_USE_NOT_ALLOWED",
                    f"{record.dataset_id} status {record.status} is not approved for enterprise {purpose}",
                )
            if record.commercial_use is not True:
                raise NetworkDatasetDenied(
                    "COMMERCIAL_LICENSE_NOT_APPROVED",
                    f"{record.dataset_id} does not have an affirmative commercial-use decision",
                )
            destination_class = {
                "experience_extraction": "experience_staging",
                "training": "training_staging",
                "evaluation": "evaluation_staging",
            }[purpose]
        else:
            if record.status not in self.policy.research_allowed_statuses:
                raise NetworkDatasetDenied(
                    "RESEARCH_USE_NOT_ALLOWED",
                    f"{record.dataset_id} status {record.status} is not allowed for research",
                )
            destination_class = "research"

        if full_sync and not self.policy.allow_full_sync:
            raise NetworkDatasetDenied(
                "FULL_SYNC_DENIED",
                "whole-corpus synchronization is disabled; request bounded objects/shards",
            )
        if estimated_bytes > self.policy.max_job_bytes:
            raise NetworkDatasetDenied(
                "JOB_BYTE_BUDGET_EXCEEDED",
                f"estimated {estimated_bytes} bytes exceeds max_job_bytes={self.policy.max_job_bytes}",
            )
        if estimated_bytes > self.policy.max_cache_bytes:
            raise NetworkDatasetDenied(
                "CACHE_CAPACITY_EXCEEDED",
                f"estimated {estimated_bytes} bytes exceeds cache max_bytes={self.policy.max_cache_bytes}",
            )
        if object_count > self.policy.max_objects_per_job:
            raise NetworkDatasetDenied(
                "OBJECT_BUDGET_EXCEEDED",
                f"{object_count} objects exceeds max_objects_per_job={self.policy.max_objects_per_job}",
            )

        selected_variant: str | None = None
        if variant is not None:
            selected_variant = str(variant).strip()
            if selected_variant not in record.variants:
                raise NetworkDatasetDenied(
                    "VARIANT_UNKNOWN",
                    f"variant {selected_variant!r} is not registered for {record.dataset_id}",
                )
            allowed_purposes = set(
                map(str, record.variants[selected_variant].get("purpose", []))
            )
            if purpose not in allowed_purposes:
                raise NetworkDatasetDenied(
                    "VARIANT_PURPOSE_DENIED",
                    f"variant {selected_variant!r} is not approved for {purpose}",
                )
        elif record.variants:
            recommended = [
                name
                for name, meta in record.variants.items()
                if meta.get("recommended") is True
                and purpose in set(map(str, meta.get("purpose", [])))
            ]
            if len(recommended) == 1:
                selected_variant = recommended[0]

        if record.acquisition_mode == "blocked_until_review":
            raise NetworkDatasetDenied(
                "ACQUISITION_BLOCKED", "dataset acquisition is blocked until review"
            )
        if not record.allowlisted_hosts:
            raise NetworkDatasetDenied(
                "NO_NETWORK_ALLOWLIST",
                "dataset has no reviewed acquisition hostname allowlist",
            )

        return AcquisitionPlan(
            dataset_id=record.dataset_id,
            dataset_name=record.name,
            purpose=purpose,
            variant=selected_variant,
            estimated_bytes=estimated_bytes,
            object_count=object_count,
            acquisition_mode=record.acquisition_mode,
            allowlisted_hosts=record.allowlisted_hosts,
            allowlisted_path_prefixes=record.allowlisted_path_prefixes,
            destination_class=destination_class,
            registry_fingerprint=self.registry_fingerprint,
            policy_fingerprint=self.policy_fingerprint,
            full_sync=full_sync,
        )

    def plan_evictions(
        self,
        entries: Iterable[CacheEntry],
        *,
        incoming_bytes: int,
    ) -> tuple[str, ...]:
        incoming_bytes = _positive_int(incoming_bytes, "incoming_bytes")
        if incoming_bytes > self.policy.max_cache_bytes:
            raise NetworkDatasetDenied(
                "CACHE_CAPACITY_EXCEEDED",
                "single incoming object set is larger than total cache capacity",
            )

        normalized = tuple(entries)
        current_bytes = sum(max(0, int(item.size_bytes)) for item in normalized)
        overflow = current_bytes + incoming_bytes - self.policy.max_cache_bytes
        if overflow <= 0:
            return ()

        candidates = sorted(
            (item for item in normalized if not item.pinned and not item.active),
            key=lambda item: (item.last_access_epoch, item.key),
        )
        selected: list[str] = []
        reclaimed = 0
        for item in candidates:
            selected.append(item.key)
            reclaimed += max(0, int(item.size_bytes))
            if reclaimed >= overflow:
                return tuple(selected)

        raise NetworkDatasetDenied(
            "CACHE_EVICTION_INSUFFICIENT",
            "cache cannot free enough space without evicting pinned or active data",
        )

    def provenance_template(
        self,
        plan: AcquisitionPlan,
        *,
        source_object: str,
        source_sha256: str,
        source_size_bytes: int,
        fetched_at: str,
        parser_version: str,
        schema_version: str,
    ) -> dict[str, Any]:
        if not source_sha256.startswith("sha256:") or len(source_sha256) != 71:
            raise NetworkDatasetPolicyError(
                "source_sha256 must be a sha256:<64-hex> digest"
            )
        int(source_sha256.removeprefix("sha256:"), 16)
        record = self._record(plan.dataset_id)
        return {
            "schema_version": "workspace-network-provenance/v1",
            "dataset_id": plan.dataset_id,
            "purpose": plan.purpose,
            "variant": plan.variant,
            "destination_class": plan.destination_class,
            "source_object": _bounded_string(source_object, "source_object", max_len=1024),
            "source_sha256": source_sha256,
            "source_size_bytes": _positive_int(source_size_bytes, "source_size_bytes"),
            "fetched_at": _bounded_string(fetched_at, "fetched_at", max_len=80),
            "parser_version": _bounded_string(parser_version, "parser_version", max_len=128),
            "normalized_schema_version": _bounded_string(
                schema_version, "schema_version", max_len=128
            ),
            "registry_fingerprint": self.registry_fingerprint,
            "policy_fingerprint": self.policy_fingerprint,
            "license_source": record.license_source,
            "license_status": record.status,
            "raw_retention": "ephemeral",
            "normalized_retention": "until_experience_extracted",
        }
