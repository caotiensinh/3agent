from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

EVIDENCE_SCHEMA = "workspace-network-evidence-record/v1"
TRUTH_SCHEMA = "workspace-network-truth-record/v1"
INSPECTION_SCHEMA = "workspace-network-adapter-inspection/v1"
RECEIPT_SCHEMA = "workspace-network-adapter-receipt/v1"

VERDICTS = {
    "PASS",
    "FAIL_SCHEMA",
    "FAIL_INTEGRITY",
    "FAIL_SECURITY",
    "FAIL_PROVENANCE",
    "FAIL_LICENSE",
    "FAIL_RESOURCE",
    "BLOCKED_DEPENDENCY_COST",
    "NOT_ENOUGH_REAL_SOURCE_EVIDENCE",
}

FORBIDDEN_VISIBLE_KEYS = {
    "label",
    "labels",
    "attack_label",
    "attack_labels",
    "class_label",
    "ground_truth",
    "hidden_ground_truth",
    "truth",
    "truth_class",
    "truth_fields",
    "answer",
    "answer_key",
    "expected_answer",
    "expected_root_cause",
    "expected_attack_path",
    "expected_forensic_findings",
    "verified_remediation",
    "remediation_truth",
    "red_team",
    "redteam",
    "red_team_flag",
    "is_attack",
}

MAX_RECORD_BYTES = 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024


class NetworkAdapterError(ValueError):
    """Base error for invalid adapter contracts or canonical records."""


class NetworkAdapterIntegrityError(NetworkAdapterError):
    """Staged source bytes do not match their bound plan/provenance."""


class NetworkAdapterSecurityError(NetworkAdapterError):
    """Visible evidence or source-path handling violates a trust boundary."""


def canonical_sha256(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _bounded(value: Any, field: str, *, max_len: int = 512) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len:
        raise NetworkAdapterError(f"{field} must be a non-empty bounded string")
    return text


def _sha256(value: Any, field: str = "sha256") -> str:
    text = _bounded(value, field, max_len=71).lower()
    if len(text) != 71 or not text.startswith("sha256:"):
        raise NetworkAdapterError(f"{field} must be sha256:<64-hex>")
    try:
        int(text[7:], 16)
    except ValueError as exc:
        raise NetworkAdapterError(f"{field} must be sha256:<64-hex>") from exc
    return text


def _git_sha(value: Any, field: str = "exact_head_sha") -> str:
    text = _bounded(value, field, max_len=64).lower()
    if len(text) not in {40, 64}:
        raise NetworkAdapterError(f"{field} must be a 40- or 64-hex Git object id")
    try:
        int(text, 16)
    except ValueError as exc:
        raise NetworkAdapterError(f"{field} must be hexadecimal") from exc
    return text


def _positive_int(value: Any, field: str, *, allow_zero: bool = False) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise NetworkAdapterError(f"{field} must be an integer") from exc
    minimum = 0 if allow_zero else 1
    if parsed < minimum:
        op = ">= 0" if allow_zero else "> 0"
        raise NetworkAdapterError(f"{field} must be {op}")
    return parsed


def _refs(
    value: Iterable[Any] | None,
    field: str,
    *,
    max_items: int = 256,
) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise NetworkAdapterError(f"{field} must be a list")
    items = tuple(_bounded(item, field, max_len=256) for item in value)
    if len(items) > max_items:
        raise NetworkAdapterError(f"{field} exceeds {max_items} items")
    if len(set(items)) != len(items):
        raise NetworkAdapterError(f"{field} must not contain duplicates")
    return items


def _logical_ref(value: Any, field: str) -> str:
    text = _bounded(value, field, max_len=512)
    if "\\" in text or text.startswith("/") or text.startswith("~"):
        raise NetworkAdapterError(
            f"{field} must be a host-independent logical reference"
        )
    parts = text.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise NetworkAdapterError(f"{field} contains an unsafe path segment")
    if ":" in parts[0]:
        raise NetworkAdapterError(f"{field} must not contain a drive/scheme prefix")
    return text


def _reject_visible_truth(value: Any, path: str = "observation_fields") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).strip().casefold()
            if normalized in FORBIDDEN_VISIBLE_KEYS:
                raise NetworkAdapterSecurityError(
                    f"truth/label field {key!r} is forbidden in visible evidence at {path}"
                )
            _reject_visible_truth(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_visible_truth(child, f"{path}[{index}]")


def _canonical_json_object(
    value: Any,
    field: str,
    *,
    forbid_truth: bool,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise NetworkAdapterError(f"{field} must be an object")
    normalized = {str(key): child for key, child in value.items()}
    if forbid_truth:
        _reject_visible_truth(normalized, field)
    try:
        encoded = json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise NetworkAdapterError(
            f"{field} must contain canonical JSON values"
        ) from exc
    if len(encoded) > MAX_RECORD_BYTES:
        raise NetworkAdapterError(f"{field} exceeds 1 MiB")
    return json.loads(encoded.decode("utf-8"))


def _record_size_guard(payload: Mapping[str, Any], field: str) -> None:
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise NetworkAdapterError(f"{field} must be canonical JSON") from exc
    if len(encoded) > MAX_RECORD_BYTES:
        raise NetworkAdapterError(f"{field} exceeds 1 MiB")


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    dataset_id: str
    source_domain: str
    source_object_ref: str
    source_sha256: str
    adapter_version: str
    record_ordinal: int
    timestamp: str | None
    interval_start: str | None
    interval_end: str | None
    asset_refs: tuple[str, ...]
    account_refs: tuple[str, ...]
    network_refs: tuple[str, ...]
    event_family: str
    event_type: str
    observation_fields: dict[str, Any]
    provenance_ref: str
    schema_version: str = EVIDENCE_SCHEMA

    @classmethod
    def build(
        cls,
        *,
        dataset_id: str,
        source_domain: str,
        source_object_ref: str,
        source_sha256: str,
        adapter_version: str,
        record_ordinal: int,
        event_family: str,
        event_type: str,
        observation_fields: Mapping[str, Any],
        provenance_ref: str,
        timestamp: str | None = None,
        interval_start: str | None = None,
        interval_end: str | None = None,
        asset_refs: Iterable[Any] | None = None,
        account_refs: Iterable[Any] | None = None,
        network_refs: Iterable[Any] | None = None,
    ) -> "EvidenceRecord":
        ts = str(timestamp).strip() if timestamp is not None else None
        start = str(interval_start).strip() if interval_start is not None else None
        end = str(interval_end).strip() if interval_end is not None else None
        if ts:
            if start or end:
                raise NetworkAdapterError(
                    "EvidenceRecord must use timestamp or interval, not both"
                )
        elif not start or not end:
            raise NetworkAdapterError(
                "EvidenceRecord requires timestamp or interval_start+interval_end"
            )

        dataset = _bounded(dataset_id, "dataset_id", max_len=80)
        domain = _bounded(source_domain, "source_domain", max_len=80)
        logical_ref = _logical_ref(source_object_ref, "source_object_ref")
        source_hash = _sha256(source_sha256, "source_sha256")
        version = _bounded(adapter_version, "adapter_version", max_len=80)
        ordinal = _positive_int(record_ordinal, "record_ordinal", allow_zero=True)
        assets = _refs(asset_refs, "asset_refs")
        accounts = _refs(account_refs, "account_refs")
        networks = _refs(network_refs, "network_refs")
        family = _bounded(event_family, "event_family", max_len=96)
        event = _bounded(event_type, "event_type", max_len=96)
        fields = _canonical_json_object(
            observation_fields, "observation_fields", forbid_truth=True
        )
        provenance = _bounded(provenance_ref, "provenance_ref", max_len=512)

        identity = {
            "schema_version": EVIDENCE_SCHEMA,
            "dataset_id": dataset,
            "source_domain": domain,
            "source_object_ref": logical_ref,
            "source_sha256": source_hash,
            "adapter_version": version,
            "record_ordinal": ordinal,
            "timestamp": ts,
            "interval_start": start,
            "interval_end": end,
            "asset_refs": list(assets),
            "account_refs": list(accounts),
            "network_refs": list(networks),
            "event_family": family,
            "event_type": event,
            "observation_fields": fields,
            "provenance_ref": provenance,
        }
        evidence_id = "ev_" + canonical_sha256(identity)[7:31]
        record = cls(
            evidence_id=evidence_id,
            dataset_id=dataset,
            source_domain=domain,
            source_object_ref=logical_ref,
            source_sha256=source_hash,
            adapter_version=version,
            record_ordinal=ordinal,
            timestamp=ts,
            interval_start=start,
            interval_end=end,
            asset_refs=assets,
            account_refs=accounts,
            network_refs=networks,
            event_family=family,
            event_type=event,
            observation_fields=fields,
            provenance_ref=provenance,
        )
        _record_size_guard(record.as_dict(), "EvidenceRecord")
        return record

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "evidence_id": self.evidence_id,
            "dataset_id": self.dataset_id,
            "source_domain": self.source_domain,
            "source_object_ref": self.source_object_ref,
            "source_sha256": self.source_sha256,
            "adapter_version": self.adapter_version,
            "record_ordinal": self.record_ordinal,
            "timestamp": self.timestamp,
            "interval_start": self.interval_start,
            "interval_end": self.interval_end,
            "asset_refs": list(self.asset_refs),
            "account_refs": list(self.account_refs),
            "network_refs": list(self.network_refs),
            "event_family": self.event_family,
            "event_type": self.event_type,
            "observation_fields": self.observation_fields,
            "provenance_ref": self.provenance_ref,
        }


@dataclass(frozen=True)
class TruthRecord:
    truth_id: str
    evidence_refs: tuple[str, ...]
    truth_class: str
    truth_fields: dict[str, Any]
    source_object_ref: str
    source_sha256: str
    adapter_version: str
    provenance_ref: str
    schema_version: str = TRUTH_SCHEMA

    @classmethod
    def build(
        cls,
        *,
        evidence_refs: Iterable[Any],
        truth_class: str,
        truth_fields: Mapping[str, Any],
        source_object_ref: str,
        source_sha256: str,
        adapter_version: str,
        provenance_ref: str,
    ) -> "TruthRecord":
        refs = _refs(evidence_refs, "evidence_refs")
        if not refs:
            raise NetworkAdapterError(
                "TruthRecord requires at least one evidence_ref"
            )
        truth = _bounded(truth_class, "truth_class", max_len=96)
        fields = _canonical_json_object(
            truth_fields, "truth_fields", forbid_truth=False
        )
        logical_ref = _logical_ref(source_object_ref, "source_object_ref")
        source_hash = _sha256(source_sha256, "source_sha256")
        version = _bounded(adapter_version, "adapter_version", max_len=80)
        provenance = _bounded(provenance_ref, "provenance_ref", max_len=512)

        identity = {
            "schema_version": TRUTH_SCHEMA,
            "evidence_refs": list(refs),
            "truth_class": truth,
            "truth_fields": fields,
            "source_object_ref": logical_ref,
            "source_sha256": source_hash,
            "adapter_version": version,
            "provenance_ref": provenance,
        }
        truth_id = "truth_" + canonical_sha256(identity)[7:31]
        record = cls(
            truth_id=truth_id,
            evidence_refs=refs,
            truth_class=truth,
            truth_fields=fields,
            source_object_ref=logical_ref,
            source_sha256=source_hash,
            adapter_version=version,
            provenance_ref=provenance,
        )
        _record_size_guard(record.as_dict(), "TruthRecord")
        return record

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "truth_id": self.truth_id,
            "evidence_refs": list(self.evidence_refs),
            "truth_class": self.truth_class,
            "truth_fields": self.truth_fields,
            "source_object_ref": self.source_object_ref,
            "source_sha256": self.source_sha256,
            "adapter_version": self.adapter_version,
            "provenance_ref": self.provenance_ref,
        }


@dataclass(frozen=True)
class AdapterInputContract:
    dataset_id: str
    variant: str
    source_object_ref: str
    source_sha256: str
    actual_source_size_bytes: int
    max_plan_bytes: int
    acquisition_plan_fingerprint: str
    registry_fingerprint: str
    policy_fingerprint: str
    provenance_ref: str
    adapter_version: str

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AdapterInputContract":
        actual = _positive_int(
            value.get("actual_source_size_bytes"),
            "actual_source_size_bytes",
            allow_zero=True,
        )
        maximum = _positive_int(value.get("max_plan_bytes"), "max_plan_bytes")
        if actual > maximum:
            raise NetworkAdapterIntegrityError(
                "actual source size exceeds the bound acquisition plan"
            )
        return cls(
            dataset_id=_bounded(
                value.get("dataset_id"), "dataset_id", max_len=80
            ),
            variant=_bounded(value.get("variant"), "variant", max_len=80),
            source_object_ref=_logical_ref(
                value.get("source_object_ref"), "source_object_ref"
            ),
            source_sha256=_sha256(
                value.get("source_sha256"), "source_sha256"
            ),
            actual_source_size_bytes=actual,
            max_plan_bytes=maximum,
            acquisition_plan_fingerprint=_sha256(
                value.get("acquisition_plan_fingerprint"),
                "acquisition_plan_fingerprint",
            ),
            registry_fingerprint=_sha256(
                value.get("registry_fingerprint"),
                "registry_fingerprint",
            ),
            policy_fingerprint=_sha256(
                value.get("policy_fingerprint"),
                "policy_fingerprint",
            ),
            provenance_ref=_bounded(
                value.get("provenance_ref"),
                "provenance_ref",
                max_len=512,
            ),
            adapter_version=_bounded(
                value.get("adapter_version"),
                "adapter_version",
                max_len=80,
            ),
        )


@dataclass(frozen=True)
class AdapterInspection:
    dataset_id: str
    variant: str
    source_object_ref: str
    source_sha256: str
    source_size_bytes: int
    acquisition_plan_fingerprint: str
    registry_fingerprint: str
    policy_fingerprint: str
    provenance_ref: str
    adapter_version: str
    inspection_fingerprint: str
    schema_version: str = INSPECTION_SCHEMA

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "dataset_id": self.dataset_id,
            "variant": self.variant,
            "source_object_ref": self.source_object_ref,
            "source_sha256": self.source_sha256,
            "source_size_bytes": self.source_size_bytes,
            "acquisition_plan_fingerprint": self.acquisition_plan_fingerprint,
            "registry_fingerprint": self.registry_fingerprint,
            "policy_fingerprint": self.policy_fingerprint,
            "provenance_ref": self.provenance_ref,
            "adapter_version": self.adapter_version,
            "inspection_fingerprint": self.inspection_fingerprint,
        }


def inspect_staged_source(
    source_path: str | Path,
    *,
    authorized_root: str | Path,
    contract: AdapterInputContract,
) -> AdapterInspection:
    root = Path(authorized_root).resolve(strict=True)
    source = Path(source_path)

    if source.is_symlink():
        raise NetworkAdapterSecurityError(
            "staged source must not be a symlink"
        )
    resolved = source.resolve(strict=True)
    if not resolved.is_file():
        raise NetworkAdapterSecurityError(
            "staged source must be a regular file"
        )
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise NetworkAdapterSecurityError(
            "staged source resolves outside the authorized root"
        ) from exc

    size = resolved.stat().st_size
    if size != contract.actual_source_size_bytes:
        raise NetworkAdapterIntegrityError(
            "staged source size does not match the verified input contract"
        )
    if size > contract.max_plan_bytes:
        raise NetworkAdapterIntegrityError(
            "staged source exceeds the acquisition plan"
        )

    digest = hashlib.sha256()
    with resolved.open("rb") as handle:
        while True:
            chunk = handle.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    observed_sha = "sha256:" + digest.hexdigest()
    if observed_sha != contract.source_sha256:
        raise NetworkAdapterIntegrityError(
            "staged source digest mismatch"
        )

    identity = {
        "schema_version": INSPECTION_SCHEMA,
        "dataset_id": contract.dataset_id,
        "variant": contract.variant,
        "source_object_ref": contract.source_object_ref,
        "source_sha256": contract.source_sha256,
        "source_size_bytes": size,
        "acquisition_plan_fingerprint": contract.acquisition_plan_fingerprint,
        "registry_fingerprint": contract.registry_fingerprint,
        "policy_fingerprint": contract.policy_fingerprint,
        "provenance_ref": contract.provenance_ref,
        "adapter_version": contract.adapter_version,
    }
    return AdapterInspection(
        dataset_id=contract.dataset_id,
        variant=contract.variant,
        source_object_ref=contract.source_object_ref,
        source_sha256=contract.source_sha256,
        source_size_bytes=size,
        acquisition_plan_fingerprint=contract.acquisition_plan_fingerprint,
        registry_fingerprint=contract.registry_fingerprint,
        policy_fingerprint=contract.policy_fingerprint,
        provenance_ref=contract.provenance_ref,
        adapter_version=contract.adapter_version,
        inspection_fingerprint=canonical_sha256(identity),
    )


@dataclass(frozen=True)
class AdapterReceipt:
    exact_head_sha: str
    adapter_id: str
    adapter_version: str
    adapter_spec_sha256: str
    fixture_or_source_manifest_sha256: str
    source_sha256: str
    registry_fingerprint: str
    policy_fingerprint: str
    records_seen: int
    records_emitted: int
    records_rejected: int
    truth_records_emitted: int
    determinism_identical: bool
    zero_tolerance_gates: dict[str, bool]
    resource_measurements: dict[str, Any]
    verdict: str
    failed_gate_ids: tuple[str, ...]
    schema_version: str = RECEIPT_SCHEMA

    @classmethod
    def build(
        cls,
        *,
        exact_head_sha: str,
        adapter_id: str,
        adapter_version: str,
        adapter_spec_sha256: str,
        fixture_or_source_manifest_sha256: str,
        source_sha256: str,
        registry_fingerprint: str,
        policy_fingerprint: str,
        records_seen: int,
        records_emitted: int,
        records_rejected: int,
        truth_records_emitted: int,
        determinism_identical: bool,
        zero_tolerance_gates: Mapping[str, Any],
        resource_measurements: Mapping[str, Any],
        verdict: str,
        failed_gate_ids: Iterable[Any] | None = None,
    ) -> "AdapterReceipt":
        normalized_verdict = _bounded(verdict, "verdict", max_len=64)
        if normalized_verdict not in VERDICTS:
            raise NetworkAdapterError(
                f"unsupported verdict {normalized_verdict!r}"
            )

        if not isinstance(zero_tolerance_gates, Mapping):
            raise NetworkAdapterError(
                "zero_tolerance_gates must be an object"
            )
        gates = {
            _bounded(key, "gate_id", max_len=128): bool(value)
            for key, value in zero_tolerance_gates.items()
        }
        failures = _refs(
            failed_gate_ids, "failed_gate_ids", max_items=128
        )
        failed_from_gates = tuple(
            sorted(key for key, passed in gates.items() if not passed)
        )
        if tuple(sorted(failures)) != failed_from_gates:
            raise NetworkAdapterError(
                "failed_gate_ids must exactly match failed zero-tolerance gates"
            )
        if normalized_verdict == "PASS" and (
            failures or not determinism_identical
        ):
            raise NetworkAdapterError(
                "PASS requires deterministic replay and zero failed gates"
            )
        resources = _canonical_json_object(
            resource_measurements,
            "resource_measurements",
            forbid_truth=False,
        )
        return cls(
            exact_head_sha=_git_sha(exact_head_sha),
            adapter_id=_bounded(adapter_id, "adapter_id", max_len=80),
            adapter_version=_bounded(
                adapter_version, "adapter_version", max_len=80
            ),
            adapter_spec_sha256=_sha256(
                adapter_spec_sha256, "adapter_spec_sha256"
            ),
            fixture_or_source_manifest_sha256=_sha256(
                fixture_or_source_manifest_sha256,
                "fixture_or_source_manifest_sha256",
            ),
            source_sha256=_sha256(
                source_sha256, "source_sha256"
            ),
            registry_fingerprint=_sha256(
                registry_fingerprint, "registry_fingerprint"
            ),
            policy_fingerprint=_sha256(
                policy_fingerprint, "policy_fingerprint"
            ),
            records_seen=_positive_int(
                records_seen, "records_seen", allow_zero=True
            ),
            records_emitted=_positive_int(
                records_emitted, "records_emitted", allow_zero=True
            ),
            records_rejected=_positive_int(
                records_rejected, "records_rejected", allow_zero=True
            ),
            truth_records_emitted=_positive_int(
                truth_records_emitted,
                "truth_records_emitted",
                allow_zero=True,
            ),
            determinism_identical=bool(determinism_identical),
            zero_tolerance_gates=gates,
            resource_measurements=resources,
            verdict=normalized_verdict,
            failed_gate_ids=failures,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "exact_head_sha": self.exact_head_sha,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "adapter_spec_sha256": self.adapter_spec_sha256,
            "fixture_or_source_manifest_sha256": (
                self.fixture_or_source_manifest_sha256
            ),
            "source_sha256": self.source_sha256,
            "registry_fingerprint": self.registry_fingerprint,
            "policy_fingerprint": self.policy_fingerprint,
            "records_seen": self.records_seen,
            "records_emitted": self.records_emitted,
            "records_rejected": self.records_rejected,
            "truth_records_emitted": self.truth_records_emitted,
            "determinism_identical": self.determinism_identical,
            "zero_tolerance_gates": dict(
                sorted(self.zero_tolerance_gates.items())
            ),
            "resource_measurements": self.resource_measurements,
            "verdict": self.verdict,
            "failed_gate_ids": list(self.failed_gate_ids),
        }
