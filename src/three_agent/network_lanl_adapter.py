from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .network_corpus_adapter import (
    AdapterInputContract,
    AdapterInspection,
    EvidenceRecord,
    NetworkAdapterError,
    NetworkAdapterIntegrityError,
    inspect_staged_source,
)
from .network_lanl_family import validate_lanl_source_family_ref

LANL_DATASET_ID = "lanl-comprehensive"
LANL_VARIANT = "events"
LANL_AUTH_ADAPTER_ID = "lanl-comprehensive-auth"
LANL_AUTH_ADAPTER_VERSION = "lanl-comprehensive-auth/0.1"
LANL_AUTH_FIELD_COUNT = 9
LANL_MAX_VISIBLE_RECORDS = 250_000
LANL_UNKNOWN = "?"


class LANLAdapterSchemaError(NetworkAdapterError):
    """A LANL staged source does not match the reviewed source-family contract."""


class LANLAdapterResourceError(NetworkAdapterError):
    """A LANL adapter exceeded its bounded streaming contract."""


@dataclass(frozen=True)
class LANLAdapterCounters:
    records_seen: int
    records_emitted: int
    records_malformed: int
    records_rejected: int
    first_error_code: str | None


def lanl_time_offset(raw: str) -> int:
    value = raw.strip()
    if not value:
        raise LANLAdapterSchemaError("LANL time is empty")
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise LANLAdapterSchemaError("LANL time must be an integer offset") from exc
    if parsed < 1:
        raise LANLAdapterSchemaError("LANL time offset must be >= 1")
    return parsed


def lanl_logical_timestamp(offset_seconds: int) -> str:
    if not isinstance(offset_seconds, int) or offset_seconds < 1:
        raise LANLAdapterSchemaError("LANL logical time requires integer offset >= 1")
    return f"lanl:T+{offset_seconds}s"


def lanl_optional(raw: str, field: str) -> str | None:
    value = raw.strip()
    if value == LANL_UNKNOWN:
        return None
    if not value:
        raise LANLAdapterSchemaError(f"{field} is empty; LANL unknown must be '?'")
    return value


def lanl_required_identity(raw: str, field: str) -> str:
    value = lanl_optional(raw, field)
    if value is None:
        raise LANLAdapterSchemaError(f"required identity {field} is unknown")
    return value


def lanl_entity_ref(kind: str, value: str | None) -> str | None:
    if value is None:
        return None
    clean_kind = kind.strip().casefold()
    if clean_kind not in {"user", "computer", "process", "port", "protocol"}:
        raise LANLAdapterSchemaError("unsupported LANL entity kind")
    clean_value = value.strip()
    if not clean_value or clean_value == LANL_UNKNOWN:
        return None
    return f"lanl:{clean_kind}:{clean_value}"


def _unique_refs(*refs: str | None) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for ref in refs:
        if ref is None or ref in seen:
            continue
        seen.add(ref)
        result.append(ref)
    return result


class LANLAuthAdapter:
    """Streaming parser for the reviewed LANL authentication source family.

    This component emits observations only. It has no red-team truth input,
    model authority, network authority, package-install authority, or shell
    execution path.
    """

    adapter_id = LANL_AUTH_ADAPTER_ID
    adapter_version = LANL_AUTH_ADAPTER_VERSION
    source_family = "auth"

    def __init__(self, *, max_visible_records: int = LANL_MAX_VISIBLE_RECORDS):
        if not isinstance(max_visible_records, int) or max_visible_records <= 0:
            raise LANLAdapterResourceError("max_visible_records must be > 0")
        if max_visible_records > LANL_MAX_VISIBLE_RECORDS:
            raise LANLAdapterResourceError(
                f"max_visible_records may not exceed {LANL_MAX_VISIBLE_RECORDS}"
            )
        self.max_visible_records = max_visible_records
        self._records_seen = 0
        self._records_emitted = 0
        self._records_malformed = 0
        self._records_rejected = 0
        self._first_error_code: str | None = None
        self._bound_contract: AdapterInputContract | None = None
        self._bound_authorized_root: Path | None = None

    def _reset(self) -> None:
        self._records_seen = 0
        self._records_emitted = 0
        self._records_malformed = 0
        self._records_rejected = 0
        self._first_error_code = None

    def _reject(self, code: str, *, malformed: bool = True) -> None:
        self._records_rejected += 1
        if malformed:
            self._records_malformed += 1
        if self._first_error_code is None:
            self._first_error_code = code

    def counters(self) -> LANLAdapterCounters:
        return LANLAdapterCounters(
            records_seen=self._records_seen,
            records_emitted=self._records_emitted,
            records_malformed=self._records_malformed,
            records_rejected=self._records_rejected,
            first_error_code=self._first_error_code,
        )

    def _validate_contract(self, contract: AdapterInputContract) -> None:
        if contract.dataset_id != LANL_DATASET_ID:
            raise LANLAdapterSchemaError(
                f"adapter requires dataset_id={LANL_DATASET_ID}"
            )
        if contract.variant != LANL_VARIANT:
            raise LANLAdapterSchemaError(f"adapter requires variant={LANL_VARIANT}")
        if contract.adapter_version != self.adapter_version:
            raise LANLAdapterSchemaError(
                "adapter version in input contract does not match runtime adapter"
            )
        validate_lanl_source_family_ref(contract.source_object_ref, self.source_family)

    def inspect(
        self,
        source_path: str | Path,
        *,
        authorized_root: str | Path,
        contract: AdapterInputContract,
    ) -> AdapterInspection:
        self._validate_contract(contract)
        inspection = inspect_staged_source(
            source_path,
            authorized_root=authorized_root,
            contract=contract,
        )

        with Path(source_path).open("r", encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            try:
                first = next(reader)
            except StopIteration as exc:
                raise LANLAdapterSchemaError("LANL authentication source is empty") from exc
            if len(first) != LANL_AUTH_FIELD_COUNT:
                raise LANLAdapterSchemaError(
                    "LANL authentication row does not have the reviewed 9-field schema"
                )

        self._bound_contract = contract
        self._bound_authorized_root = Path(authorized_root).resolve(strict=True)
        return inspection

    def iterate(
        self,
        source_path: str | Path,
        *,
        inspection: AdapterInspection,
    ) -> Iterator[EvidenceRecord]:
        if inspection.dataset_id != LANL_DATASET_ID:
            raise LANLAdapterSchemaError("inspection dataset does not match LANL")
        if inspection.variant != LANL_VARIANT:
            raise LANLAdapterSchemaError("inspection variant does not match LANL events")
        if inspection.adapter_version != self.adapter_version:
            raise LANLAdapterSchemaError("inspection adapter version mismatch")
        if self._bound_contract is None or self._bound_authorized_root is None:
            raise LANLAdapterSchemaError("inspect() must succeed before iterate()")

        rebound = inspect_staged_source(
            source_path,
            authorized_root=self._bound_authorized_root,
            contract=self._bound_contract,
        )
        if rebound.inspection_fingerprint != inspection.inspection_fingerprint:
            raise NetworkAdapterIntegrityError("source inspection changed before parse")

        self._reset()
        with Path(source_path).open("r", encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            for ordinal, row in enumerate(reader):
                self._records_seen += 1
                if len(row) != LANL_AUTH_FIELD_COUNT:
                    self._reject("AUTH_FIELD_COUNT")
                    continue

                try:
                    offset = lanl_time_offset(row[0])
                    source_user = lanl_optional(row[1], "source_user_domain")
                    destination_user = lanl_optional(
                        row[2], "destination_user_domain"
                    )
                    source_computer = lanl_required_identity(
                        row[3], "source_computer"
                    )
                    destination_computer = lanl_required_identity(
                        row[4], "destination_computer"
                    )
                    authentication_type = lanl_optional(
                        row[5], "authentication_type"
                    )
                    logon_type = lanl_optional(row[6], "logon_type")
                    authentication_orientation = lanl_optional(
                        row[7], "authentication_orientation"
                    )
                    success_failure = lanl_optional(row[8], "success_failure")
                except LANLAdapterSchemaError:
                    self._reject("AUTH_REQUIRED_FIELD_INVALID")
                    continue

                if self._records_emitted >= self.max_visible_records:
                    raise LANLAdapterResourceError("visible record budget exceeded")

                evidence = EvidenceRecord.build(
                    dataset_id=LANL_DATASET_ID,
                    source_domain="authentication",
                    source_object_ref=inspection.source_object_ref,
                    source_sha256=inspection.source_sha256,
                    adapter_version=self.adapter_version,
                    record_ordinal=ordinal,
                    timestamp=lanl_logical_timestamp(offset),
                    asset_refs=_unique_refs(
                        lanl_entity_ref("computer", source_computer),
                        lanl_entity_ref("computer", destination_computer),
                    ),
                    account_refs=_unique_refs(
                        lanl_entity_ref("user", source_user),
                        lanl_entity_ref("user", destination_user),
                    ),
                    network_refs=[],
                    event_family="authentication",
                    event_type="lanl_authentication",
                    observation_fields={
                        "time_offset_seconds": offset,
                        "source_user_domain": source_user,
                        "destination_user_domain": destination_user,
                        "source_computer": source_computer,
                        "destination_computer": destination_computer,
                        "authentication_type": authentication_type,
                        "logon_type": logon_type,
                        "authentication_orientation": authentication_orientation,
                        "success_failure": success_failure,
                    },
                    provenance_ref=inspection.provenance_ref,
                )
                self._records_emitted += 1
                yield evidence
