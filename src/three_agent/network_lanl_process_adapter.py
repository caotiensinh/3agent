from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterator

from .network_corpus_adapter import (
    AdapterInputContract,
    AdapterInspection,
    EvidenceRecord,
    NetworkAdapterIntegrityError,
    inspect_staged_source,
)
from .network_lanl_adapter import (
    LANLAdapterCounters,
    LANLAdapterResourceError,
    LANLAdapterSchemaError,
    LANL_DATASET_ID,
    LANL_MAX_VISIBLE_RECORDS,
    LANL_VARIANT,
    _unique_refs,
    lanl_entity_ref,
    lanl_logical_timestamp,
    lanl_optional,
    lanl_required_identity,
    lanl_time_offset,
)

LANL_PROCESS_ADAPTER_ID = "lanl-comprehensive-process"
LANL_PROCESS_ADAPTER_VERSION = "lanl-comprehensive-process/0.1"
LANL_PROCESS_FIELD_COUNT = 5
LANL_PROCESS_LIFECYCLE_VALUES = frozenset({"Start", "End"})


class LANLProcessAdapter:
    """Streaming parser for the reviewed LANL process source family.

    Process/user/computer strings are treated only as untrusted observations.
    This adapter has no red-team truth input, model authority, network authority,
    package-install authority, or shell execution path.
    """

    adapter_id = LANL_PROCESS_ADAPTER_ID
    adapter_version = LANL_PROCESS_ADAPTER_VERSION
    source_family = "process"

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
                raise LANLAdapterSchemaError("LANL process source is empty") from exc
            if len(first) != LANL_PROCESS_FIELD_COUNT:
                raise LANLAdapterSchemaError(
                    "LANL process row does not have the reviewed 5-field schema"
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
                if len(row) != LANL_PROCESS_FIELD_COUNT:
                    self._reject("PROCESS_FIELD_COUNT")
                    continue

                try:
                    offset = lanl_time_offset(row[0])
                    user_domain = lanl_optional(row[1], "user_domain")
                    computer = lanl_required_identity(row[2], "computer")
                    process_name = lanl_optional(row[3], "process_name")
                    start_end = lanl_optional(row[4], "start_end")
                except LANLAdapterSchemaError:
                    self._reject("PROCESS_REQUIRED_FIELD_INVALID")
                    continue

                if (
                    start_end is not None
                    and start_end not in LANL_PROCESS_LIFECYCLE_VALUES
                ):
                    self._reject("PROCESS_LIFECYCLE_INVALID")
                    continue

                if self._records_emitted >= self.max_visible_records:
                    raise LANLAdapterResourceError("visible record budget exceeded")

                evidence = EvidenceRecord.build(
                    dataset_id=LANL_DATASET_ID,
                    source_domain="host_process",
                    source_object_ref=inspection.source_object_ref,
                    source_sha256=inspection.source_sha256,
                    adapter_version=self.adapter_version,
                    record_ordinal=ordinal,
                    timestamp=lanl_logical_timestamp(offset),
                    asset_refs=_unique_refs(
                        lanl_entity_ref("computer", computer),
                    ),
                    account_refs=_unique_refs(
                        lanl_entity_ref("user", user_domain),
                    ),
                    network_refs=[],
                    event_family="process",
                    event_type="lanl_process_lifecycle",
                    observation_fields={
                        "time_offset_seconds": offset,
                        "user_domain": user_domain,
                        "computer": computer,
                        "process_name": process_name,
                        "start_end": start_end,
                    },
                    provenance_ref=inspection.provenance_ref,
                )
                self._records_emitted += 1
                yield evidence
