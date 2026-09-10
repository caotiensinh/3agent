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
from .network_lanl_family import validate_lanl_source_family_ref

LANL_FLOW_ADAPTER_ID = "lanl-comprehensive-flow"
LANL_FLOW_ADAPTER_VERSION = "lanl-comprehensive-flow/0.1"
LANL_FLOW_FIELD_COUNT = 9


def lanl_nonnegative_integer(raw: str, field: str) -> int:
    value = lanl_optional(raw, field)
    if value is None:
        raise LANLAdapterSchemaError(f"required numeric field {field} is unknown")
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise LANLAdapterSchemaError(f"{field} must be an integer") from exc
    if parsed < 0:
        raise LANLAdapterSchemaError(f"{field} must be >= 0")
    return parsed


class LANLFlowAdapter:
    """Streaming parser for the reviewed LANL network-flow source family.

    LANL ports and protocols remain dataset observations. Anonymized `N...`
    ports are preserved as strings and are never coerced into invented numeric
    ports. Dataset content grants no network, model, package or shell authority.
    """

    adapter_id = LANL_FLOW_ADAPTER_ID
    adapter_version = LANL_FLOW_ADAPTER_VERSION
    source_family = "flow"

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
                raise LANLAdapterSchemaError("LANL flow source is empty") from exc
            if len(first) != LANL_FLOW_FIELD_COUNT:
                raise LANLAdapterSchemaError(
                    "LANL flow row does not have the reviewed 9-field schema"
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
                if len(row) != LANL_FLOW_FIELD_COUNT:
                    self._reject("FLOW_FIELD_COUNT")
                    continue

                try:
                    offset = lanl_time_offset(row[0])
                    duration_seconds = lanl_nonnegative_integer(
                        row[1], "duration_seconds"
                    )
                    source_computer = lanl_required_identity(
                        row[2], "source_computer"
                    )
                    source_port = lanl_optional(row[3], "source_port")
                    destination_computer = lanl_required_identity(
                        row[4], "destination_computer"
                    )
                    destination_port = lanl_optional(row[5], "destination_port")
                    protocol = lanl_optional(row[6], "protocol")
                    packet_count = lanl_nonnegative_integer(row[7], "packet_count")
                    byte_count = lanl_nonnegative_integer(row[8], "byte_count")
                except LANLAdapterSchemaError:
                    self._reject("FLOW_REQUIRED_FIELD_INVALID")
                    continue

                if self._records_emitted >= self.max_visible_records:
                    raise LANLAdapterResourceError("visible record budget exceeded")

                evidence = EvidenceRecord.build(
                    dataset_id=LANL_DATASET_ID,
                    source_domain="network_flow",
                    source_object_ref=inspection.source_object_ref,
                    source_sha256=inspection.source_sha256,
                    adapter_version=self.adapter_version,
                    record_ordinal=ordinal,
                    timestamp=lanl_logical_timestamp(offset),
                    asset_refs=_unique_refs(
                        lanl_entity_ref("computer", source_computer),
                        lanl_entity_ref("computer", destination_computer),
                    ),
                    account_refs=[],
                    network_refs=_unique_refs(
                        lanl_entity_ref("port", source_port),
                        lanl_entity_ref("port", destination_port),
                        lanl_entity_ref("protocol", protocol),
                    ),
                    event_family="network_flow",
                    event_type="lanl_router_flow",
                    observation_fields={
                        "time_offset_seconds": offset,
                        "duration_seconds": duration_seconds,
                        "source_computer": source_computer,
                        "source_port": source_port,
                        "destination_computer": destination_computer,
                        "destination_port": destination_port,
                        "protocol": protocol,
                        "packet_count": packet_count,
                        "byte_count": byte_count,
                    },
                    provenance_ref=inspection.provenance_ref,
                )
                self._records_emitted += 1
                yield evidence
