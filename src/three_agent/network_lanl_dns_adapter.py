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

LANL_DNS_ADAPTER_ID = "lanl-comprehensive-dns"
LANL_DNS_ADAPTER_VERSION = "lanl-comprehensive-dns/0.1"
LANL_DNS_FIELD_COUNT = 3


class LANLDNSAdapter:
    """Streaming parser for the reviewed LANL DNS source family.

    LANL computer identifiers remain de-identified dataset identities. The
    adapter never resolves them through DNS, treats them as Internet hostnames,
    or grants network/model/shell authority from dataset content.
    """

    adapter_id = LANL_DNS_ADAPTER_ID
    adapter_version = LANL_DNS_ADAPTER_VERSION
    source_family = "dns"

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
                raise LANLAdapterSchemaError("LANL DNS source is empty") from exc
            if len(first) != LANL_DNS_FIELD_COUNT:
                raise LANLAdapterSchemaError(
                    "LANL DNS row does not have the reviewed 3-field schema"
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
                if len(row) != LANL_DNS_FIELD_COUNT:
                    self._reject("DNS_FIELD_COUNT")
                    continue

                try:
                    offset = lanl_time_offset(row[0])
                    source_computer = lanl_required_identity(
                        row[1], "source_computer"
                    )
                    computer_resolved = lanl_optional(
                        row[2], "computer_resolved"
                    )
                except LANLAdapterSchemaError:
                    self._reject("DNS_REQUIRED_FIELD_INVALID")
                    continue

                if self._records_emitted >= self.max_visible_records:
                    raise LANLAdapterResourceError("visible record budget exceeded")

                evidence = EvidenceRecord.build(
                    dataset_id=LANL_DATASET_ID,
                    source_domain="dns",
                    source_object_ref=inspection.source_object_ref,
                    source_sha256=inspection.source_sha256,
                    adapter_version=self.adapter_version,
                    record_ordinal=ordinal,
                    timestamp=lanl_logical_timestamp(offset),
                    asset_refs=_unique_refs(
                        lanl_entity_ref("computer", source_computer),
                        lanl_entity_ref("computer", computer_resolved),
                    ),
                    account_refs=[],
                    network_refs=[],
                    event_family="dns",
                    event_type="lanl_dns_lookup",
                    observation_fields={
                        "time_offset_seconds": offset,
                        "source_computer": source_computer,
                        "computer_resolved": computer_resolved,
                    },
                    provenance_ref=inspection.provenance_ref,
                )
                self._records_emitted += 1
                yield evidence
