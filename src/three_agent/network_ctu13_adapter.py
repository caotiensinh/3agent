from __future__ import annotations

import csv
import math
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator

from .network_corpus_adapter import (
    AdapterInputContract,
    AdapterInspection,
    EvidenceRecord,
    NetworkAdapterError,
    NetworkAdapterIntegrityError,
    TruthRecord,
    inspect_staged_source,
)

CTU13_DATASET_ID = "ctu-13"
CTU13_VARIANT = "bidirectional-netflow"
CTU13_ADAPTER_ID = "ctu-13-bidirectional-netflow"
CTU13_ADAPTER_VERSION = "ctu-13-bidirectional-netflow/0.1"
CTU13_MAX_VISIBLE_RECORDS = 250_000

# Reviewed against the publisher's CTU-13 FAQ for Argus/ra bidirectional
# flow output. Schema drift fails closed rather than guessing aliases.
CTU13_COLUMNS = (
    "StartTime",
    "Dur",
    "Proto",
    "SrcAddr",
    "Sport",
    "Dir",
    "DstAddr",
    "Dport",
    "State",
    "sTos",
    "dTos",
    "TotPkts",
    "TotBytes",
    "SrcBytes",
    "Label",
)

CTU13_TIMESTAMP_FORMATS = (
    "%Y/%m/%d %H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
)


class CTU13AdapterSchemaError(NetworkAdapterError):
    """The staged flow file does not match the reviewed CTU-13 schema."""


class CTU13AdapterResourceError(NetworkAdapterError):
    """The adapter exceeded a bounded streaming/resource contract."""


@dataclass(frozen=True)
class CTU13AdapterCounters:
    records_seen: int
    records_emitted: int
    truth_records_emitted: int
    records_malformed: int
    records_rejected: int
    first_error_code: str | None


@dataclass(frozen=True)
class CTU13AdapterOutput:
    evidence: EvidenceRecord
    truth: TruthRecord


def _normalize_header(row: list[str]) -> tuple[str, ...]:
    return tuple(value.strip().lstrip("\ufeff") for value in row)


def _bounded_text(raw: str, field: str, *, allow_empty: bool = False, max_len: int = 256) -> str:
    value = raw.strip()
    if not value and not allow_empty:
        raise CTU13AdapterSchemaError(f"required field {field!r} is empty")
    if len(value) > max_len:
        raise CTU13AdapterSchemaError(f"field {field!r} exceeds {max_len} characters")
    return value


def _normalize_timestamp(raw: str) -> str:
    value = _bounded_text(raw, "StartTime", max_len=64)
    for fmt in CTU13_TIMESTAMP_FORMATS:
        try:
            parsed = datetime.strptime(value, fmt)
        except ValueError:
            continue
        # CTU-13 text flows do not encode a timezone. Preserve that uncertainty
        # rather than inventing UTC.
        return parsed.isoformat(timespec="microseconds").rstrip("0").rstrip(".")
    raise CTU13AdapterSchemaError("invalid required StartTime value")


def _nonnegative_number(raw: str, field: str, *, integer: bool) -> int | float:
    value = _bounded_text(raw, field, max_len=64)
    try:
        parsed: int | float
        if integer:
            parsed = int(value, 10)
        else:
            parsed = float(value)
    except ValueError as exc:
        raise CTU13AdapterSchemaError(f"required numeric field {field!r} is invalid") from exc
    if isinstance(parsed, float) and not math.isfinite(parsed):
        raise CTU13AdapterSchemaError(f"required numeric field {field!r} is non-finite")
    if parsed < 0:
        raise CTU13AdapterSchemaError(f"required numeric field {field!r} must be non-negative")
    return parsed


def _validate_header(header: tuple[str, ...]) -> None:
    if header != CTU13_COLUMNS:
        raise CTU13AdapterSchemaError(
            "CSV header does not match the reviewed CTU-13 bidirectional NetFlow schema"
        )


class CTU13BidirectionalFlowAdapter:
    """Bounded streaming adapter for CTU-13 labelled bidirectional flow text.

    The dataset label is removed before visible EvidenceRecord construction and
    emitted only as scorer-side TruthRecord metadata. This class performs no
    network, model, subprocess, package-installation, packet-capture or malware
    execution work.
    """

    adapter_id = CTU13_ADAPTER_ID
    adapter_version = CTU13_ADAPTER_VERSION

    def __init__(self, *, max_visible_records: int = CTU13_MAX_VISIBLE_RECORDS):
        if not isinstance(max_visible_records, int) or isinstance(max_visible_records, bool):
            raise CTU13AdapterResourceError("max_visible_records must be an integer")
        if max_visible_records <= 0 or max_visible_records > CTU13_MAX_VISIBLE_RECORDS:
            raise CTU13AdapterResourceError(
                f"max_visible_records must be 1..{CTU13_MAX_VISIBLE_RECORDS}"
            )
        self.max_visible_records = max_visible_records
        self._records_seen = 0
        self._records_emitted = 0
        self._truth_records_emitted = 0
        self._records_malformed = 0
        self._records_rejected = 0
        self._first_error_code: str | None = None
        self._bound_contract: AdapterInputContract | None = None
        self._bound_authorized_root: Path | None = None

    def _reset(self) -> None:
        self._records_seen = 0
        self._records_emitted = 0
        self._truth_records_emitted = 0
        self._records_malformed = 0
        self._records_rejected = 0
        self._first_error_code = None

    def _reject(self, code: str, *, malformed: bool = False) -> None:
        self._records_rejected += 1
        if malformed:
            self._records_malformed += 1
        if self._first_error_code is None:
            self._first_error_code = code

    def counters(self) -> CTU13AdapterCounters:
        return CTU13AdapterCounters(
            records_seen=self._records_seen,
            records_emitted=self._records_emitted,
            truth_records_emitted=self._truth_records_emitted,
            records_malformed=self._records_malformed,
            records_rejected=self._records_rejected,
            first_error_code=self._first_error_code,
        )

    def inspect(
        self,
        source_path: str | Path,
        *,
        authorized_root: str | Path,
        contract: AdapterInputContract,
    ) -> AdapterInspection:
        if contract.dataset_id != CTU13_DATASET_ID:
            raise CTU13AdapterSchemaError(f"adapter requires dataset_id={CTU13_DATASET_ID}")
        if contract.variant != CTU13_VARIANT:
            raise CTU13AdapterSchemaError(f"adapter requires variant={CTU13_VARIANT}")
        if contract.adapter_version != self.adapter_version:
            raise CTU13AdapterSchemaError("adapter version in input contract does not match runtime adapter")

        inspection = inspect_staged_source(
            source_path,
            authorized_root=authorized_root,
            contract=contract,
        )
        self._bound_contract = contract
        self._bound_authorized_root = Path(authorized_root).resolve(strict=True)

        with Path(source_path).open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle)
            try:
                header = next(reader)
            except StopIteration as exc:
                raise CTU13AdapterSchemaError("CTU-13 source is empty") from exc
            _validate_header(_normalize_header(header))
        return inspection

    def iterate(
        self,
        source_path: str | Path,
        *,
        inspection: AdapterInspection,
    ) -> Iterator[CTU13AdapterOutput]:
        if inspection.dataset_id != CTU13_DATASET_ID:
            raise CTU13AdapterSchemaError("inspection dataset does not match CTU-13 adapter")
        if inspection.variant != CTU13_VARIANT:
            raise CTU13AdapterSchemaError("inspection variant does not match CTU-13 adapter")
        if inspection.adapter_version != self.adapter_version:
            raise CTU13AdapterSchemaError("inspection adapter version mismatch")
        if self._bound_contract is None or self._bound_authorized_root is None:
            raise CTU13AdapterSchemaError("inspect() must succeed before iterate()")

        rebound = inspect_staged_source(
            source_path,
            authorized_root=self._bound_authorized_root,
            contract=self._bound_contract,
        )
        if rebound.inspection_fingerprint != inspection.inspection_fingerprint:
            raise NetworkAdapterIntegrityError("source inspection changed before parse")

        self._reset()
        with Path(source_path).open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle)
            try:
                header = _normalize_header(next(reader))
            except StopIteration as exc:
                raise CTU13AdapterSchemaError("CTU-13 source is empty") from exc
            _validate_header(header)

            for ordinal, row in enumerate(reader):
                self._records_seen += 1
                if len(row) != len(CTU13_COLUMNS):
                    self._reject("ROW_COLUMN_COUNT", malformed=True)
                    continue

                values = dict(zip(CTU13_COLUMNS, row))
                label = values.pop("Label").strip()
                if not label:
                    self._reject("LABEL_MISSING", malformed=True)
                    continue

                try:
                    timestamp = _normalize_timestamp(values.pop("StartTime"))
                    duration = _nonnegative_number(values.pop("Dur"), "Dur", integer=False)
                    protocol = _bounded_text(values.pop("Proto"), "Proto", max_len=32)
                    src_addr = _bounded_text(values.pop("SrcAddr"), "SrcAddr", max_len=128)
                    src_port = _bounded_text(values.pop("Sport"), "Sport", allow_empty=True, max_len=32)
                    direction = _bounded_text(values.pop("Dir"), "Dir", max_len=16)
                    dst_addr = _bounded_text(values.pop("DstAddr"), "DstAddr", max_len=128)
                    dst_port = _bounded_text(values.pop("Dport"), "Dport", allow_empty=True, max_len=32)
                    state = _bounded_text(values.pop("State"), "State", allow_empty=True, max_len=64)
                    source_tos = _bounded_text(values.pop("sTos"), "sTos", allow_empty=True, max_len=32)
                    destination_tos = _bounded_text(values.pop("dTos"), "dTos", allow_empty=True, max_len=32)
                    total_packets = _nonnegative_number(values.pop("TotPkts"), "TotPkts", integer=True)
                    total_bytes = _nonnegative_number(values.pop("TotBytes"), "TotBytes", integer=True)
                    source_bytes = _nonnegative_number(values.pop("SrcBytes"), "SrcBytes", integer=True)
                except CTU13AdapterSchemaError:
                    self._reject("ROW_REQUIRED_FIELD_INVALID", malformed=True)
                    continue

                if values:
                    self._reject("ROW_UNCONSUMED_FIELDS", malformed=True)
                    continue
                if source_bytes > total_bytes:
                    self._reject("ROW_BYTE_INVARIANT_INVALID", malformed=True)
                    continue
                if self._records_emitted >= self.max_visible_records:
                    raise CTU13AdapterResourceError("visible record budget exceeded")

                observations = {
                    "duration_seconds": duration,
                    "protocol": protocol,
                    "source_address": src_addr,
                    "source_port": src_port,
                    "direction": direction,
                    "destination_address": dst_addr,
                    "destination_port": dst_port,
                    "state": state,
                    "source_tos": source_tos,
                    "destination_tos": destination_tos,
                    "total_packets": total_packets,
                    "total_bytes": total_bytes,
                    "source_bytes": source_bytes,
                }
                evidence = EvidenceRecord.build(
                    dataset_id=CTU13_DATASET_ID,
                    source_domain="network_flow",
                    source_object_ref=inspection.source_object_ref,
                    source_sha256=inspection.source_sha256,
                    adapter_version=self.adapter_version,
                    record_ordinal=ordinal,
                    timestamp=timestamp,
                    asset_refs=[src_addr, dst_addr],
                    account_refs=[],
                    network_refs=[
                        f"src={src_addr}",
                        f"sport={src_port or '-'}",
                        f"dst={dst_addr}",
                        f"dport={dst_port or '-'}",
                        f"protocol={protocol}",
                    ],
                    event_family="network_flow",
                    event_type="ctu13_bidirectional_flow",
                    observation_fields=observations,
                    provenance_ref=inspection.provenance_ref,
                )

                label_folded = label.casefold()
                truth = TruthRecord.build(
                    evidence_refs=[evidence.evidence_id],
                    truth_class="ctu13_flow_label",
                    truth_fields={
                        "flow_label": label,
                        "is_botnet": "botnet" in label_folded,
                        "is_normal": "normal" in label_folded,
                        "is_background": "background" in label_folded,
                    },
                    source_object_ref=inspection.source_object_ref,
                    source_sha256=inspection.source_sha256,
                    adapter_version=self.adapter_version,
                    provenance_ref=inspection.provenance_ref,
                )
                self._records_emitted += 1
                self._truth_records_emitted += 1
                yield CTU13AdapterOutput(evidence=evidence, truth=truth)
