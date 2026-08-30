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

CIC_DATASET_ID = "cse-cic-ids2018"
CIC_VARIANT = "processed-ml"
CIC_ADAPTER_ID = "cse-cic-ids2018-processed-ml"
CIC_ADAPTER_VERSION = "cse-cic-ids2018-processed-ml/0.1"
CIC_MAX_VISIBLE_RECORDS = 250_000

CIC_COLUMNS = (
    "Dst Port",
    "Protocol",
    "Timestamp",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean",
    "Fwd Pkt Len Std",
    "Bwd Pkt Len Max",
    "Bwd Pkt Len Min",
    "Bwd Pkt Len Mean",
    "Bwd Pkt Len Std",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Tot",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Tot",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Len",
    "Bwd Header Len",
    "Fwd Pkts/s",
    "Bwd Pkts/s",
    "Pkt Len Min",
    "Pkt Len Max",
    "Pkt Len Mean",
    "Pkt Len Std",
    "Pkt Len Var",
    "FIN Flag Cnt",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "PSH Flag Cnt",
    "ACK Flag Cnt",
    "URG Flag Cnt",
    "CWE Flag Count",
    "ECE Flag Cnt",
    "Down/Up Ratio",
    "Pkt Size Avg",
    "Fwd Seg Size Avg",
    "Bwd Seg Size Avg",
    "Fwd Byts/b Avg",
    "Fwd Pkts/b Avg",
    "Fwd Blk Rate Avg",
    "Bwd Byts/b Avg",
    "Bwd Pkts/b Avg",
    "Bwd Blk Rate Avg",
    "Subflow Fwd Pkts",
    "Subflow Fwd Byts",
    "Subflow Bwd Pkts",
    "Subflow Bwd Byts",
    "Init Fwd Win Byts",
    "Init Bwd Win Byts",
    "Fwd Act Data Pkts",
    "Fwd Seg Size Min",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
    "Label",
)

CIC_TIMESTAMP_FORMATS = (
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
)


class CICAdapterSchemaError(NetworkAdapterError):
    """The staged CSV does not match the reviewed CSE-CIC-IDS2018 schema."""


class CICAdapterResourceError(NetworkAdapterError):
    """The adapter exceeded a bounded streaming/resource contract."""


@dataclass(frozen=True)
class CICAdapterCounters:
    records_seen: int
    records_emitted: int
    truth_records_emitted: int
    records_skipped_benign: int
    records_malformed: int
    records_rejected: int
    first_error_code: str | None


@dataclass(frozen=True)
class CICAdapterOutput:
    evidence: EvidenceRecord
    truth: TruthRecord


def _normalize_header(row: list[str]) -> tuple[str, ...]:
    return tuple(value.strip().lstrip("\ufeff") for value in row)


def _normalize_timestamp(raw: str) -> str:
    value = raw.strip()
    for fmt in CIC_TIMESTAMP_FORMATS:
        try:
            parsed = datetime.strptime(value, fmt)
        except ValueError:
            continue
        return parsed.isoformat(timespec="seconds") + "Z"
    raise CICAdapterSchemaError("invalid required Timestamp value")


def _parse_numeric(raw: str, field: str) -> int | float:
    value = raw.strip()
    if not value:
        raise CICAdapterSchemaError(f"required numeric field {field!r} is empty")
    try:
        if value.lstrip("+-").isdigit():
            return int(value, 10)
        parsed = float(value)
    except ValueError as exc:
        raise CICAdapterSchemaError(
            f"required numeric field {field!r} is invalid"
        ) from exc
    if not math.isfinite(parsed):
        raise CICAdapterSchemaError(
            f"required numeric field {field!r} is non-finite"
        )
    return parsed


def _validate_header(header: tuple[str, ...]) -> None:
    if header != CIC_COLUMNS:
        raise CICAdapterSchemaError(
            "CSV header does not match the reviewed CSE-CIC-IDS2018 processed-ml schema"
        )


class CSECICIDS2018Adapter:
    """Streaming adapter for reviewed CSE-CIC-IDS2018 processed-ml CSV shards.

    Dataset labels are separated into scorer-only TruthRecord objects before
    visible EvidenceRecord construction. The adapter performs no model,
    network, package-installation or subprocess work.
    """

    adapter_id = CIC_ADAPTER_ID
    adapter_version = CIC_ADAPTER_VERSION

    def __init__(self, *, max_visible_records: int = CIC_MAX_VISIBLE_RECORDS):
        if not isinstance(max_visible_records, int) or max_visible_records <= 0:
            raise CICAdapterResourceError("max_visible_records must be > 0")
        if max_visible_records > CIC_MAX_VISIBLE_RECORDS:
            raise CICAdapterResourceError(
                f"max_visible_records may not exceed {CIC_MAX_VISIBLE_RECORDS}"
            )
        self.max_visible_records = max_visible_records
        self._records_seen = 0
        self._records_emitted = 0
        self._truth_records_emitted = 0
        self._records_skipped_benign = 0
        self._records_malformed = 0
        self._records_rejected = 0
        self._first_error_code: str | None = None
        self._bound_contract: AdapterInputContract | None = None
        self._bound_authorized_root: Path | None = None

    def _reset(self) -> None:
        self._records_seen = 0
        self._records_emitted = 0
        self._truth_records_emitted = 0
        self._records_skipped_benign = 0
        self._records_malformed = 0
        self._records_rejected = 0
        self._first_error_code = None

    def _mark_rejected(self, code: str, *, malformed: bool = False) -> None:
        self._records_rejected += 1
        if malformed:
            self._records_malformed += 1
        if self._first_error_code is None:
            self._first_error_code = code

    def counters(self) -> CICAdapterCounters:
        return CICAdapterCounters(
            records_seen=self._records_seen,
            records_emitted=self._records_emitted,
            truth_records_emitted=self._truth_records_emitted,
            records_skipped_benign=self._records_skipped_benign,
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
        if contract.dataset_id != CIC_DATASET_ID:
            raise CICAdapterSchemaError(
                f"adapter requires dataset_id={CIC_DATASET_ID}"
            )
        if contract.variant != CIC_VARIANT:
            raise CICAdapterSchemaError(
                f"adapter requires variant={CIC_VARIANT}"
            )
        if contract.adapter_version != self.adapter_version:
            raise CICAdapterSchemaError(
                "adapter version in input contract does not match runtime adapter"
            )

        inspection = inspect_staged_source(
            source_path,
            authorized_root=authorized_root,
            contract=contract,
        )
        self._bound_contract = contract
        self._bound_authorized_root = Path(authorized_root).resolve(strict=True)

        with Path(source_path).open(
            "r", encoding="utf-8-sig", newline=""
        ) as handle:
            reader = csv.reader(handle)
            try:
                header = next(reader)
            except StopIteration as exc:
                raise CICAdapterSchemaError("CSV source is empty") from exc
            _validate_header(_normalize_header(header))
        return inspection

    def iterate(
        self,
        source_path: str | Path,
        *,
        inspection: AdapterInspection,
    ) -> Iterator[CICAdapterOutput]:
        if inspection.dataset_id != CIC_DATASET_ID:
            raise CICAdapterSchemaError("inspection dataset does not match CIC adapter")
        if inspection.variant != CIC_VARIANT:
            raise CICAdapterSchemaError("inspection variant does not match CIC adapter")
        if inspection.adapter_version != self.adapter_version:
            raise CICAdapterSchemaError("inspection adapter version mismatch")
        if self._bound_contract is None or self._bound_authorized_root is None:
            raise CICAdapterSchemaError("inspect() must succeed before iterate()")

        rebound = inspect_staged_source(
            source_path,
            authorized_root=self._bound_authorized_root,
            contract=self._bound_contract,
        )
        if rebound.inspection_fingerprint != inspection.inspection_fingerprint:
            raise NetworkAdapterIntegrityError(
                "source inspection changed before parse"
            )

        self._reset()
        with Path(source_path).open(
            "r", encoding="utf-8-sig", newline=""
        ) as handle:
            reader = csv.reader(handle)
            try:
                header = _normalize_header(next(reader))
            except StopIteration as exc:
                raise CICAdapterSchemaError("CSV source is empty") from exc
            _validate_header(header)

            for ordinal, row in enumerate(reader):
                self._records_seen += 1
                if len(row) != len(CIC_COLUMNS):
                    self._mark_rejected("ROW_COLUMN_COUNT", malformed=True)
                    continue

                values = dict(zip(CIC_COLUMNS, row))
                label = values.pop("Label").strip()
                if not label:
                    self._mark_rejected("LABEL_MISSING", malformed=True)
                    continue

                try:
                    timestamp = _normalize_timestamp(values.pop("Timestamp"))
                    observations = {
                        field: _parse_numeric(raw, field)
                        for field, raw in values.items()
                    }
                except CICAdapterSchemaError:
                    self._mark_rejected("ROW_REQUIRED_FIELD_INVALID", malformed=True)
                    continue

                if self._records_emitted >= self.max_visible_records:
                    raise CICAdapterResourceError("visible record budget exceeded")

                dst_port = observations["Dst Port"]
                protocol = observations["Protocol"]
                evidence = EvidenceRecord.build(
                    dataset_id=CIC_DATASET_ID,
                    source_domain="network_flow",
                    source_object_ref=inspection.source_object_ref,
                    source_sha256=inspection.source_sha256,
                    adapter_version=self.adapter_version,
                    record_ordinal=ordinal,
                    timestamp=timestamp,
                    asset_refs=[],
                    account_refs=[],
                    network_refs=[
                        f"dst_port={dst_port}",
                        f"protocol={protocol}",
                    ],
                    event_family="network_flow",
                    event_type="cicflowmeter_flow",
                    observation_fields=observations,
                    provenance_ref=inspection.provenance_ref,
                )
                truth = TruthRecord.build(
                    evidence_refs=[evidence.evidence_id],
                    truth_class="cic_flow_label",
                    truth_fields={
                        "attack_class": label,
                        "is_benign": label.casefold() == "benign",
                    },
                    source_object_ref=inspection.source_object_ref,
                    source_sha256=inspection.source_sha256,
                    adapter_version=self.adapter_version,
                    provenance_ref=inspection.provenance_ref,
                )
                self._records_emitted += 1
                self._truth_records_emitted += 1
                yield CICAdapterOutput(evidence=evidence, truth=truth)
