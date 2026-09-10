from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from .network_corpus_adapter import (
    AdapterInputContract,
    AdapterInspection,
    EvidenceRecord,
    NetworkAdapterIntegrityError,
    TruthRecord,
    inspect_staged_source,
)
from .network_lanl_adapter import (
    LANLAdapterResourceError,
    LANLAdapterSchemaError,
    LANL_DATASET_ID,
    LANL_MAX_VISIBLE_RECORDS,
    LANL_VARIANT,
    lanl_logical_timestamp,
    lanl_required_identity,
    lanl_time_offset,
)
from .network_lanl_family import validate_lanl_source_family_ref

LANL_REDTEAM_MATCHER_ID = "lanl-comprehensive-redteam-truth-matcher"
LANL_REDTEAM_MATCHER_VERSION = "lanl-comprehensive-redteam-truth-matcher/0.1"
LANL_REDTEAM_FIELD_COUNT = 4
LANL_MAX_AUTH_EVIDENCE = 250_000


@dataclass(frozen=True)
class LANLRedTeamCounters:
    records_seen: int
    truth_records_emitted: int
    unmatched_truth: int
    ambiguous_truth: int
    records_rejected: int
    first_error_code: str | None


class LANLRedTeamTruthMatcher:
    """Deterministically bind LANL red-team rows to authentication evidence.

    Red-team bytes are scorer-only input. The matcher emits no EvidenceRecord,
    never chooses a nearest/first/model-selected candidate, and keeps only a
    bounded authentication index for the caller-authorized incident window.
    """

    matcher_id = LANL_REDTEAM_MATCHER_ID
    matcher_version = LANL_REDTEAM_MATCHER_VERSION
    source_family = "redteam"

    def __init__(self, *, max_auth_evidence: int = LANL_MAX_AUTH_EVIDENCE):
        if not isinstance(max_auth_evidence, int) or max_auth_evidence <= 0:
            raise LANLAdapterResourceError("max_auth_evidence must be > 0")
        if max_auth_evidence > LANL_MAX_AUTH_EVIDENCE:
            raise LANLAdapterResourceError(
                f"max_auth_evidence may not exceed {LANL_MAX_AUTH_EVIDENCE}"
            )
        self.max_auth_evidence = max_auth_evidence
        self._bound_contract: AdapterInputContract | None = None
        self._bound_authorized_root: Path | None = None
        self._records_seen = 0
        self._truth_records_emitted = 0
        self._unmatched_truth = 0
        self._ambiguous_truth = 0
        self._records_rejected = 0
        self._first_error_code: str | None = None

    def _reset(self) -> None:
        self._records_seen = 0
        self._truth_records_emitted = 0
        self._unmatched_truth = 0
        self._ambiguous_truth = 0
        self._records_rejected = 0
        self._first_error_code = None

    def _reject(self, code: str) -> None:
        self._records_rejected += 1
        if self._first_error_code is None:
            self._first_error_code = code

    def counters(self) -> LANLRedTeamCounters:
        return LANLRedTeamCounters(
            records_seen=self._records_seen,
            truth_records_emitted=self._truth_records_emitted,
            unmatched_truth=self._unmatched_truth,
            ambiguous_truth=self._ambiguous_truth,
            records_rejected=self._records_rejected,
            first_error_code=self._first_error_code,
        )

    def _validate_contract(self, contract: AdapterInputContract) -> None:
        if contract.dataset_id != LANL_DATASET_ID:
            raise LANLAdapterSchemaError(
                f"matcher requires dataset_id={LANL_DATASET_ID}"
            )
        if contract.variant != LANL_VARIANT:
            raise LANLAdapterSchemaError(f"matcher requires variant={LANL_VARIANT}")
        if contract.adapter_version != self.matcher_version:
            raise LANLAdapterSchemaError(
                "matcher version in input contract does not match runtime matcher"
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
                raise LANLAdapterSchemaError("LANL red-team source is empty") from exc
            if len(first) != LANL_REDTEAM_FIELD_COUNT:
                raise LANLAdapterSchemaError(
                    "LANL red-team row does not have the reviewed 4-field schema"
                )

        self._bound_contract = contract
        self._bound_authorized_root = Path(authorized_root).resolve(strict=True)
        return inspection

    def _auth_key(
        self,
        evidence: EvidenceRecord,
    ) -> tuple[int, str, str, str | None, str | None]:
        if evidence.dataset_id != LANL_DATASET_ID:
            raise LANLAdapterSchemaError("truth matcher accepts LANL evidence only")
        if evidence.source_domain != "authentication":
            raise LANLAdapterSchemaError("truth matcher accepts authentication evidence only")
        if evidence.event_family != "authentication":
            raise LANLAdapterSchemaError("authentication evidence family mismatch")
        if evidence.event_type != "lanl_authentication":
            raise LANLAdapterSchemaError("authentication evidence type mismatch")
        validate_lanl_source_family_ref(evidence.source_object_ref, "auth")

        fields = evidence.observation_fields
        try:
            offset = int(fields["time_offset_seconds"])
            source_computer = str(fields["source_computer"])
            destination_computer = str(fields["destination_computer"])
        except (KeyError, TypeError, ValueError) as exc:
            raise LANLAdapterSchemaError(
                "authentication evidence lacks required match fields"
            ) from exc
        if offset < 1:
            raise LANLAdapterSchemaError("authentication evidence time is invalid")
        if evidence.timestamp != lanl_logical_timestamp(offset):
            raise LANLAdapterSchemaError("authentication evidence logical time mismatch")
        if not source_computer or source_computer == "?":
            raise LANLAdapterSchemaError("authentication source computer is invalid")
        if not destination_computer or destination_computer == "?":
            raise LANLAdapterSchemaError("authentication destination computer is invalid")

        source_user_raw = fields.get("source_user_domain")
        destination_user_raw = fields.get("destination_user_domain")
        source_user = None if source_user_raw is None else str(source_user_raw)
        destination_user = (
            None if destination_user_raw is None else str(destination_user_raw)
        )
        return (
            offset,
            source_computer,
            destination_computer,
            source_user,
            destination_user,
        )

    def match(
        self,
        source_path: str | Path,
        *,
        inspection: AdapterInspection,
        auth_evidence: Iterable[EvidenceRecord],
    ) -> Iterator[TruthRecord]:
        if inspection.dataset_id != LANL_DATASET_ID:
            raise LANLAdapterSchemaError("inspection dataset does not match LANL")
        if inspection.variant != LANL_VARIANT:
            raise LANLAdapterSchemaError("inspection variant does not match LANL events")
        if inspection.adapter_version != self.matcher_version:
            raise LANLAdapterSchemaError("inspection matcher version mismatch")
        if self._bound_contract is None or self._bound_authorized_root is None:
            raise LANLAdapterSchemaError("inspect() must succeed before match()")

        rebound = inspect_staged_source(
            source_path,
            authorized_root=self._bound_authorized_root,
            contract=self._bound_contract,
        )
        if rebound.inspection_fingerprint != inspection.inspection_fingerprint:
            raise NetworkAdapterIntegrityError("source inspection changed before truth match")

        index: dict[tuple[int, str, str], list[tuple[EvidenceRecord, str | None, str | None]]] = {}
        evidence_count = 0
        for evidence in auth_evidence:
            evidence_count += 1
            if evidence_count > self.max_auth_evidence:
                raise LANLAdapterResourceError("authentication evidence budget exceeded")
            offset, source_computer, destination_computer, source_user, destination_user = (
                self._auth_key(evidence)
            )
            key = (offset, source_computer, destination_computer)
            index.setdefault(key, []).append((evidence, source_user, destination_user))

        self._reset()
        with Path(source_path).open("r", encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            for row in reader:
                self._records_seen += 1
                if len(row) != LANL_REDTEAM_FIELD_COUNT:
                    self._reject("REDTEAM_FIELD_COUNT")
                    continue

                try:
                    offset = lanl_time_offset(row[0])
                    user_domain = lanl_required_identity(row[1], "user_domain")
                    source_computer = lanl_required_identity(
                        row[2], "source_computer"
                    )
                    destination_computer = lanl_required_identity(
                        row[3], "destination_computer"
                    )
                except LANLAdapterSchemaError:
                    self._reject("REDTEAM_REQUIRED_FIELD_INVALID")
                    continue

                candidates = index.get(
                    (offset, source_computer, destination_computer),
                    [],
                )
                matches = [
                    evidence
                    for evidence, source_user, destination_user in candidates
                    if user_domain == source_user or user_domain == destination_user
                ]

                if not matches:
                    self._unmatched_truth += 1
                    continue
                if len(matches) != 1:
                    self._ambiguous_truth += 1
                    continue

                truth = TruthRecord.build(
                    evidence_refs=[matches[0].evidence_id],
                    truth_class="lanl_redteam_auth_compromise",
                    truth_fields={
                        "known_compromise": True,
                        "time_offset_seconds": offset,
                    },
                    source_object_ref=inspection.source_object_ref,
                    source_sha256=inspection.source_sha256,
                    adapter_version=self.matcher_version,
                    provenance_ref=inspection.provenance_ref,
                )
                self._truth_records_emitted += 1
                yield truth
