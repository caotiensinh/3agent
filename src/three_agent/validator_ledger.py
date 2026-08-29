from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Iterable

from .store import TaskStore
from .task_contract import TaskContract, VALIDATORS

_VALIDATOR_STATUSES = {"passed", "failed"}
_REASON_CODE = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{0,127}$")
_EVIDENCE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255}$")


class ValidatorLedgerError(ValueError):
    """Validator evidence cannot be bound safely to the authoritative task contract."""


@dataclass(frozen=True)
class TaskVerificationState:
    task_id: str
    contract_bound: bool
    contract_sha256: str | None
    required_validators: tuple[str, ...]
    passed_validators: tuple[str, ...]
    failed_validators: tuple[str, ...]
    missing_validators: tuple[str, ...]
    verified: bool
    first_pass_verified: bool
    result_count: int

    def to_dict(self) -> dict:
        return {
            "schema_version": "workspace-task-verification/v1",
            "task_id": self.task_id,
            "contract_bound": self.contract_bound,
            "contract_sha256": self.contract_sha256,
            "required_validators": list(self.required_validators),
            "passed_validators": list(self.passed_validators),
            "failed_validators": list(self.failed_validators),
            "missing_validators": list(self.missing_validators),
            "verified": self.verified,
            "first_pass_verified": self.first_pass_verified,
            "result_count": self.result_count,
        }


class ValidatorLedger:
    """Authoritative, deterministic validator result ledger.

    The TaskContract defines which validators are required. Validator events may
    report outcomes, but they cannot add/remove required validators or mutate the
    bound contract. Only compact reason codes and evidence references are stored;
    raw model/tool/evidence content does not belong in this ledger.
    """

    def __init__(self, store: TaskStore):
        self.store = store

    def bind_contract(self, contract: TaskContract) -> str:
        contract.validate()
        return self.store.bind_task_contract(contract.task_id, contract.to_dict())

    @staticmethod
    def _normalize_refs(evidence_refs: Iterable[str]) -> list[str]:
        refs: list[str] = []
        for raw in evidence_refs:
            ref = str(raw).strip()
            if not ref:
                continue
            if not _EVIDENCE_REF.fullmatch(ref):
                raise ValidatorLedgerError(
                    "evidence_refs must be compact identifiers/paths, not raw content"
                )
            if ref not in refs:
                refs.append(ref)
            if len(refs) > 32:
                raise ValidatorLedgerError("at most 32 evidence references are allowed")
        return refs

    def record(
        self,
        task_id: str,
        validator: str,
        *,
        status: str,
        reason_code: str,
        evidence_refs: Iterable[str] = (),
        validator_version: str = "v1",
        attempt: int = 1,
    ) -> int:
        contract = self.store.task_contract_for_task(task_id)
        if contract is None:
            raise ValidatorLedgerError("TASK_CONTRACT_NOT_BOUND")

        validator = str(validator).strip()
        if validator not in VALIDATORS:
            raise ValidatorLedgerError(f"UNKNOWN_VALIDATOR:{validator}")
        normalized_status = str(status).strip().lower()
        if normalized_status not in _VALIDATOR_STATUSES:
            raise ValidatorLedgerError("validator status must be passed or failed")
        version = str(validator_version).strip()
        if not version or len(version) > 64 or any(ch.isspace() for ch in version):
            raise ValidatorLedgerError("validator_version must be a compact identifier")
        code = str(reason_code).strip().upper()
        if not _REASON_CODE.fullmatch(code):
            raise ValidatorLedgerError("reason_code must be a compact machine-readable code")
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
            raise ValidatorLedgerError("attempt must be an integer >= 1")
        refs = self._normalize_refs(evidence_refs)

        result_id = self.store.record_validator_result(
            task_id,
            validator,
            version,
            normalized_status,
            code,
            refs,
            attempt,
        )
        self.store.record_activity(
            task_id,
            "validator_bus",
            "validator_result_recorded",
            "ok" if normalized_status == "passed" else "error",
            (
                f"validator={validator} version={version} status={normalized_status} "
                f"reason={code} attempt={attempt} refs={len(refs)}"
            ),
        )
        return result_id

    def evaluate(self, task_id: str) -> TaskVerificationState:
        self.store.get_task(task_id)
        contract = self.store.task_contract_for_task(task_id)
        record = self.store.task_contract_record(task_id)
        rows = self.store.validator_results_for_task(task_id)

        if contract is None or record is None:
            return TaskVerificationState(
                task_id=task_id,
                contract_bound=False,
                contract_sha256=None,
                required_validators=(),
                passed_validators=(),
                failed_validators=(),
                missing_validators=(),
                verified=False,
                first_pass_verified=False,
                result_count=len(rows),
            )

        raw_required = contract.get("validators", [])
        required = tuple(
            dict.fromkeys(
                str(item).strip()
                for item in raw_required
                if str(item).strip() in VALIDATORS
            )
        ) if isinstance(raw_required, list) else ()

        by_validator: dict[str, list] = {}
        for row in rows:
            name = str(row["validator"])
            by_validator.setdefault(name, []).append(row)

        passed: list[str] = []
        failed: list[str] = []
        missing: list[str] = []
        first_pass = True
        for name in required:
            events = by_validator.get(name, [])
            if not events:
                missing.append(name)
                first_pass = False
                continue
            if str(events[-1]["status"]) == "passed":
                passed.append(name)
            else:
                failed.append(name)
            if str(events[0]["status"]) != "passed":
                first_pass = False

        verified = bool(required) and not failed and not missing and len(passed) == len(required)
        first_pass_verified = verified and first_pass
        return TaskVerificationState(
            task_id=task_id,
            contract_bound=True,
            contract_sha256=str(record["contract_sha256"]),
            required_validators=required,
            passed_validators=tuple(passed),
            failed_validators=tuple(failed),
            missing_validators=tuple(missing),
            verified=verified,
            first_pass_verified=first_pass_verified,
            result_count=len(rows),
        )

    def export_results(self, task_id: str) -> list[dict]:
        """Return metadata-only validator events for audit/metric aggregation."""
        self.store.get_task(task_id)
        result: list[dict] = []
        for row in self.store.validator_results_for_task(task_id):
            try:
                refs = json.loads(str(row["evidence_refs"]))
            except json.JSONDecodeError:
                refs = []
            result.append(
                {
                    "id": int(row["id"]),
                    "timestamp": str(row["timestamp"]),
                    "task_id": str(row["task_id"]),
                    "validator": str(row["validator"]),
                    "validator_version": str(row["validator_version"]),
                    "status": str(row["status"]),
                    "reason_code": str(row["reason_code"]),
                    "evidence_refs": refs if isinstance(refs, list) else [],
                    "attempt": int(row["attempt"]),
                }
            )
        return result
