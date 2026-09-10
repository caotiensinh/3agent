"""Deterministic admission gate for future WorkSpace reflection.

Phase 4A decides whether a completed workflow is trustworthy enough to become
learning input. It does not run an LLM, create knowledge, grant capabilities, or
write to the adaptive-learning store.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import TaskStatus
from .store import TaskStore
from .task_contract import (
    CachePolicy,
    ContextBudget,
    ExecutionBudget,
    GenerationBudget,
    LoggingPolicy,
    ModelPolicy,
    TaskContract,
)
from .validator_ledger import ValidatorLedger

ADMISSION_SCHEMA = "workspace-learning-admission/v1"
MANIFEST_SCHEMA = "workflow-run/v1"
_MAX_MANIFEST_BYTES = 1_048_576
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_SENSITIVITY_ORDER = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
    "secret": 4,
}
_MANIFEST_FIELDS = {
    "schema_version",
    "task_id",
    "status",
    "task_status",
    "stage",
    "business_stage",
    "live",
    "report_date",
    "options",
    "research_artifacts",
    "presentation_artifacts",
    "daily_report_artifacts",
    "verification",
    "execution_budget",
    "model_authority",
    "error",
    "started_at",
    "completed_at",
}
_FORBIDDEN_ENVELOPE_FIELDS = {
    "request",
    "raw_request",
    "prompt",
    "raw_prompt",
    "uploads",
    "upload_ids",
    "artifact_paths",
    "research_artifacts",
    "presentation_artifacts",
    "daily_report_artifacts",
    "allowed_tools",
    "write_scope",
    "network_scope",
    "model_policy",
    "model_authority",
    "execution_budget",
    "credentials",
    "secrets",
    "started_at",
    "completed_at",
}


class LearningAdmissionError(ValueError):
    """A workflow failed a deterministic learning-source admission rule."""

    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code)
        super().__init__(self.reason_code)


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _bytes_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _task_contract_from_payload(payload: dict[str, Any]) -> TaskContract:
    """Reconstruct and validate the exact bound TaskContract, not a subset."""
    try:
        data = dict(payload)
        data["allowed_sources"] = tuple(data["allowed_sources"])
        data["allowed_tools"] = tuple(data["allowed_tools"])
        data["validators"] = tuple(data["validators"])
        data["policy_reason_codes"] = tuple(data.get("policy_reason_codes", ()))
        if isinstance(data.get("write_scope"), list):
            data["write_scope"] = tuple(data["write_scope"])
        data["context_budget"] = ContextBudget(**data["context_budget"])
        data["generation_budget"] = GenerationBudget(**data["generation_budget"])
        data["execution_budget"] = ExecutionBudget(**data["execution_budget"])
        data["model_policy"] = ModelPolicy(**data["model_policy"])
        data["cache_policy"] = CachePolicy(**data["cache_policy"])
        data["logging_policy"] = LoggingPolicy(**data["logging_policy"])
        return TaskContract(**data).validate()
    except (KeyError, TypeError, ValueError) as exc:
        raise LearningAdmissionError("LEARNING_CONTRACT_INVALID") from exc


def _parse_aware_timestamp(value: Any) -> datetime:
    text = str(value or "").strip()
    if not text or len(text) > 64:
        raise LearningAdmissionError("LEARNING_MANIFEST_TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LearningAdmissionError("LEARNING_MANIFEST_TIME_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise LearningAdmissionError("LEARNING_MANIFEST_TIME_INVALID")
    return parsed


@dataclass(frozen=True)
class VerifiedLearningSourceEnvelope:
    """Metadata-only, capability-free input boundary for future Reflection."""

    admission_id: str
    task_id: str
    task_type: str
    outcome: str
    sensitivity: str
    risk_level: str
    contract_sha256: str
    manifest_sha256: str
    validator_provenance_sha256: str
    provenance_sha256: str
    evidence_hashes: tuple[str, ...]
    required_validators: tuple[str, ...]
    capability_grants: tuple[str, ...] = ()
    schema_version: str = ADMISSION_SCHEMA

    def to_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["evidence_hashes"] = list(self.evidence_hashes)
        payload["required_validators"] = list(self.required_validators)
        payload["capability_grants"] = list(self.capability_grants)
        if set(payload) & _FORBIDDEN_ENVELOPE_FIELDS:
            raise LearningAdmissionError("LEARNING_ENVELOPE_AUTHORITY_FIELD_FORBIDDEN")
        return payload


class DeterministicLearningAdmission:
    """Admit only exact, evidence-backed DONE workflows for future reflection."""

    def __init__(self, store: TaskStore):
        self.store = store
        self.ledger = ValidatorLedger(store)

    def _bound_contract(self, task_id: str) -> tuple[TaskContract, str]:
        payload = self.store.task_contract_for_task(task_id)
        record = self.store.task_contract_record(task_id)
        if payload is None or record is None:
            raise LearningAdmissionError("LEARNING_CONTRACT_NOT_BOUND")
        if not isinstance(payload, dict):
            raise LearningAdmissionError("LEARNING_CONTRACT_INVALID")
        recomputed = _digest(payload)
        stored = str(record["contract_sha256"] or "").lower()
        if recomputed != stored:
            raise LearningAdmissionError("LEARNING_CONTRACT_DIGEST_MISMATCH")
        contract = _task_contract_from_payload(payload)
        if contract.task_id != task_id:
            raise LearningAdmissionError("LEARNING_CONTRACT_TASK_MISMATCH")
        return contract, stored

    @staticmethod
    def _load_manifest(path: Path) -> tuple[dict[str, Any], str]:
        manifest_path = Path(path)
        try:
            raw = manifest_path.read_bytes()
        except OSError as exc:
            raise LearningAdmissionError("LEARNING_MANIFEST_UNREADABLE") from exc
        if not raw or len(raw) > _MAX_MANIFEST_BYTES:
            raise LearningAdmissionError("LEARNING_MANIFEST_SIZE_INVALID")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LearningAdmissionError("LEARNING_MANIFEST_INVALID_JSON") from exc
        if not isinstance(payload, dict) or set(payload) != _MANIFEST_FIELDS:
            raise LearningAdmissionError("LEARNING_MANIFEST_SCHEMA_INVALID")
        if payload.get("schema_version") != MANIFEST_SCHEMA:
            raise LearningAdmissionError("LEARNING_MANIFEST_SCHEMA_INVALID")
        if not isinstance(payload.get("live"), bool) or not isinstance(payload.get("options"), dict):
            raise LearningAdmissionError("LEARNING_MANIFEST_SCHEMA_INVALID")
        for field in (
            "research_artifacts",
            "presentation_artifacts",
            "daily_report_artifacts",
        ):
            values = payload.get(field)
            if (
                not isinstance(values, list)
                or len(values) > 128
                or any(not isinstance(item, str) for item in values)
            ):
                raise LearningAdmissionError("LEARNING_MANIFEST_SCHEMA_INVALID")
        started_at = _parse_aware_timestamp(payload.get("started_at"))
        completed_at = _parse_aware_timestamp(payload.get("completed_at"))
        if completed_at < started_at:
            raise LearningAdmissionError("LEARNING_MANIFEST_TIME_INVALID")
        return payload, _bytes_digest(raw)

    @staticmethod
    def _evidence_hashes(events: list[dict[str, Any]]) -> tuple[str, ...]:
        """Accept only content-addressed refs from the final evidence validator."""
        final_event: dict[str, Any] | None = None
        for event in events:
            if str(event.get("validator") or "") == "evidence":
                final_event = event
        if final_event is None or final_event.get("status") != "passed":
            raise LearningAdmissionError("LEARNING_EVIDENCE_VALIDATOR_NOT_PASSED")
        refs = final_event.get("evidence_refs")
        if not isinstance(refs, list) or not refs:
            raise LearningAdmissionError("LEARNING_EVIDENCE_HASHES_MISSING")
        hashes: list[str] = []
        for raw in refs:
            ref = str(raw).strip().lower()
            if not _SHA.fullmatch(ref):
                raise LearningAdmissionError("LEARNING_EVIDENCE_NOT_CONTENT_ADDRESSED")
            if ref not in hashes:
                hashes.append(ref)
        return tuple(hashes)

    def admit(
        self,
        task_id: str,
        manifest_path: Path,
        *,
        requested_sensitivity: str | None = None,
    ) -> VerifiedLearningSourceEnvelope:
        task = self.store.get_task(task_id)
        if task.status == TaskStatus.WAITING_HUMAN:
            raise LearningAdmissionError("LEARNING_SOURCE_WAITING_HUMAN")
        if task.status == TaskStatus.FAILED:
            raise LearningAdmissionError("LEARNING_SOURCE_FAILED")
        if task.status != TaskStatus.DONE:
            raise LearningAdmissionError("LEARNING_SOURCE_NOT_DONE")

        contract, contract_sha256 = self._bound_contract(task_id)
        if not contract.evidence_required:
            raise LearningAdmissionError("LEARNING_SOURCE_EVIDENCE_NOT_REQUIRED")

        sensitivity = contract.sensitivity
        if requested_sensitivity is not None:
            requested = str(requested_sensitivity).strip().lower()
            if requested not in _SENSITIVITY_ORDER:
                raise LearningAdmissionError("LEARNING_SENSITIVITY_INVALID")
            if _SENSITIVITY_ORDER[requested] < _SENSITIVITY_ORDER[contract.sensitivity]:
                raise LearningAdmissionError("LEARNING_SENSITIVITY_DOWNGRADE_DENIED")
            sensitivity = requested

        verification = self.ledger.evaluate(task_id)
        if not verification.contract_bound or verification.contract_sha256 != contract_sha256:
            raise LearningAdmissionError("LEARNING_VERIFICATION_CONTRACT_MISMATCH")
        if not verification.verified:
            if verification.failed_validators:
                raise LearningAdmissionError("LEARNING_REQUIRED_VALIDATOR_FAILED")
            if verification.missing_validators:
                raise LearningAdmissionError("LEARNING_REQUIRED_VALIDATOR_MISSING")
            raise LearningAdmissionError("LEARNING_VERIFICATION_NOT_PASSED")
        if "evidence" not in verification.required_validators:
            raise LearningAdmissionError("LEARNING_EVIDENCE_VALIDATOR_NOT_REQUIRED")

        manifest, manifest_sha256 = self._load_manifest(Path(manifest_path))
        if str(manifest.get("task_id") or "") != task_id:
            raise LearningAdmissionError("LEARNING_MANIFEST_TASK_MISMATCH")
        if manifest.get("status") != "completed" or manifest.get("task_status") != "DONE":
            raise LearningAdmissionError("LEARNING_MANIFEST_OUTCOME_NOT_VERIFIED_SUCCESS")
        if manifest.get("business_stage") != "task_completed" or manifest.get("error") is not None:
            raise LearningAdmissionError("LEARNING_MANIFEST_COMPLETION_INVALID")
        if manifest.get("verification") != verification.to_dict():
            raise LearningAdmissionError("LEARNING_MANIFEST_VERIFICATION_MISMATCH")

        events = self.ledger.export_results(task_id)
        validator_provenance_sha256 = _digest(
            {
                "schema_version": "workspace-learning-validator-provenance/v1",
                "task_id": task_id,
                "events": events,
            }
        )
        evidence_hashes = self._evidence_hashes(events)

        # The exact manifest hash remains in the envelope for audit, but does not
        # create a distinct trusted experience when only non-authoritative manifest
        # bytes change. Authoritative task/contract/validator/evidence provenance
        # controls admission identity and prevents self-reinforcement by replay.
        provenance_payload = {
            "schema_version": "workspace-learning-admission-provenance/v1",
            "task_id": task_id,
            "task_status": task.status.value,
            "task_type": contract.task_type,
            "contract_sha256": contract_sha256,
            "validator_provenance_sha256": validator_provenance_sha256,
            "verification": verification.to_dict(),
            "sensitivity": sensitivity,
            "risk_level": contract.risk_level,
            "evidence_hashes": list(evidence_hashes),
        }
        provenance_sha256 = _digest(provenance_payload)

        # Effective classification is audit provenance, not a source-identity
        # dimension. A trusted caller may raise classification without creating a
        # second trusted experience from the same authoritative source. Reusing the
        # historical provenance shape with the bound contract sensitivity keeps
        # default (non-upgraded) admission IDs backward-compatible.
        source_identity_payload = dict(provenance_payload)
        source_identity_payload["sensitivity"] = contract.sensitivity
        source_identity_sha256 = _digest(source_identity_payload)
        admission_id = "admission:" + source_identity_sha256.split(":", 1)[1]

        envelope = VerifiedLearningSourceEnvelope(
            admission_id=admission_id,
            task_id=task_id,
            task_type=contract.task_type,
            outcome="verified_success",
            sensitivity=sensitivity,
            risk_level=contract.risk_level,
            contract_sha256=contract_sha256,
            manifest_sha256=manifest_sha256,
            validator_provenance_sha256=validator_provenance_sha256,
            provenance_sha256=provenance_sha256,
            evidence_hashes=evidence_hashes,
            required_validators=verification.required_validators,
        )
        envelope.to_payload()
        return envelope
