from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .artifacts import ArtifactManager
from .handoff_security import (
    HandoffSecurityValidationError,
    verify_handoff_security_metadata,
)
from .models import TaskStatus
from .presentation_model import handoff_is_presentable
from .presentation_schemas import PRESENTATION_PLAN_SCHEMA_V1
from .route_planner import DeterministicRoutePlanner
from .store import TaskStore
from .task_contract import TaskContractCompiler
from .validator_ledger import TaskVerificationState, ValidatorLedger


class RuntimeValidationError(RuntimeError):
    """A deterministic runtime validation gate rejected the workflow."""


@dataclass(frozen=True)
class RuntimeValidationAttempt:
    contract_sha256: str


class RuntimeValidatorBridge:
    """Bind production workflow gates to the authoritative Validator Ledger.

    The bridge never asks a model whether work passed. It consumes deterministic
    contract policy, typed Research handoff integrity/readiness, Presentation
    lineage/QA artifacts, and compact hashes only. Raw prompts, source bodies,
    tool output, credentials and business content are never copied into the
    Validator Ledger.
    """

    def __init__(
        self,
        store: TaskStore,
        artifacts: ArtifactManager,
        *,
        confidentiality_mode: str,
        public_web: bool,
    ):
        self.store = store
        self.artifacts = artifacts
        self.ledger = ValidatorLedger(store)
        self.compiler = TaskContractCompiler()
        self.sensitivity = self._resolve_sensitivity(confidentiality_mode)
        self.public_web = bool(public_web)
        if self.public_web and self.sensitivity != "public":
            raise ValueError(
                "public_web runtime validation is permitted only in public-research mode"
            )

    @staticmethod
    def _resolve_sensitivity(confidentiality_mode: str) -> str:
        mode = str(confidentiality_mode or "").strip().lower()
        mapping = {
            "development-test": "internal",
            "public-research": "public",
            "public": "public",
            "internal": "internal",
            "confidential": "confidential",
            "restricted": "restricted",
            "secret": "secret",
        }
        if mode not in mapping:
            raise ValueError(
                "unsupported confidentiality_mode for runtime validation: "
                + (mode or "<empty>")
            )
        return mapping[mode]

    @staticmethod
    def _artifact_ref(path: Path) -> str:
        return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"

    @staticmethod
    def _load_json_object(path: Path) -> dict:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("artifact must contain one JSON object")
        return payload

    def _next_attempt(self, task_id: str, validator: str) -> int:
        attempts = [
            int(row["attempt"])
            for row in self.store.validator_results_for_task(task_id)
            if str(row["validator"]) == validator
        ]
        return max(attempts, default=0) + 1

    def _record(
        self,
        task_id: str,
        validator: str,
        *,
        passed: bool,
        reason_code: str,
        evidence_refs: Iterable[str] = (),
        validator_version: str,
    ) -> None:
        self.ledger.record(
            task_id,
            validator,
            status="passed" if passed else "failed",
            reason_code=reason_code,
            evidence_refs=evidence_refs,
            validator_version=validator_version,
            attempt=self._next_attempt(task_id, validator),
        )

    def begin(self, task_id: str) -> RuntimeValidationAttempt:
        """Compile, immutably bind, policy-validate, and expose the route decision."""
        contract = self.compiler.compile(
            task_id=task_id,
            task_type="analysis",
            sensitivity=self.sensitivity,
            risk_level="low",
            public_web=self.public_web,
            output_schema=PRESENTATION_PLAN_SCHEMA_V1,
        )
        try:
            digest = self.ledger.bind_contract(contract)
        except Exception as exc:
            # Preserve a failed policy event when an immutable contract already
            # exists. Never replace or mutate the bound contract.
            if self.store.task_contract_for_task(task_id) is not None:
                self._record(
                    task_id,
                    "policy",
                    passed=False,
                    reason_code="POLICY_CONTRACT_BIND_MISMATCH",
                    validator_version="runtime-policy/v2",
                )
            raise RuntimeValidationError("TASK_CONTRACT_BIND_FAILED") from exc

        self._record(
            task_id,
            "policy",
            passed=True,
            reason_code="POLICY_CONTRACT_VALIDATED",
            evidence_refs=(digest,),
            validator_version="runtime-policy/v2",
        )
        route = DeterministicRoutePlanner.plan(contract)
        self.store.record_activity(
            task_id,
            "route_planner",
            "route_selected",
            "ok",
            (
                f"route={route.route} reason={route.reason_code} "
                f"initial={route.initial_model_tier} max={route.max_model_tier} "
                f"escalation={str(route.escalation_allowed).lower()}"
            ),
        )
        return RuntimeValidationAttempt(contract_sha256=digest)

    def record_research_evidence(
        self,
        task_id: str,
        *,
        handoff_path: Path | None = None,
        task_status: TaskStatus | None = None,
    ) -> bool:
        """Record Research evidence outcome from the typed handoff artifact."""
        if handoff_path is None:
            handoff_path = self.artifacts.find_latest_task_artifact(
                "research", task_id, suffix="_handoff.json"
            )
        if handoff_path is None or not handoff_path.is_file():
            self._record(
                task_id,
                "evidence",
                passed=False,
                reason_code="EVIDENCE_HANDOFF_MISSING",
                validator_version="research-evidence/v2",
            )
            return False

        ref = self._artifact_ref(handoff_path)
        try:
            handoff = self._load_json_object(handoff_path)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            self._record(
                task_id,
                "evidence",
                passed=False,
                reason_code="EVIDENCE_HANDOFF_INVALID",
                evidence_refs=(ref,),
                validator_version="research-evidence/v2",
            )
            return False

        if str(handoff.get("task_id") or "") != task_id:
            self._record(
                task_id,
                "evidence",
                passed=False,
                reason_code="EVIDENCE_HANDOFF_TASK_MISMATCH",
                evidence_refs=(ref,),
                validator_version="research-evidence/v2",
            )
            return False

        try:
            verify_handoff_security_metadata(
                handoff,
                expected_source_agent="research",
                expected_target_agent="presentation",
                expected_task_id=task_id,
            )
        except (HandoffSecurityValidationError, TypeError, ValueError):
            self._record(
                task_id,
                "evidence",
                passed=False,
                reason_code="EVIDENCE_HANDOFF_INTEGRITY_FAIL",
                evidence_refs=(ref,),
                validator_version="research-evidence/v2",
            )
            return False

        ready, _ = handoff_is_presentable(handoff)
        if not ready:
            self._record(
                task_id,
                "evidence",
                passed=False,
                reason_code="EVIDENCE_HANDOFF_NOT_READY",
                evidence_refs=(ref,),
                validator_version="research-evidence/v2",
            )
            return False

        current_status = task_status or self.store.get_task(task_id).status
        if current_status != TaskStatus.RESEARCH_COMPLETED:
            self._record(
                task_id,
                "evidence",
                passed=False,
                reason_code="EVIDENCE_RESEARCH_STAGE_STATE_INVALID",
                evidence_refs=(ref,),
                validator_version="research-evidence/v2",
            )
            return False

        self._record(
            task_id,
            "evidence",
            passed=True,
            reason_code="EVIDENCE_HANDOFF_VERIFIED",
            evidence_refs=(ref,),
            validator_version="research-evidence/v2",
        )
        return True

    def record_presentation_validation(
        self,
        task_id: str,
        *,
        presentation_path: Path | None = None,
        handoff_path: Path | None = None,
        task_status: TaskStatus | None = None,
    ) -> bool:
        """Record deterministic Presentation schema/semantic/lineage validation."""
        if presentation_path is None:
            presentation_path = self.artifacts.find_latest_task_artifact(
                "presentations", task_id, suffix=".json"
            )
        if presentation_path is None or not presentation_path.is_file():
            self._record(
                task_id,
                "schema",
                passed=False,
                reason_code="PRESENTATION_ARTIFACT_MISSING",
                validator_version="presentation-validation/v2",
            )
            return False

        presentation_ref = self._artifact_ref(presentation_path)
        refs: tuple[str, ...] = (presentation_ref,)
        try:
            payload = self._load_json_object(presentation_path)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            self._record(
                task_id,
                "schema",
                passed=False,
                reason_code="PRESENTATION_ARTIFACT_INVALID",
                evidence_refs=refs,
                validator_version="presentation-validation/v2",
            )
            return False

        if str(payload.get("task_id") or "") != task_id:
            self._record(
                task_id,
                "schema",
                passed=False,
                reason_code="PRESENTATION_TASK_MISMATCH",
                evidence_refs=refs,
                validator_version="presentation-validation/v2",
            )
            return False

        if handoff_path is None:
            handoff_path = self.artifacts.find_latest_task_artifact(
                "research", task_id, suffix="_handoff.json"
            )
        if handoff_path is None or not handoff_path.is_file():
            self._record(
                task_id,
                "schema",
                passed=False,
                reason_code="PRESENTATION_LINEAGE_MISSING",
                evidence_refs=refs,
                validator_version="presentation-validation/v2",
            )
            return False

        handoff_ref = self._artifact_ref(handoff_path)
        refs = (presentation_ref, handoff_ref)
        if str(payload.get("source_research_handoff_sha256") or "") != handoff_ref:
            self._record(
                task_id,
                "schema",
                passed=False,
                reason_code="PRESENTATION_LINEAGE_MISMATCH",
                evidence_refs=refs,
                validator_version="presentation-validation/v2",
            )
            return False

        plan = payload.get("plan")
        qa = payload.get("qa")
        current_status = task_status or self.store.get_task(task_id).status
        qa_status = str(qa.get("status") or "") if isinstance(qa, dict) else ""
        valid = (
            isinstance(plan, dict)
            and plan.get("schema_version") == "presentation-plan/v1"
            and isinstance(qa, dict)
            and qa.get("schema_version") == "presentation-qa/v1"
            and qa_status in {"pass", "dry_run"}
            and qa.get("errors") == []
            and qa.get("visible_facts_source_bounded") is True
            and current_status == TaskStatus.PRESENTATION_COMPLETED
        )
        self._record(
            task_id,
            "schema",
            passed=valid,
            reason_code=(
                "PRESENTATION_VALIDATION_PASS"
                if valid
                else "PRESENTATION_VALIDATION_FAILED"
            ),
            evidence_refs=refs,
            validator_version="presentation-validation/v2",
        )
        return valid

    def evaluate(self, task_id: str) -> TaskVerificationState:
        return self.ledger.evaluate(task_id)
