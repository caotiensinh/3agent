from __future__ import annotations

import json
from contextvars import ContextVar
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterable

from .artifacts import ArtifactManager
from .handoff_security import (
    HandoffSecurityValidationError,
    verify_handoff_security_metadata,
)
from .models import TaskStatus
from .store import TaskStore
from .task_contract import TaskContractCompiler
from .validator_ledger import TaskVerificationState, ValidatorLedger


class RuntimeValidationError(RuntimeError):
    """A deterministic runtime validation gate rejected the workflow."""


_ACTIVE_WORKFLOW_TASK: ContextVar[str | None] = ContextVar(
    "workspace_active_validated_workflow_task",
    default=None,
)


class RuntimeValidatorBridge:
    """Bind workflow execution to TaskContract/Validator Ledger evidence.

    This bridge grants no runtime authority. It observes deterministic workflow
    outputs and records metadata-only validator results so D3 verified-success
    metrics reflect real production execution rather than TaskStatus or model
    self-reports.
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
        status: str,
        reason_code: str,
        evidence_refs: Iterable[str] = (),
        validator_version: str,
    ) -> int:
        return self.ledger.record(
            task_id,
            validator,
            status=status,
            reason_code=reason_code,
            evidence_refs=evidence_refs,
            validator_version=validator_version,
            attempt=self._next_attempt(task_id, validator),
        )

    def begin(self, task_id: str) -> TaskVerificationState:
        contract = self.compiler.compile(
            task_id=task_id,
            task_type="analysis",
            sensitivity=self.sensitivity,
            risk_level="low",
            public_web=self.public_web,
        )
        contract = replace(
            contract,
            validators=tuple(
                dict.fromkeys((*contract.validators, "integration_test"))
            ),
            policy_reason_codes=tuple(
                dict.fromkeys(
                    (*contract.policy_reason_codes, "WORKFLOW_E2E_VALIDATION")
                )
            ),
        ).validate()
        digest = self.ledger.bind_contract(contract)
        self._record(
            task_id,
            "policy",
            status="passed",
            reason_code="POLICY_CONTRACT_VALIDATED",
            evidence_refs=[digest],
            validator_version="runtime-policy-v1",
        )
        return self.ledger.evaluate(task_id)

    def record_evidence_failure(
        self,
        task_id: str,
        reason_code: str,
    ) -> TaskVerificationState:
        if self.store.task_contract_for_task(task_id) is None:
            return self.ledger.evaluate(task_id)
        self._record(
            task_id,
            "evidence",
            status="failed",
            reason_code=reason_code,
            validator_version="research-evidence-v1",
        )
        return self.ledger.evaluate(task_id)

    def validate_research_evidence(self, task_id: str) -> TaskVerificationState:
        handoff_path = self.artifacts.find_latest_task_artifact(
            "research",
            task_id,
            suffix="_handoff.json",
        )
        if handoff_path is None:
            self.record_evidence_failure(task_id, "EVIDENCE_HANDOFF_MISSING")
            raise RuntimeValidationError("EVIDENCE_HANDOFF_MISSING")

        try:
            payload = json.loads(handoff_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeError) as exc:
            self.record_evidence_failure(task_id, "EVIDENCE_HANDOFF_INVALID")
            raise RuntimeValidationError("EVIDENCE_HANDOFF_INVALID") from exc
        if not isinstance(payload, dict):
            self.record_evidence_failure(task_id, "EVIDENCE_HANDOFF_INVALID")
            raise RuntimeValidationError("EVIDENCE_HANDOFF_INVALID")

        try:
            security = verify_handoff_security_metadata(
                payload,
                expected_source_agent="research",
                expected_target_agent="presentation",
                expected_task_id=task_id,
            )
        except HandoffSecurityValidationError as exc:
            self.record_evidence_failure(
                task_id,
                "EVIDENCE_HANDOFF_INTEGRITY_FAIL",
            )
            raise RuntimeValidationError(
                "EVIDENCE_HANDOFF_INTEGRITY_FAIL"
            ) from exc

        blockers = payload.get("blockers")
        key_facts = payload.get("key_facts")
        if (
            payload.get("presentation_ready") is not True
            or not isinstance(blockers, list)
            or blockers
            or not isinstance(key_facts, list)
            or not any(isinstance(item, dict) for item in key_facts)
        ):
            self.record_evidence_failure(
                task_id,
                "EVIDENCE_HANDOFF_NOT_READY",
            )
            raise RuntimeValidationError("EVIDENCE_HANDOFF_NOT_READY")

        content_hash = str(security.get("content_hash") or "")
        refs = [content_hash] if content_hash.startswith("sha256:") else []
        self._record(
            task_id,
            "evidence",
            status="passed",
            reason_code="EVIDENCE_HANDOFF_VERIFIED",
            evidence_refs=refs,
            validator_version="research-evidence-v1",
        )
        return self.ledger.evaluate(task_id)

    @staticmethod
    def _paths_exist(paths: Iterable[Any]) -> tuple[bool, int]:
        count = 0
        for raw in paths:
            path = Path(str(raw))
            if not path.exists() or not path.is_file():
                return False, count
            count += 1
        return count > 0, count

    def finalize(
        self,
        task_id: str,
        *,
        daily_success: bool,
        daily_paths: Iterable[Any] = (),
    ) -> TaskVerificationState:
        if self.store.task_contract_for_task(task_id) is None:
            return self.ledger.evaluate(task_id)

        task = self.store.get_task(task_id)
        pre = self.ledger.evaluate(task_id)
        presentation_path = self.artifacts.find_latest_task_artifact(
            "presentations",
            task_id,
            suffix=".json",
        )
        daily_ok, daily_count = self._paths_exist(daily_paths)

        reason = "WORKFLOW_E2E_PASS"
        passed = True
        if not daily_success:
            passed = False
            reason = "WORKFLOW_DAILY_FAILED"
        elif task.status != TaskStatus.DONE:
            passed = False
            reason = "WORKFLOW_TASK_NOT_DONE"
        elif "evidence" not in pre.passed_validators:
            passed = False
            reason = "WORKFLOW_EVIDENCE_NOT_VERIFIED"
        elif presentation_path is None or not presentation_path.is_file():
            passed = False
            reason = "WORKFLOW_PRESENTATION_MISSING"
        elif not daily_ok:
            passed = False
            reason = "WORKFLOW_DAILY_ARTIFACT_MISSING"

        refs: list[str] = []
        if passed:
            refs = [
                f"task:{task_id}",
                "artifact:research_handoff:1",
                "artifact:presentation:1",
                f"artifact:daily_report:{daily_count}",
            ]
        self._record(
            task_id,
            "integration_test",
            status="passed" if passed else "failed",
            reason_code=reason,
            evidence_refs=refs,
            validator_version="workflow-e2e-v1",
        )
        return self.ledger.evaluate(task_id)


class _DelegatingProxy:
    def __init__(self, agent: Any, bridge: RuntimeValidatorBridge):
        self._agent = agent
        self._bridge = bridge

    def __getattr__(self, name: str) -> Any:
        return getattr(self._agent, name)


class WorkflowResearchValidationProxy(_DelegatingProxy):
    """Validate/bind the task before research and verify its handoff afterward."""

    def run(
        self,
        task_id: str,
        store: TaskStore,
        artifacts: ArtifactManager,
        live: bool = False,
    ):
        _ACTIVE_WORKFLOW_TASK.set(task_id)
        self._bridge.begin(task_id)
        try:
            result = self._agent.run(
                task_id,
                store,
                artifacts,
                live=live,
            )
        except Exception:
            self._bridge.record_evidence_failure(
                task_id,
                "EVIDENCE_RESEARCH_STAGE_FAILED",
            )
            raise

        task = store.get_task(task_id)
        if task.status != TaskStatus.RESEARCH_COMPLETED:
            self._bridge.record_evidence_failure(
                task_id,
                "EVIDENCE_RESEARCH_NOT_READY",
            )
            return result

        self._bridge.validate_research_evidence(task_id)
        return result


class WorkflowDailyValidationProxy(_DelegatingProxy):
    """Close the integration validator around the date-wide Daily Report stage."""

    def run(
        self,
        date: str,
        store: TaskStore,
        artifacts: ArtifactManager,
        live: bool = False,
    ):
        task_id = _ACTIVE_WORKFLOW_TASK.get()
        try:
            result = self._agent.run(
                date,
                store,
                artifacts,
                live=live,
            )
        except Exception:
            if task_id:
                self._bridge.finalize(
                    task_id,
                    daily_success=False,
                    daily_paths=(),
                )
            _ACTIVE_WORKFLOW_TASK.set(None)
            raise

        try:
            if task_id:
                state = self._bridge.finalize(
                    task_id,
                    daily_success=True,
                    daily_paths=result if isinstance(result, (list, tuple)) else (result,),
                )
                task = store.get_task(task_id)
                if task.status == TaskStatus.DONE and not state.verified:
                    raise RuntimeValidationError(
                        "WORKFLOW_VERIFICATION_FAILED"
                    )
            return result
        finally:
            _ACTIVE_WORKFLOW_TASK.set(None)
