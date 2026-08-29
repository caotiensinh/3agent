from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from .artifacts import ArtifactManager
from .execution_budget import TaskExecutionBudgetState
from .inference_scope import inference_scope
from .model_authority import TaskModelAuthority
from .models import TaskStatus
from .runtime_validation import RuntimeValidatorBridge
from .store import TaskStore

TZ = ZoneInfo("Asia/Tokyo")

_SECRET_PATTERNS = (
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)((?:token|password|passwd|secret|api[_-]?key|authorization)\s*[:=]\s*)[^\s,&;]+"),
    re.compile(r"(?i)((?:token|password|secret|api[_-]?key)=)[^&\s]+"),
)


@dataclass
class WorkflowRunResult:
    task_id: str
    status: str
    task_status: str
    stage: str
    research_artifacts: list[str]
    presentation_artifacts: list[str]
    daily_report_artifacts: list[str]
    error: str | None
    manifest_path: str


class WorkflowRunner:
    """Run Research -> Presentation -> Daily Report as one auditable workflow.

    Production construction supplies RuntimeValidatorBridge. In that path the
    TaskContract, persistent execution budget and immutable model-authority
    envelope are bound before Research. The same authority envelope is carried
    through Research and Presentation, so changing model tier cannot expand
    source/tool/network/write authority. DONE still requires verified validators.
    """

    def __init__(
        self,
        store: TaskStore,
        artifacts: ArtifactManager,
        research_agent: Any,
        presentation_agent: Any,
        daily_agent: Any,
        *,
        validator_bridge: RuntimeValidatorBridge | None = None,
    ):
        self.store = store
        self.artifacts = artifacts
        self.research_agent = research_agent
        self.presentation_agent = presentation_agent
        self.daily_agent = daily_agent
        self.validator_bridge = validator_bridge

    @staticmethod
    def _safe_error(exc: Exception) -> str:
        text = f"{type(exc).__name__}: {exc}".replace("\n", " ")[:1200]
        for pattern in _SECRET_PATTERNS:
            text = pattern.sub(lambda m: f"{m.group(1)}<redacted>", text)
        return text

    @staticmethod
    def _release_agent_model(agent: Any, *, live: bool) -> None:
        if not live:
            return
        llm = getattr(agent, "llm", None)
        if bool(getattr(llm, "budget_managed_residency", False)):
            return
        unload = getattr(llm, "unload", None)
        if callable(unload):
            try:
                unload()
            except Exception:
                return

    @staticmethod
    def _path_with_suffix(paths: list[str], suffix: str) -> Path | None:
        for raw in paths:
            path = Path(raw)
            if path.name.endswith(suffix):
                return path
        return None

    @staticmethod
    def result_dict(result: WorkflowRunResult) -> dict[str, Any]:
        return asdict(result)

    def _write_manifest(self, payload: dict[str, Any]) -> Path:
        folder = self.artifacts.root / "workflow_runs" / self.artifacts.today()
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{payload['task_id']}.json"
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def create_and_run(
        self,
        title: str,
        request: str,
        *,
        live: bool = False,
        audience: str = "R&D internal",
        purpose: str = "inform",
        language: str = "ja",
        slide_count: int = 6,
        output_format: str = "pptx",
        report_date: str | None = None,
    ) -> WorkflowRunResult:
        task = self.store.create_task(title, request)
        return self.run_task(
            task.task_id,
            live=live,
            audience=audience,
            purpose=purpose,
            language=language,
            slide_count=slide_count,
            output_format=output_format,
            report_date=report_date,
        )

    def run_task(
        self,
        task_id: str,
        *,
        live: bool = False,
        audience: str = "R&D internal",
        purpose: str = "inform",
        language: str = "ja",
        slide_count: int = 6,
        output_format: str = "pptx",
        report_date: str | None = None,
    ) -> WorkflowRunResult:
        self.store.get_task(task_id)
        started_at = datetime.now(TZ).isoformat()
        target_date = report_date or datetime.now(TZ).strftime("%Y-%m-%d")
        research_paths: list[str] = []
        presentation_paths: list[str] = []
        daily_paths: list[str] = []
        error: str | None = None
        stage = "contract" if self.validator_bridge is not None else "research"
        outcome = "failed"
        bridge_bound = False
        verification = None
        execution_budget: TaskExecutionBudgetState | None = None
        model_authority: TaskModelAuthority | None = None
        handoff_path: Path | None = None
        presentation_path: Path | None = None

        self.store.record_activity(
            task_id,
            "workflow",
            "workflow_started",
            "ok",
            f"live={live} report_date={target_date} format={output_format}",
        )

        try:
            if self.validator_bridge is not None:
                attempt = self.validator_bridge.begin(task_id)
                bridge_bound = True
                execution_budget = attempt.execution_budget
                model_authority = attempt.model_authority
                self.store.record_activity(
                    task_id,
                    "workflow",
                    "runtime_validator_bridge_bound",
                    "ok",
                    f"contract={attempt.contract_sha256}",
                )

            stage = "research"
            try:
                with inference_scope(
                    task_id,
                    agent_id="research",
                    stage="research",
                    execution_budget=execution_budget,
                    model_authority=model_authority,
                ):
                    paths = self.research_agent.run(
                        task_id, self.store, self.artifacts, live=live
                    )
                research_paths = [str(path) for path in paths]
            except Exception:
                if bridge_bound:
                    handoff_path = self._path_with_suffix(
                        research_paths, "_handoff.json"
                    )
                    self.validator_bridge.record_research_evidence(
                        task_id,
                        handoff_path=handoff_path,
                        task_status=self.store.get_task(task_id).status,
                    )
                raise
            finally:
                self._release_agent_model(self.research_agent, live=live)

            task = self.store.get_task(task_id)
            if bridge_bound:
                handoff_path = self._path_with_suffix(
                    research_paths, "_handoff.json"
                )
                evidence_passed = self.validator_bridge.record_research_evidence(
                    task_id,
                    handoff_path=handoff_path,
                    task_status=task.status,
                )
                if not evidence_passed:
                    stage = "research_gate"
                    if task.status == TaskStatus.WAITING_HUMAN:
                        outcome = "blocked"
                    else:
                        outcome = "failed"
                        error = "RuntimeValidationError: RESEARCH_EVIDENCE_VALIDATION_FAILED"
                        if task.status != TaskStatus.FAILED:
                            self.store.set_status(task_id, TaskStatus.FAILED)
                    self.store.record_activity(
                        task_id,
                        "workflow",
                        "presentation_skipped",
                        "blocked" if outcome == "blocked" else "error",
                        "required research evidence validator did not pass",
                    )
                else:
                    outcome = "continue"
            elif task.status != TaskStatus.RESEARCH_COMPLETED:
                outcome = "blocked"
                stage = "research_gate"
                self.store.record_activity(
                    task_id,
                    "workflow",
                    "presentation_skipped",
                    "blocked",
                    f"research_status={task.status.value}",
                )
            else:
                outcome = "continue"

            if outcome == "continue":
                stage = "presentation"
                try:
                    with inference_scope(
                        task_id,
                        agent_id="presentation",
                        stage="presentation",
                        execution_budget=execution_budget,
                        model_authority=model_authority,
                    ):
                        paths = self.presentation_agent.run(
                            task_id,
                            self.store,
                            self.artifacts,
                            live=live,
                            audience=audience,
                            purpose=purpose,
                            language=language,
                            slide_count=slide_count,
                            output_format=output_format,
                        )
                    presentation_paths = [str(path) for path in paths]
                except Exception:
                    if bridge_bound:
                        presentation_path = self._path_with_suffix(
                            presentation_paths, ".json"
                        )
                        self.validator_bridge.record_presentation_validation(
                            task_id,
                            presentation_path=presentation_path,
                            handoff_path=handoff_path,
                            task_status=self.store.get_task(task_id).status,
                        )
                    raise
                finally:
                    self._release_agent_model(self.presentation_agent, live=live)

                task = self.store.get_task(task_id)
                if task.status != TaskStatus.PRESENTATION_COMPLETED:
                    raise RuntimeError(
                        f"Presentation Agent returned without completion: {task.status.value}"
                    )

                if bridge_bound:
                    presentation_path = self._path_with_suffix(
                        presentation_paths, ".json"
                    )
                    schema_passed = self.validator_bridge.record_presentation_validation(
                        task_id,
                        presentation_path=presentation_path,
                        handoff_path=handoff_path,
                        task_status=task.status,
                    )
                    if not schema_passed:
                        stage = "validator_gate"
                        self.store.set_status(task_id, TaskStatus.FAILED)
                        raise RuntimeError("PRESENTATION_VALIDATION_FAILED")

                    verification = self.validator_bridge.evaluate(task_id)
                    if not verification.verified:
                        stage = "validator_gate"
                        self.store.set_status(task_id, TaskStatus.FAILED)
                        self.store.record_activity(
                            task_id,
                            "workflow",
                            "runtime_verification_failed",
                            "error",
                            (
                                f"missing={','.join(verification.missing_validators)} "
                                f"failed={','.join(verification.failed_validators)}"
                            ),
                        )
                        raise RuntimeError("REQUIRED_VALIDATOR_NOT_PASSED")

                self.store.set_status(task_id, TaskStatus.DONE)
                outcome = "completed"
                stage = "task_completed"
                self.store.record_activity(
                    task_id,
                    "workflow",
                    "task_workflow_completed",
                    "ok",
                    (
                        "Required runtime validators passed; task marked DONE."
                        if bridge_bound
                        else "Research and presentation stages completed; task marked DONE."
                    ),
                )
        except Exception as exc:
            error = self._safe_error(exc)
            current = self.store.get_task(task_id)
            if current.status not in {TaskStatus.FAILED, TaskStatus.WAITING_HUMAN}:
                self.store.set_status(task_id, TaskStatus.FAILED)
            outcome = "failed"
            self.store.record_activity(
                task_id,
                "workflow",
                "workflow_stage_failed",
                "error",
                f"stage={stage} {error}",
            )

        if self.validator_bridge is not None:
            try:
                verification = self.validator_bridge.evaluate(task_id)
            except Exception:
                verification = None

        business_stage = stage
        try:
            stage = "daily_report"
            try:
                # Daily Report is date-wide and outside the task-specific execution
                # budget/model-authority envelope and task validator contract.
                paths = self.daily_agent.run(
                    target_date, self.store, self.artifacts, live=live
                )
                daily_paths = [str(path) for path in paths]
            finally:
                self._release_agent_model(self.daily_agent, live=live)

            self.store.record_activity(
                task_id,
                "workflow",
                "daily_report_attached",
                "ok",
                f"date={target_date} outcome={outcome}",
            )
        except Exception as exc:
            report_error = self._safe_error(exc)
            error = (
                f"{error}; daily_report={report_error}"
                if error
                else f"daily_report={report_error}"
            )
            outcome = "failed"
            self.store.set_status(task_id, TaskStatus.FAILED)
            self.store.record_activity(
                task_id,
                "workflow",
                "daily_report_failed",
                "error",
                report_error,
            )

        final_task = self.store.get_task(task_id)
        final_stage = "daily_report_completed" if daily_paths else stage
        manifest = {
            "schema_version": "workflow-run/v1",
            "task_id": task_id,
            "status": outcome,
            "task_status": final_task.status.value,
            "stage": final_stage,
            "business_stage": business_stage,
            "live": live,
            "report_date": target_date,
            "options": {
                "audience": audience,
                "purpose": purpose,
                "language": language,
                "slide_count": slide_count,
                "output_format": output_format,
            },
            "research_artifacts": research_paths,
            "presentation_artifacts": presentation_paths,
            "daily_report_artifacts": daily_paths,
            "verification": (
                verification.to_dict() if verification is not None else None
            ),
            "execution_budget": (
                execution_budget.snapshot() if execution_budget is not None else None
            ),
            "model_authority": (
                model_authority.metadata() if model_authority is not None else None
            ),
            "error": error,
            "started_at": started_at,
            "completed_at": datetime.now(TZ).isoformat(),
        }
        manifest_path = self._write_manifest(manifest)
        self.store.record_artifact(
            task_id,
            "workflow",
            "workflow_manifest_json",
            str(manifest_path),
        )
        self.store.record_activity(
            task_id,
            "workflow",
            "workflow_finished",
            "ok" if outcome == "completed" else outcome,
            f"stage={business_stage} manifest={manifest_path}",
        )
        return WorkflowRunResult(
            task_id=task_id,
            status=outcome,
            task_status=final_task.status.value,
            stage=final_stage,
            research_artifacts=research_paths,
            presentation_artifacts=presentation_paths,
            daily_report_artifacts=daily_paths,
            error=error,
            manifest_path=str(manifest_path),
        )
