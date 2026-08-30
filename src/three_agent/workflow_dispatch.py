from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from .presentation_schemas import PRESENTATION_PLAN_SCHEMA_V1
from .privacy import redact_sensitive_text
from .task_contract import TaskContractCompiler
from .workflow_design import WorkflowDesignError, validate_contract


DISPATCH_SCHEMA_VERSION = "workspace-workflow-dispatch/v2"
EXECUTION_PROFILE = "workspace-fixed-analysis/v1"
_ALLOWED_ACTION_CHAINS = {
    ("input", "research", "presentation", "daily_report", "output"),
    ("input", "research", "validate", "presentation", "daily_report", "output"),
}
_KIND_BY_ACTION = {
    "input": "input",
    "research": "agent",
    "validate": "validation",
    "presentation": "agent",
    "daily_report": "agent",
    "output": "output",
}


class WorkflowDispatchError(ValueError):
    """A designed workflow cannot enter the executable dispatch boundary."""


def _canonical_sha256(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _bounded_text(value: Any, *, field: str, default: str, limit: int) -> str:
    text = " ".join(str(value or default).split()).strip() or default
    if len(text) > limit:
        raise WorkflowDispatchError(f"{field} exceeds {limit} characters")
    return text


class WorkflowDispatchController:
    """Deterministic admission plus explicit administrator authorization.

    V2 exposes only the low-risk linear profile already implemented by the
    production WorkflowRunner. Node labels and model output never become tools,
    commands, capabilities, or authority.
    """

    def __init__(self, orchestrator: Any):
        self.orchestrator = orchestrator
        self.store = orchestrator.store
        self.artifacts = orchestrator.artifacts
        self.bridge = orchestrator.runtime_validator_bridge
        self.compiler = TaskContractCompiler()
        self._lock = threading.RLock()

    @property
    def root(self) -> Path:
        path = self.artifacts.root / "workflow_dispatch"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _record_path(self, task_id: str) -> Path:
        safe = str(task_id).strip()
        if not safe or "/" in safe or "\\" in safe or ".." in safe:
            raise WorkflowDispatchError("invalid task_id")
        return self.root / f"{safe}.json"

    def _write_record(self, record: dict[str, Any]) -> Path:
        path = self._record_path(str(record["task_id"]))
        tmp = path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        tmp.replace(path)
        return path

    def _load_record(self, task_id: str) -> dict[str, Any]:
        path = self._record_path(task_id)
        if not path.is_file():
            raise WorkflowDispatchError("dispatch preparation not found")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema_version") != DISPATCH_SCHEMA_VERSION:
            raise WorkflowDispatchError("invalid dispatch preparation")
        return payload

    @staticmethod
    def _linear_actions(contract: dict[str, Any]) -> tuple[str, ...]:
        nodes = contract["nodes"]
        by_id = {node["id"]: node for node in nodes}
        children: dict[str, list[str]] = {node["id"]: [] for node in nodes}
        roots: list[str] = []
        for node in nodes:
            parents = node["depends_on"]
            if len(parents) > 1:
                raise WorkflowDispatchError("branch joins are design-only in V2")
            if not parents:
                roots.append(node["id"])
            else:
                children[parents[0]].append(node["id"])
        if len(roots) != 1:
            raise WorkflowDispatchError("V2 execution requires exactly one workflow start")
        if any(len(items) > 1 for items in children.values()):
            raise WorkflowDispatchError("branching is design-only in V2")

        order: list[str] = []
        current: str | None = roots[0]
        while current is not None:
            order.append(current)
            next_ids = children[current]
            current = next_ids[0] if next_ids else None
        if len(order) != len(nodes):
            raise WorkflowDispatchError("V2 execution requires one connected chain")

        actions: list[str] = []
        for node_id in order:
            node = by_id[node_id]
            action = node["action"]
            if node["condition"]:
                raise WorkflowDispatchError("conditional edges are design-only in V2")
            expected_kind = _KIND_BY_ACTION.get(action)
            if expected_kind is None:
                raise WorkflowDispatchError(f"action {action} is design-only in V2")
            if node["kind"] != expected_kind:
                raise WorkflowDispatchError(
                    f"action {action} requires kind={expected_kind} for V2 execution"
                )
            if node["approval_required"]:
                raise WorkflowDispatchError("mid-workflow approval is design-only in V2")
            actions.append(action)
        return tuple(actions)

    def _admit(self, raw_contract: Any) -> tuple[dict[str, Any], tuple[str, ...]]:
        try:
            contract = validate_contract(raw_contract)
        except WorkflowDesignError as exc:
            raise WorkflowDispatchError(str(exc)) from exc

        if contract["trigger"] != "manual":
            raise WorkflowDispatchError("schedule/event triggers remain design-only in V2")
        if contract["risk_level"] != "low":
            raise WorkflowDispatchError("V2 execution is limited to low-risk workflows")
        if any(node["kind"] in {"decision", "approval", "manual"} for node in contract["nodes"]):
            raise WorkflowDispatchError(
                "decision, approval, and manual nodes remain design-only in V2"
            )

        runtime_sensitivity = str(self.bridge.sensitivity)
        if runtime_sensitivity == "secret":
            raise WorkflowDispatchError("Workflow Studio cannot represent secret data class")
        if contract["data_class"] != runtime_sensitivity:
            raise WorkflowDispatchError(
                "workflow data_class must match the active WorkSpace confidentiality zone"
            )

        actions = self._linear_actions(contract)
        if actions not in _ALLOWED_ACTION_CHAINS:
            raise WorkflowDispatchError(
                "workflow does not match the bounded V2 Research→Presentation→Daily Report execution profile"
            )
        return contract, actions

    def prepare(
        self,
        raw_contract: Any,
        *,
        language: str = "ja",
        audience: str = "R&D internal",
        purpose: str = "inform",
        slide_count: int = 6,
        output_format: str = "pptx",
    ) -> dict[str, Any]:
        with self._lock:
            contract, actions = self._admit(raw_contract)
            language = str(language or "ja").strip().lower()
            if language not in {"ja", "vi", "en"}:
                raise WorkflowDispatchError("unsupported language")
            audience = _bounded_text(
                audience, field="audience", default="R&D internal", limit=120
            )
            purpose = _bounded_text(purpose, field="purpose", default="inform", limit=80)
            if (
                not isinstance(slide_count, int)
                or isinstance(slide_count, bool)
                or not 3 <= slide_count <= 20
            ):
                raise WorkflowDispatchError("slide_count must be an integer between 3 and 20")
            if str(output_format).strip().lower() != "pptx":
                raise WorkflowDispatchError("V2 dispatch currently supports output_format=pptx only")

            workflow_sha = _canonical_sha256(contract)
            task = self.store.create_task(contract["title"], contract["objective"])
            task_contract = self.compiler.compile(
                task_id=task.task_id,
                task_type="analysis",
                sensitivity=self.bridge.sensitivity,
                risk_level="low",
                public_web=self.bridge.public_web,
                output_schema=PRESENTATION_PLAN_SCHEMA_V1,
            )
            contract_sha = self.bridge.ledger.bind_contract(task_contract)
            approval_fingerprint = _canonical_sha256(
                {
                    "schema_version": DISPATCH_SCHEMA_VERSION,
                    "task_id": task.task_id,
                    "workflow_sha256": workflow_sha,
                    "task_contract_sha256": contract_sha,
                    "execution_profile": EXECUTION_PROFILE,
                }
            )
            options = {
                "language": language,
                "audience": audience,
                "purpose": purpose,
                "slide_count": slide_count,
                "output_format": "pptx",
            }
            record = {
                "schema_version": DISPATCH_SCHEMA_VERSION,
                "task_id": task.task_id,
                "status": "prepared",
                "execution_profile": EXECUTION_PROFILE,
                "workflow_sha256": workflow_sha,
                "task_contract_sha256": contract_sha,
                "approval_fingerprint": approval_fingerprint,
                "actions": list(actions),
                "risk_level": "low",
                "sensitivity": self.bridge.sensitivity,
                "approval_required": True,
                "admin_approval_required": True,
                "options": options,
                "run_status": None,
            }
            record_path = self._write_record(record)
            self.store.record_artifact(
                task.task_id,
                "workflow_dispatch",
                "workflow_dispatch_preparation",
                str(record_path),
            )
            self.store.record_activity(
                task.task_id,
                "workflow_dispatch",
                "dispatch_prepared",
                "ok",
                (
                    f"profile={EXECUTION_PROFILE} actions={len(actions)} "
                    f"workflow={workflow_sha} contract={contract_sha}"
                ),
            )
            return {
                "schema_version": DISPATCH_SCHEMA_VERSION,
                "task_id": task.task_id,
                "status": "prepared",
                "execution_profile": EXECUTION_PROFILE,
                "workflow_sha256": workflow_sha,
                "task_contract_sha256": contract_sha,
                "approval_fingerprint": approval_fingerprint,
                "approval_required": True,
                "admin_approval_required": True,
                "execution_authorized": False,
                "actions": list(actions),
                "risk_level": "low",
                "sensitivity": self.bridge.sensitivity,
                "budget": asdict(task_contract.execution_budget),
                "model_policy": asdict(task_contract.model_policy),
            }

    @staticmethod
    def _runtime_summary(task_id: str, result: Any) -> dict[str, Any]:
        if is_dataclass(result):
            raw = asdict(result)
        elif isinstance(result, dict):
            raw = dict(result)
        else:
            raw = {
                "status": getattr(result, "status", "unknown"),
                "task_status": getattr(result, "task_status", "unknown"),
                "stage": getattr(result, "stage", "unknown"),
                "error": getattr(result, "error", None),
            }
        error = raw.get("error")
        return {
            "task_id": task_id,
            "status": str(raw.get("status") or "unknown"),
            "task_status": str(raw.get("task_status") or "unknown"),
            "stage": str(raw.get("stage") or "unknown"),
            "error": (
                redact_sensitive_text(str(error))[:400]
                if error not in {None, ""}
                else None
            ),
        }

    def execute(
        self,
        task_id: str,
        *,
        approval_fingerprint: str,
        confirmation: str,
        approver_id: str,
    ) -> dict[str, Any]:
        with self._lock:
            record = self._load_record(task_id)
            if record.get("status") != "prepared":
                raise WorkflowDispatchError("dispatch preparation is not executable")
            if str(approval_fingerprint).strip() != record.get("approval_fingerprint"):
                raise WorkflowDispatchError("approval fingerprint mismatch")
            if str(confirmation).strip() != "AUTHORIZE":
                raise WorkflowDispatchError("explicit AUTHORIZE confirmation is required")
            if not str(approver_id).strip():
                raise WorkflowDispatchError("approver identity is required")

            approver_ref = "sha256:" + hashlib.sha256(
                str(approver_id).encode("utf-8")
            ).hexdigest()
            record["status"] = "executing"
            record["approver_ref"] = approver_ref
            self._write_record(record)
            self.store.record_activity(
                task_id,
                "workflow_dispatch",
                "dispatch_authorized",
                "ok",
                f"profile={EXECUTION_PROFILE} approver={approver_ref}",
            )

        options = dict(record.get("options") or {})
        try:
            result = self.orchestrator.workflow.run_task(
                task_id,
                live=True,
                audience=options.get("audience", "R&D internal"),
                purpose=options.get("purpose", "inform"),
                language=options.get("language", "ja"),
                slide_count=int(options.get("slide_count", 6)),
                output_format="pptx",
            )
        except Exception:
            with self._lock:
                record = self._load_record(task_id)
                record["status"] = "failed"
                record["run_status"] = "exception"
                self._write_record(record)
            raise

        result_payload = self._runtime_summary(task_id, result)
        run_status = result_payload["status"]
        with self._lock:
            record = self._load_record(task_id)
            record["status"] = "completed" if run_status == "completed" else "failed"
            record["run_status"] = run_status
            self._write_record(record)
            self.store.record_activity(
                task_id,
                "workflow_dispatch",
                "dispatch_finished",
                "ok" if run_status == "completed" else "error",
                f"run_status={run_status} profile={EXECUTION_PROFILE}",
            )
        return {
            "schema_version": DISPATCH_SCHEMA_VERSION,
            "task_id": task_id,
            "dispatch_status": record["status"],
            "execution_profile": EXECUTION_PROFILE,
            "result": result_payload,
        }
