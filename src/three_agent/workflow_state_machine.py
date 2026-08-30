from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, replace
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from .execution_budget import TaskExecutionBudgetState
from .inference_scope import inference_scope
from .model_authority import TaskModelAuthority
from .models import TaskStatus
from .presentation_schemas import PRESENTATION_PLAN_SCHEMA_V1
from .privacy import redact_sensitive_text
from .runtime_validation import MAX_PRECOMPILED_ANALYSIS_WALL_TIME_MS
from .task_contract import ExecutionBudget, TaskContract, TaskContractCompiler
from .workflow_design import WorkflowDesignError, validate_contract


TZ = ZoneInfo("Asia/Tokyo")
STATE_SCHEMA_VERSION = "workspace-workflow-state/v3"
EXECUTION_PROFILE = "workspace-checkpoint-graph/v1"
WORKFLOW_V3_MAX_WALL_TIME_MS = MAX_PRECOMPILED_ANALYSIS_WALL_TIME_MS

_ALLOWED_PAIRS = {
    ("input", "input"),
    ("agent", "research"),
    ("validation", "validate"),
    ("decision", "validate"),
    ("approval", "human_approval"),
    ("agent", "presentation"),
    ("agent", "daily_report"),
    ("output", "output"),
}
_BRANCH_CONDITIONS = {
    "decision": {"passed", "failed"},
    "approval": {"approved", "rejected"},
}


class WorkflowStateError(ValueError):
    """A V3 workflow state or transition violates the execution contract."""


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
        raise WorkflowStateError(f"{field} exceeds {limit} characters")
    return text


def _actor_ref(actor_id: str) -> str:
    actor = str(actor_id or "").strip()
    if not actor:
        raise WorkflowStateError("approver identity is required")
    return "sha256:" + hashlib.sha256(actor.encode("utf-8")).hexdigest()


class WorkflowStateMachineController:
    """Durable deterministic workflow runner with exact approval checkpoints.

    V3 may choose between already-authorized WorkSpace capabilities, but graph
    labels and model output never become commands, tools, credentials, network
    authority, or free-form executable conditions.
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
        path = self.artifacts.root / "workflow_state"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def _safe_task_id(task_id: str) -> str:
        safe = str(task_id).strip()
        if not safe or "/" in safe or "\\" in safe or ".." in safe:
            raise WorkflowStateError("invalid task_id")
        return safe

    def _state_path(self, task_id: str) -> Path:
        return self.root / f"{self._safe_task_id(task_id)}.state.json"

    def _contract_path(self, task_id: str) -> Path:
        return self.root / f"{self._safe_task_id(task_id)}.contract.json"

    @staticmethod
    def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        tmp.replace(path)
        try:
            path.chmod(0o600)
        except OSError:
            pass

    def _write_state(self, state: dict[str, Any]) -> None:
        self._atomic_json(self._state_path(str(state["task_id"])), state)

    def _load_state(self, task_id: str) -> dict[str, Any]:
        path = self._state_path(task_id)
        if not path.is_file():
            raise WorkflowStateError("workflow state not found")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise WorkflowStateError("workflow state is unreadable") from exc
        if not isinstance(payload, dict) or payload.get("schema_version") != STATE_SCHEMA_VERSION:
            raise WorkflowStateError("invalid workflow state")
        if str(payload.get("task_id") or "") != str(task_id):
            raise WorkflowStateError("workflow state task mismatch")
        return payload

    def _write_contract(self, task_id: str, contract: dict[str, Any]) -> None:
        self._atomic_json(self._contract_path(task_id), contract)

    def _load_contract(self, state: dict[str, Any]) -> dict[str, Any]:
        task_id = str(state["task_id"])
        path = self._contract_path(task_id)
        if not path.is_file():
            raise WorkflowStateError("workflow contract artifact missing")
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            contract = validate_contract(raw)
        except (OSError, UnicodeError, json.JSONDecodeError, WorkflowDesignError) as exc:
            raise WorkflowStateError("workflow contract artifact invalid") from exc
        if _canonical_sha256(contract) != state.get("workflow_sha256"):
            raise WorkflowStateError("workflow contract fingerprint mismatch")
        return contract

    @staticmethod
    def _children(contract: dict[str, Any]) -> dict[str, list[str]]:
        children = {node["id"]: [] for node in contract["nodes"]}
        for node in contract["nodes"]:
            for parent in node["depends_on"]:
                children[parent].append(node["id"])
        return children

    @staticmethod
    def _node_map(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {node["id"]: node for node in contract["nodes"]}

    @staticmethod
    def _normalized_condition(node: dict[str, Any]) -> str:
        return " ".join(str(node.get("condition") or "").split()).strip().lower()

    def _admit(self, raw_contract: Any) -> tuple[dict[str, Any], str]:
        try:
            contract = validate_contract(raw_contract)
        except WorkflowDesignError as exc:
            raise WorkflowStateError(str(exc)) from exc

        if contract["trigger"] != "manual":
            raise WorkflowStateError("schedule/event triggers remain design-only in V3")
        if contract["risk_level"] != "low":
            raise WorkflowStateError("V3.0 execution remains limited to low-risk workflows")

        runtime_sensitivity = str(self.bridge.sensitivity)
        if runtime_sensitivity == "secret":
            raise WorkflowStateError("Workflow Studio cannot represent secret data class")
        if contract["data_class"] != runtime_sensitivity:
            raise WorkflowStateError(
                "workflow data_class must match the active WorkSpace confidentiality zone"
            )

        nodes = contract["nodes"]
        by_id = self._node_map(contract)
        children = self._children(contract)
        roots = [node["id"] for node in nodes if not node["depends_on"]]
        if len(roots) != 1 or by_id[roots[0]]["action"] != "input":
            raise WorkflowStateError("V3 requires exactly one input root")
        if sum(1 for node in nodes if node["action"] == "input") != 1:
            raise WorkflowStateError("V3 permits exactly one input action")
        if sum(1 for node in nodes if node["action"] == "research") != 1:
            raise WorkflowStateError("V3 requires exactly one research action")
        if sum(1 for node in nodes if node["action"] == "presentation") != 1:
            raise WorkflowStateError("V3 requires exactly one presentation action")
        if sum(1 for node in nodes if node["action"] == "daily_report") != 1:
            raise WorkflowStateError("V3 requires exactly one daily_report action")

        for node in nodes:
            pair = (node["kind"], node["action"])
            if pair not in _ALLOWED_PAIRS:
                raise WorkflowStateError(
                    f"node {node['id']} uses a design-only kind/action pair"
                )
            if len(node["depends_on"]) > 1:
                raise WorkflowStateError("branch joins remain design-only in V3")
            if node["kind"] == "approval":
                if not node["approval_required"]:
                    raise WorkflowStateError("approval nodes must set approval_required=true")
            elif node["approval_required"]:
                raise WorkflowStateError(
                    "approval_required may only be asserted by an approval node in V3"
                )

            branch = children[node["id"]]
            if len(branch) > 2:
                raise WorkflowStateError("V3 supports at most two deterministic branch targets")
            if len(branch) > 1 and node["kind"] not in {"decision", "approval"}:
                raise WorkflowStateError(
                    "only validation decisions or approval checkpoints may branch in V3"
                )

            expected = _BRANCH_CONDITIONS.get(node["kind"])
            if expected is not None:
                seen: set[str] = set()
                for child_id in branch:
                    child = by_id[child_id]
                    condition = self._normalized_condition(child)
                    if condition not in expected:
                        raise WorkflowStateError(
                            f"branch from {node['id']} must use one of {sorted(expected)}"
                        )
                    if condition in seen:
                        raise WorkflowStateError(
                            f"branch from {node['id']} repeats condition {condition}"
                        )
                    if condition in {"failed", "rejected"} and child["kind"] != "output":
                        raise WorkflowStateError(
                            f"{condition} branch must terminate directly at output in V3"
                        )
                    seen.add(condition)
                if len(branch) == 2 and seen != expected:
                    raise WorkflowStateError(
                        f"two-way {node['kind']} branch must provide exactly {sorted(expected)}"
                    )
            else:
                for child_id in branch:
                    if self._normalized_condition(by_id[child_id]):
                        raise WorkflowStateError(
                            "conditions are executable only after decision or approval nodes"
                        )

        leaves = [node_id for node_id, items in children.items() if not items]
        if not leaves or any(by_id[node_id]["kind"] != "output" for node_id in leaves):
            raise WorkflowStateError("every executable V3 branch must terminate at an output node")

        # The graph is a rooted tree because joins are forbidden. Verify capability
        # ordering along every path, not merely by node presence.
        stack: list[tuple[str, frozenset[str]]] = [(roots[0], frozenset())]
        visited_nodes: set[str] = set()
        while stack:
            node_id, ancestors = stack.pop()
            visited_nodes.add(node_id)
            node = by_id[node_id]
            action = node["action"]
            if action == "presentation" and "research" not in ancestors:
                raise WorkflowStateError("presentation must be downstream of research")
            if action == "daily_report" and "presentation" not in ancestors:
                raise WorkflowStateError("daily_report must be downstream of presentation")
            if node["kind"] == "decision" and not ({"research", "presentation"} & set(ancestors)):
                raise WorkflowStateError("decision requires a prior validated agent stage")
            next_ancestors = frozenset(set(ancestors) | {action})
            for child_id in children[node_id]:
                stack.append((child_id, next_ancestors))
        if len(visited_nodes) != len(nodes):
            raise WorkflowStateError("V3 requires one connected workflow graph")

        return contract, roots[0]

    def _task_contract(self, task_id: str) -> TaskContract:
        base = self.compiler.compile(
            task_id=task_id,
            task_type="analysis",
            sensitivity=self.bridge.sensitivity,
            risk_level="low",
            public_web=self.bridge.public_web,
            output_schema=PRESENTATION_PLAN_SCHEMA_V1,
        )
        budget = base.execution_budget
        extended = ExecutionBudget(
            max_steps=budget.max_steps,
            max_tool_calls=budget.max_tool_calls,
            max_retries=budget.max_retries,
            max_escalations=budget.max_escalations,
            max_wall_time_ms=WORKFLOW_V3_MAX_WALL_TIME_MS,
        )
        return replace(
            base,
            execution_budget=extended,
            policy_reason_codes=tuple(base.policy_reason_codes)
            + ("WORKFLOW_V3_CHECKPOINT_24H_BOUND",),
        ).validate()

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
            contract, root_node = self._admit(raw_contract)
            language = str(language or "ja").strip().lower()
            if language not in {"ja", "vi", "en"}:
                raise WorkflowStateError("unsupported language")
            audience = _bounded_text(
                audience, field="audience", default="R&D internal", limit=120
            )
            purpose = _bounded_text(purpose, field="purpose", default="inform", limit=80)
            if (
                not isinstance(slide_count, int)
                or isinstance(slide_count, bool)
                or not 3 <= slide_count <= 20
            ):
                raise WorkflowStateError("slide_count must be an integer between 3 and 20")
            if str(output_format).strip().lower() != "pptx":
                raise WorkflowStateError("V3 currently supports output_format=pptx only")

            workflow_sha = _canonical_sha256(contract)
            task = self.store.create_task(contract["title"], contract["objective"])
            task_contract = self._task_contract(task.task_id)
            contract_sha = self.bridge.ledger.bind_contract(task_contract)
            dispatch_fingerprint = _canonical_sha256(
                {
                    "schema_version": STATE_SCHEMA_VERSION,
                    "task_id": task.task_id,
                    "workflow_sha256": workflow_sha,
                    "task_contract_sha256": contract_sha,
                    "execution_profile": EXECUTION_PROFILE,
                }
            )
            self._write_contract(task.task_id, contract)
            now = datetime.now(TZ).isoformat()
            state = {
                "schema_version": STATE_SCHEMA_VERSION,
                "task_id": task.task_id,
                "status": "prepared",
                "revision": 1,
                "execution_profile": EXECUTION_PROFILE,
                "workflow_sha256": workflow_sha,
                "task_contract_sha256": contract_sha,
                "dispatch_fingerprint": dispatch_fingerprint,
                "root_node": root_node,
                "current_node": root_node,
                "completed_nodes": [],
                "branch_history": [],
                "checkpoint": None,
                "last_validation": None,
                "runtime_bound": False,
                "terminal_reason": None,
                "error": None,
                "initial_approver_ref": None,
                "options": {
                    "language": language,
                    "audience": audience,
                    "purpose": purpose,
                    "slide_count": slide_count,
                    "output_format": "pptx",
                },
                "created_at": now,
                "updated_at": now,
            }
            self._write_state(state)
            self.store.record_artifact(
                task.task_id,
                "workflow_state",
                "workflow_v3_contract",
                str(self._contract_path(task.task_id)),
            )
            self.store.record_artifact(
                task.task_id,
                "workflow_state",
                "workflow_v3_state",
                str(self._state_path(task.task_id)),
            )
            self.store.record_activity(
                task.task_id,
                "workflow_v3",
                "workflow_prepared",
                "ok",
                f"profile={EXECUTION_PROFILE} workflow={workflow_sha} contract={contract_sha}",
            )
            return {
                "schema_version": STATE_SCHEMA_VERSION,
                "task_id": task.task_id,
                "status": "prepared",
                "execution_profile": EXECUTION_PROFILE,
                "workflow_sha256": workflow_sha,
                "task_contract_sha256": contract_sha,
                "approval_fingerprint": dispatch_fingerprint,
                "approval_required": True,
                "admin_approval_required": True,
                "execution_authorized": False,
                "risk_level": "low",
                "sensitivity": self.bridge.sensitivity,
                "supports_pause_resume": True,
                "supports_deterministic_branching": True,
                "budget": asdict(task_contract.execution_budget),
                "model_policy": asdict(task_contract.model_policy),
            }

    def _runtime_context(
        self,
        state: dict[str, Any],
    ) -> tuple[TaskExecutionBudgetState, TaskModelAuthority]:
        task_id = str(state["task_id"])
        contract = self._task_contract(task_id)
        compiled_sha = _canonical_sha256(contract.to_dict())
        if compiled_sha != state.get("task_contract_sha256"):
            raise WorkflowStateError("runtime TaskContract compiler drift detected")
        record = self.store.task_contract_record(task_id)
        if record is None or str(record["contract_sha256"]) != state.get("task_contract_sha256"):
            raise WorkflowStateError("bound TaskContract no longer matches workflow state")
        if not state.get("runtime_bound"):
            attempt = self.bridge.begin(task_id, contract=contract)
            state["runtime_bound"] = True
            state["updated_at"] = datetime.now(TZ).isoformat()
            self._write_state(state)
            if attempt.execution_budget is None or attempt.model_authority is None:
                raise WorkflowStateError("runtime authority binding incomplete")
            return attempt.execution_budget, attempt.model_authority
        return (
            TaskExecutionBudgetState.from_bound_contract(self.store, task_id),
            TaskModelAuthority.from_contract(contract),
        )

    @staticmethod
    def _release_agent_model(agent: Any) -> None:
        llm = getattr(agent, "llm", None)
        if bool(getattr(llm, "budget_managed_residency", False)):
            return
        unload = getattr(llm, "unload", None)
        if callable(unload):
            try:
                unload()
            except Exception:
                return

    def _next_unconditional(
        self,
        node_id: str,
        contract: dict[str, Any],
    ) -> str | None:
        children = self._children(contract)[node_id]
        if not children:
            return None
        if len(children) != 1:
            raise WorkflowStateError("branch node requires deterministic selection")
        child = self._node_map(contract)[children[0]]
        if self._normalized_condition(child):
            raise WorkflowStateError("conditioned edge requires deterministic selection")
        return children[0]

    def _select_branch(
        self,
        state: dict[str, Any],
        contract: dict[str, Any],
        node_id: str,
        outcome: str,
    ) -> str | None:
        by_id = self._node_map(contract)
        candidates = [
            child_id
            for child_id in self._children(contract)[node_id]
            if self._normalized_condition(by_id[child_id]) == outcome
        ]
        if len(candidates) > 1:
            raise WorkflowStateError("ambiguous deterministic branch")
        selected = candidates[0] if candidates else None
        state["branch_history"].append(
            {"node_id": node_id, "outcome": outcome, "selected_node": selected}
        )
        return selected

    def _complete_node(
        self,
        state: dict[str, Any],
        node_id: str,
        next_node: str | None,
    ) -> None:
        if node_id not in state["completed_nodes"]:
            state["completed_nodes"].append(node_id)
        state["current_node"] = next_node
        state["revision"] = int(state.get("revision", 0)) + 1
        state["updated_at"] = datetime.now(TZ).isoformat()
        self._write_state(state)

    def _pause_for_approval(
        self,
        state: dict[str, Any],
        node: dict[str, Any],
    ) -> dict[str, Any]:
        task_id = str(state["task_id"])
        prior_status = self.store.get_task(task_id).status
        revision = int(state.get("revision", 0)) + 1
        checkpoint_fingerprint = _canonical_sha256(
            {
                "schema_version": STATE_SCHEMA_VERSION,
                "task_id": task_id,
                "workflow_sha256": state["workflow_sha256"],
                "task_contract_sha256": state["task_contract_sha256"],
                "node_id": node["id"],
                "revision": revision,
                "completed_sha256": _canonical_sha256(state["completed_nodes"]),
            }
        )
        state["status"] = "paused"
        state["revision"] = revision
        state["checkpoint"] = {
            "node_id": node["id"],
            "fingerprint": checkpoint_fingerprint,
            "status": "pending",
            "prior_task_status": prior_status.value,
            "decided_by": None,
            "decision": None,
        }
        state["updated_at"] = datetime.now(TZ).isoformat()
        self._write_state(state)
        self.store.set_status(task_id, TaskStatus.WAITING_HUMAN)
        self.store.record_activity(
            task_id,
            "workflow_v3",
            "approval_checkpoint_paused",
            "blocked",
            f"node={node['id']} revision={revision}",
        )
        return self._summary(state)

    def _run_research(self, state: dict[str, Any]) -> bool:
        task_id = str(state["task_id"])
        budget, authority = self._runtime_context(state)
        try:
            budget.reserve(steps=1)
            with inference_scope(
                task_id,
                agent_id="research",
                stage="workflow_v3_research",
                execution_budget=budget,
                model_authority=authority,
            ):
                self.orchestrator.research_agent.run(
                    task_id, self.store, self.artifacts, live=True
                )
        finally:
            self._release_agent_model(self.orchestrator.research_agent)
        passed = self.bridge.record_research_evidence(
            task_id,
            task_status=self.store.get_task(task_id).status,
        )
        state["last_validation"] = {"source": "research", "passed": bool(passed)}
        state["updated_at"] = datetime.now(TZ).isoformat()
        self._write_state(state)
        return bool(passed)

    def _run_presentation(self, state: dict[str, Any]) -> bool:
        task_id = str(state["task_id"])
        last = state.get("last_validation") or {}
        if last.get("source") != "research" or last.get("passed") is not True:
            raise WorkflowStateError("presentation requires passed research evidence")
        budget, authority = self._runtime_context(state)
        options = dict(state.get("options") or {})
        try:
            budget.reserve(steps=1)
            with inference_scope(
                task_id,
                agent_id="presentation",
                stage="workflow_v3_presentation",
                execution_budget=budget,
                model_authority=authority,
            ):
                self.orchestrator.presentation_agent.run(
                    task_id,
                    self.store,
                    self.artifacts,
                    live=True,
                    audience=options.get("audience", "R&D internal"),
                    purpose=options.get("purpose", "inform"),
                    language=options.get("language", "ja"),
                    slide_count=int(options.get("slide_count", 6)),
                    output_format="pptx",
                )
        finally:
            self._release_agent_model(self.orchestrator.presentation_agent)
        passed = self.bridge.record_presentation_validation(
            task_id,
            task_status=self.store.get_task(task_id).status,
        )
        state["last_validation"] = {"source": "presentation", "passed": bool(passed)}
        state["updated_at"] = datetime.now(TZ).isoformat()
        self._write_state(state)
        return bool(passed)

    def _run_daily_report(self, state: dict[str, Any]) -> None:
        target_date = datetime.now(TZ).strftime("%Y-%m-%d")
        try:
            self.orchestrator.daily_agent.run(
                target_date, self.store, self.artifacts, live=True
            )
        finally:
            self._release_agent_model(self.orchestrator.daily_agent)
        self.store.record_activity(
            str(state["task_id"]),
            "workflow_v3",
            "daily_report_attached",
            "ok",
            f"date={target_date}",
        )

    def _finish_output(
        self,
        state: dict[str, Any],
        node_id: str,
    ) -> dict[str, Any]:
        task_id = str(state["task_id"])
        self._complete_node(state, node_id, None)
        if state.get("terminal_reason") == "approval_rejected":
            state["status"] = "rejected"
            state["updated_at"] = datetime.now(TZ).isoformat()
            self._write_state(state)
            self.store.record_activity(
                task_id,
                "workflow_v3",
                "workflow_rejected",
                "blocked",
                "approval checkpoint rejected",
            )
            return self._summary(state)

        last = state.get("last_validation") or {}
        if last.get("passed") is not True:
            state["status"] = "blocked"
            state["terminal_reason"] = "validation_failed"
            state["updated_at"] = datetime.now(TZ).isoformat()
            self._write_state(state)
            if self.store.get_task(task_id).status != TaskStatus.FAILED:
                self.store.set_status(task_id, TaskStatus.FAILED)
            return self._summary(state)

        verification = self.bridge.evaluate(task_id)
        budget, _ = self._runtime_context(state)
        budget.assert_active()
        if not verification.verified:
            state["status"] = "blocked"
            state["terminal_reason"] = "required_validator_missing"
            state["updated_at"] = datetime.now(TZ).isoformat()
            self._write_state(state)
            if self.store.get_task(task_id).status != TaskStatus.FAILED:
                self.store.set_status(task_id, TaskStatus.FAILED)
            return self._summary(state)

        self.store.set_status(task_id, TaskStatus.DONE)
        state["status"] = "completed"
        state["terminal_reason"] = "verified"
        state["updated_at"] = datetime.now(TZ).isoformat()
        self._write_state(state)
        self.store.record_activity(
            task_id,
            "workflow_v3",
            "workflow_completed",
            "ok",
            f"verified=true output_node={node_id}",
        )
        return self._summary(state)

    def _advance(
        self,
        state: dict[str, Any],
        contract: dict[str, Any],
    ) -> dict[str, Any]:
        by_id = self._node_map(contract)
        state["status"] = "running"
        state["updated_at"] = datetime.now(TZ).isoformat()
        self._write_state(state)

        while state.get("current_node"):
            node_id = str(state["current_node"])
            node = by_id.get(node_id)
            if node is None:
                raise WorkflowStateError("current workflow node no longer exists")
            action = node["action"]
            self.store.record_activity(
                str(state["task_id"]),
                "workflow_v3",
                "node_entered",
                "ok",
                f"node={node_id} action={action}",
            )

            if action == "input":
                self._complete_node(state, node_id, self._next_unconditional(node_id, contract))
                continue

            if action == "research":
                self._run_research(state)
                self._complete_node(state, node_id, self._next_unconditional(node_id, contract))
                continue

            if node["kind"] == "validation":
                last = state.get("last_validation")
                if not isinstance(last, dict) or "passed" not in last:
                    raise WorkflowStateError("validation node has no authoritative validator result")
                self._complete_node(state, node_id, self._next_unconditional(node_id, contract))
                continue

            if node["kind"] == "decision":
                last = state.get("last_validation")
                if not isinstance(last, dict) or "passed" not in last:
                    raise WorkflowStateError("decision node has no authoritative validator result")
                outcome = "passed" if bool(last["passed"]) else "failed"
                selected = self._select_branch(state, contract, node_id, outcome)
                if selected is None:
                    raise WorkflowStateError(f"decision branch {outcome} has no target")
                self._complete_node(state, node_id, selected)
                continue

            if node["kind"] == "approval":
                return self._pause_for_approval(state, node)

            if action == "presentation":
                self._run_presentation(state)
                self._complete_node(state, node_id, self._next_unconditional(node_id, contract))
                continue

            if action == "daily_report":
                self._run_daily_report(state)
                self._complete_node(state, node_id, self._next_unconditional(node_id, contract))
                continue

            if action == "output":
                return self._finish_output(state, node_id)

            raise WorkflowStateError(f"unsupported runtime action: {action}")

        raise WorkflowStateError("workflow terminated without an output node")

    def _mark_runtime_failure(self, task_id: str, exc: Exception) -> None:
        safe = redact_sensitive_text(f"{type(exc).__name__}: {exc}")[:400]
        state = self._load_state(task_id)
        state["status"] = "failed"
        state["error"] = safe
        state["terminal_reason"] = "runtime_exception"
        state["updated_at"] = datetime.now(TZ).isoformat()
        self._write_state(state)
        current = self.store.get_task(task_id)
        if current.status not in {TaskStatus.FAILED, TaskStatus.WAITING_HUMAN}:
            self.store.set_status(task_id, TaskStatus.FAILED)
        self.store.record_activity(
            task_id,
            "workflow_v3",
            "workflow_failed",
            "error",
            safe,
        )

    def start(
        self,
        task_id: str,
        *,
        approval_fingerprint: str,
        confirmation: str,
        approver_id: str,
    ) -> dict[str, Any]:
        with self._lock:
            state = self._load_state(task_id)
            if state.get("status") != "prepared":
                raise WorkflowStateError("workflow preparation is not startable")
            if str(approval_fingerprint).strip() != state.get("dispatch_fingerprint"):
                raise WorkflowStateError("dispatch approval fingerprint mismatch")
            if str(confirmation).strip() != "AUTHORIZE":
                raise WorkflowStateError("explicit AUTHORIZE confirmation is required")
            state["initial_approver_ref"] = _actor_ref(approver_id)
            state["status"] = "running"
            state["revision"] = int(state.get("revision", 0)) + 1
            state["updated_at"] = datetime.now(TZ).isoformat()
            self._write_state(state)
            self.store.record_activity(
                task_id,
                "workflow_v3",
                "workflow_authorized",
                "ok",
                f"profile={EXECUTION_PROFILE} approver={state['initial_approver_ref']}",
            )
            contract = self._load_contract(state)
            try:
                return self._advance(state, contract)
            except Exception as exc:
                self._mark_runtime_failure(task_id, exc)
                raise

    def decide_checkpoint(
        self,
        task_id: str,
        *,
        checkpoint_fingerprint: str,
        decision: str,
        confirmation: str,
        approver_id: str,
    ) -> dict[str, Any]:
        with self._lock:
            state = self._load_state(task_id)
            if state.get("status") != "paused":
                raise WorkflowStateError("workflow is not paused at an approval checkpoint")
            checkpoint = state.get("checkpoint")
            if not isinstance(checkpoint, dict) or checkpoint.get("status") != "pending":
                raise WorkflowStateError("approval checkpoint is not pending")
            if str(checkpoint_fingerprint).strip() != checkpoint.get("fingerprint"):
                raise WorkflowStateError("checkpoint fingerprint mismatch")

            normalized = str(decision or "").strip().upper()
            if normalized not in {"APPROVE", "REJECT"}:
                raise WorkflowStateError("decision must be APPROVE or REJECT")
            if str(confirmation).strip() != normalized:
                raise WorkflowStateError(f"explicit {normalized} confirmation is required")

            actor = _actor_ref(approver_id)
            node_id = str(checkpoint["node_id"])
            contract = self._load_contract(state)
            outcome = "approved" if normalized == "APPROVE" else "rejected"
            selected = self._select_branch(state, contract, node_id, outcome)
            if normalized == "APPROVE" and selected is None:
                raise WorkflowStateError("approval checkpoint has no approved branch")

            prior_raw = str(checkpoint.get("prior_task_status") or TaskStatus.NEW.value)
            try:
                prior_status = TaskStatus(prior_raw)
            except ValueError:
                raise WorkflowStateError("checkpoint prior task status is invalid")

            checkpoint["status"] = "decided"
            checkpoint["decision"] = normalized
            checkpoint["decided_by"] = actor
            state["checkpoint"] = checkpoint
            if node_id not in state["completed_nodes"]:
                state["completed_nodes"].append(node_id)
            state["revision"] = int(state.get("revision", 0)) + 1
            state["current_node"] = selected
            state["updated_at"] = datetime.now(TZ).isoformat()
            # Both approval outcomes consume the human checkpoint. Restore the
            # exact pre-pause task status so WAITING_HUMAN never remains terminal.
            self.store.set_status(task_id, prior_status)

            if normalized == "REJECT":
                state["terminal_reason"] = "approval_rejected"
                if selected is None:
                    state["status"] = "rejected"
                    self._write_state(state)
                    self.store.record_activity(
                        task_id,
                        "workflow_v3",
                        "approval_checkpoint_rejected",
                        "blocked",
                        f"node={node_id} approver={actor}",
                    )
                    return self._summary(state, contract)

            state["status"] = "running"
            self._write_state(state)
            self.store.record_activity(
                task_id,
                "workflow_v3",
                "approval_checkpoint_decided",
                "ok" if normalized == "APPROVE" else "blocked",
                f"node={node_id} decision={normalized} approver={actor}",
            )
            try:
                return self._advance(state, contract)
            except Exception as exc:
                self._mark_runtime_failure(task_id, exc)
                raise

    def _summary(
        self,
        state: dict[str, Any],
        contract: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        contract = contract or self._load_contract(state)
        by_id = self._node_map(contract)
        checkpoint = state.get("checkpoint")
        public_checkpoint = None
        if isinstance(checkpoint, dict) and checkpoint.get("status") == "pending":
            node_id = str(checkpoint.get("node_id") or "")
            node = by_id.get(node_id, {})
            public_checkpoint = {
                "node_id": node_id,
                "label": str(node.get("label") or node_id)[:120],
                "fingerprint": str(checkpoint.get("fingerprint") or ""),
                "decisions": ["APPROVE", "REJECT"],
            }
        last = state.get("last_validation")
        validation = None
        if isinstance(last, dict) and "passed" in last:
            validation = {
                "source": str(last.get("source") or "unknown"),
                "passed": bool(last.get("passed")),
            }
        return {
            "schema_version": STATE_SCHEMA_VERSION,
            "task_id": str(state["task_id"]),
            "status": str(state.get("status") or "unknown"),
            "execution_profile": EXECUTION_PROFILE,
            "revision": int(state.get("revision", 0)),
            "current_node": state.get("current_node"),
            "completed_nodes": list(state.get("completed_nodes") or []),
            "checkpoint": public_checkpoint,
            "last_validation": validation,
            "terminal_reason": state.get("terminal_reason"),
            "error": state.get("error"),
        }

    def status(self, task_id: str) -> dict[str, Any]:
        with self._lock:
            state = self._load_state(task_id)
            return self._summary(state)
