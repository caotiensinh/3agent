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


# Canonical bounded-parallel Workflow V4 execution.
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, replace
from datetime import datetime
from pathlib import Path
from typing import Any

from .execution_budget import TaskExecutionBudgetState
from .inference_scope import inference_scope
from .model_authority import TaskModelAuthority
from .models import TaskStatus
from .presentation_schemas import PRESENTATION_PLAN_SCHEMA_V1
from .task_contract import ExecutionBudget, TaskContract
from .version import DISPLAY_VERSION
from .workflow_design import WorkflowDesignError, validate_contract_v4

STATE_SCHEMA_VERSION_V4 = "workspace-workflow-state/v4"
EXECUTION_PROFILE_V4 = "workspace-bounded-parallel-dag/v1"
WORKFLOW_V4_MAX_WALL_TIME_MS = WORKFLOW_V3_MAX_WALL_TIME_MS
WORKFLOW_V4_MAX_PARALLEL_BRANCHES = 2
WORKFLOW_V4_MAX_PARALLEL_WORKERS = 2

_ALLOWED_PAIRS_V4 = {
    ("input", "input"),
    ("agent", "research"),
    ("validation", "validate"),
    ("decision", "validate"),
    ("approval", "human_approval"),
    ("parallel", "parallel_fork"),
    ("parallel", "parallel_join"),
    ("agent", "presentation"),
    ("agent", "daily_report"),
    ("output", "output"),
}
_BRANCH_CONDITIONS = {
    "decision": {"passed", "failed"},
    "approval": {"approved", "rejected"},
}


class WorkflowStateMachineV4Controller(WorkflowStateMachineController):
    """V3 authority model plus one bounded, independently verified parallel DAG.

    Parallelism is orchestration only. It cannot add tools, model tiers, network
    scope, credentials, conditions, or execution budget. Each lane is isolated in
    a child task with its own canonical TaskContract and Validator Ledger state.
    """

    @property
    def root(self) -> Path:
        path = self.artifacts.root / "workflow_state_v4"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _load_state(self, task_id: str) -> dict[str, Any]:
        path = self._state_path(task_id)
        if not path.is_file():
            raise WorkflowStateError("workflow state not found")
        try:
            import json

            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            raise WorkflowStateError("workflow state is unreadable") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("schema_version") != STATE_SCHEMA_VERSION_V4
        ):
            raise WorkflowStateError("invalid workflow state")
        if str(payload.get("task_id") or "") != str(task_id):
            raise WorkflowStateError("workflow state task mismatch")
        return payload

    def _load_contract(self, state: dict[str, Any]) -> dict[str, Any]:
        import json

        task_id = str(state["task_id"])
        path = self._contract_path(task_id)
        if not path.is_file():
            raise WorkflowStateError("workflow contract artifact missing")
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            contract = validate_contract_v4(raw)
        except (OSError, UnicodeError, ValueError, WorkflowDesignError) as exc:
            raise WorkflowStateError("workflow contract artifact invalid") from exc
        if _canonical_sha256(contract) != state.get("workflow_sha256"):
            raise WorkflowStateError("workflow contract fingerprint mismatch")
        return contract

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
            max_wall_time_ms=WORKFLOW_V4_MAX_WALL_TIME_MS,
        )
        return replace(
            base,
            execution_budget=extended,
            policy_reason_codes=tuple(base.policy_reason_codes)
            + ("WORKFLOW_V4_CHECKPOINT_24H_BOUND",),
        ).validate()

    def _parallel_plan(self, contract: dict[str, Any]) -> dict[str, Any] | None:
        by_id = self._node_map(contract)
        children = self._children(contract)
        forks = [n for n in contract["nodes"] if n["action"] == "parallel_fork"]
        joins = [n for n in contract["nodes"] if n["action"] == "parallel_join"]
        if not forks and not joins:
            return None
        if len(forks) != 1 or len(joins) != 1:
            raise WorkflowStateError("ver.0.0.1 permits exactly one parallel fork and one join")
        fork, join = forks[0], joins[0]
        lane_roots = list(children[fork["id"]])
        if len(lane_roots) != WORKFLOW_V4_MAX_PARALLEL_BRANCHES:
            raise WorkflowStateError("ver.0.0.1 requires exactly two parallel lanes")
        if any(self._normalized_condition(by_id[nid]) for nid in lane_roots):
            raise WorkflowStateError("parallel fork lanes cannot use conditions")
        if any(by_id[nid]["action"] != "research" for nid in lane_roots):
            raise WorkflowStateError("each parallel lane must start with research")

        lanes: list[dict[str, str]] = []
        presentations: list[str] = []
        for research_id in sorted(lane_roots):
            branch = children[research_id]
            if len(branch) != 1:
                raise WorkflowStateError("each parallel research node requires one presentation child")
            presentation_id = branch[0]
            presentation = by_id[presentation_id]
            if presentation["action"] != "presentation":
                raise WorkflowStateError("parallel research must flow directly to presentation")
            if self._normalized_condition(presentation):
                raise WorkflowStateError("parallel presentation edges cannot use conditions")
            if children[presentation_id] != [join["id"]]:
                raise WorkflowStateError("each parallel presentation must flow directly to the join")
            lanes.append({"research": research_id, "presentation": presentation_id})
            presentations.append(presentation_id)

        if sorted(join["depends_on"]) != sorted(presentations):
            raise WorkflowStateError("parallel join must depend on exactly both lane presentations")
        if self._normalized_condition(join):
            raise WorkflowStateError("parallel join cannot use a condition")
        after_join = children[join["id"]]
        if len(after_join) != 1 or by_id[after_join[0]]["kind"] != "decision":
            raise WorkflowStateError("parallel join must flow directly to one deterministic decision")
        decision = by_id[after_join[0]]
        outcomes = {
            self._normalized_condition(by_id[cid]): cid
            for cid in children[decision["id"]]
        }
        if set(outcomes) != {"passed", "failed"}:
            raise WorkflowStateError("post-join decision requires exact passed and failed branches")
        if by_id[outcomes["failed"]]["kind"] != "output":
            raise WorkflowStateError("post-join failed branch must terminate directly at output")
        return {
            "fork": fork["id"],
            "join": join["id"],
            "decision": decision["id"],
            "lanes": lanes,
        }

    def _admit(self, raw_contract: Any) -> tuple[dict[str, Any], str]:
        try:
            contract = validate_contract_v4(raw_contract)
        except WorkflowDesignError as exc:
            raise WorkflowStateError(str(exc)) from exc

        plan = self._parallel_plan(contract)
        if plan is None:
            # Preserve the complete hardened V3 executable slice in V4.
            return super()._admit(contract)

        if contract["trigger"] != "manual":
            raise WorkflowStateError("schedule/event triggers remain design-only in ver.0.0.1")
        if contract["risk_level"] != "low":
            raise WorkflowStateError("ver.0.0.1 execution remains limited to low-risk workflows")
        sensitivity = str(self.bridge.sensitivity)
        if sensitivity == "secret":
            raise WorkflowStateError("Workflow Studio cannot represent secret data class")
        if contract["data_class"] != sensitivity:
            raise WorkflowStateError(
                "workflow data_class must match the active WorkSpace confidentiality zone"
            )

        nodes = contract["nodes"]
        by_id = self._node_map(contract)
        children = self._children(contract)
        roots = [node["id"] for node in nodes if not node["depends_on"]]
        if len(roots) != 1 or by_id[roots[0]]["action"] != "input":
            raise WorkflowStateError("V4 requires exactly one input root")
        if sum(n["action"] == "input" for n in nodes) != 1:
            raise WorkflowStateError("V4 permits exactly one input action")
        if sum(n["action"] == "research" for n in nodes) != 2:
            raise WorkflowStateError("bounded V4 parallel execution requires exactly two research nodes")
        if sum(n["action"] == "presentation" for n in nodes) != 2:
            raise WorkflowStateError("bounded V4 parallel execution requires exactly two presentation nodes")
        if sum(n["action"] == "daily_report" for n in nodes) != 1:
            raise WorkflowStateError("V4 requires exactly one daily_report action")

        for node in nodes:
            pair = (node["kind"], node["action"])
            if pair not in _ALLOWED_PAIRS_V4:
                raise WorkflowStateError(f"node {node['id']} uses a design-only kind/action pair")
            if node["kind"] == "approval":
                if not node["approval_required"]:
                    raise WorkflowStateError("approval nodes must set approval_required=true")
            elif node["approval_required"]:
                raise WorkflowStateError("approval_required may only be asserted by an approval node")

            if len(node["depends_on"]) > 1 and node["action"] != "parallel_join":
                raise WorkflowStateError("only the bounded parallel_join may have multiple parents")
            branch = children[node["id"]]
            if len(branch) > 2:
                raise WorkflowStateError("V4 supports at most two deterministic child edges")
            if len(branch) > 1 and node["kind"] not in {"decision", "approval", "parallel"}:
                raise WorkflowStateError("only decision, approval, or parallel fork may branch")
            if node["action"] == "parallel_join" and len(branch) != 1:
                raise WorkflowStateError("parallel_join requires exactly one downstream decision")

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
                        raise WorkflowStateError(f"{condition} branch must terminate directly at output")
                    seen.add(condition)
                if len(branch) == 2 and seen != expected:
                    raise WorkflowStateError(
                        f"two-way {node['kind']} branch must provide exactly {sorted(expected)}"
                    )
            elif node["action"] != "parallel_fork":
                for child_id in branch:
                    if self._normalized_condition(by_id[child_id]):
                        raise WorkflowStateError(
                            "conditions are executable only after decision or approval nodes"
                        )

        leaves = [node_id for node_id, items in children.items() if not items]
        if not leaves or any(by_id[node_id]["kind"] != "output" for node_id in leaves):
            raise WorkflowStateError("every executable V4 branch must terminate at output")

        # All nodes must be reachable from the one root. The two-lane shape itself
        # was validated by _parallel_plan; this traversal blocks disconnected DAGs.
        visited: set[str] = set()
        stack = [roots[0]]
        while stack:
            node_id = stack.pop()
            if node_id in visited:
                continue
            visited.add(node_id)
            stack.extend(children[node_id])
        if len(visited) != len(nodes):
            raise WorkflowStateError("V4 requires one connected workflow graph")

        join = str(plan["join"])
        # Side effects after a failed lane are prevented by requiring daily_report
        # to be reachable only from the post-join passed path.
        passed_child = next(
            cid
            for cid in children[str(plan["decision"])]
            if self._normalized_condition(by_id[cid]) == "passed"
        )
        downstream: set[str] = set()
        stack = [passed_child]
        while stack:
            nid = stack.pop()
            if nid in downstream:
                continue
            downstream.add(nid)
            stack.extend(children[nid])
        daily_ids = [n["id"] for n in nodes if n["action"] == "daily_report"]
        if any(nid not in downstream for nid in daily_ids):
            raise WorkflowStateError("daily_report must be downstream of the verified post-join passed path")
        if join in downstream:
            raise WorkflowStateError("parallel graph contains an invalid backward dependency")

        return contract, roots[0]

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
            audience = _bounded_text(audience, field="audience", default="R&D internal", limit=120)
            purpose = _bounded_text(purpose, field="purpose", default="inform", limit=80)
            if not isinstance(slide_count, int) or isinstance(slide_count, bool) or not 3 <= slide_count <= 20:
                raise WorkflowStateError("slide_count must be an integer between 3 and 20")
            if str(output_format).strip().lower() != "pptx":
                raise WorkflowStateError("ver.0.0.1 currently supports output_format=pptx only")

            workflow_sha = _canonical_sha256(contract)
            task = self.store.create_task(contract["title"], contract["objective"])
            task_contract = self._task_contract(task.task_id)
            contract_sha = self.bridge.ledger.bind_contract(task_contract)
            dispatch_fingerprint = _canonical_sha256(
                {
                    "schema_version": STATE_SCHEMA_VERSION_V4,
                    "task_id": task.task_id,
                    "workflow_sha256": workflow_sha,
                    "task_contract_sha256": contract_sha,
                    "execution_profile": EXECUTION_PROFILE_V4,
                }
            )
            self._write_contract(task.task_id, contract)
            now = datetime.now(TZ).isoformat()
            state = {
                "schema_version": STATE_SCHEMA_VERSION_V4,
                "release_version": DISPLAY_VERSION,
                "task_id": task.task_id,
                "status": "prepared",
                "revision": 1,
                "execution_profile": EXECUTION_PROFILE_V4,
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
                "parallel_region": None,
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
                "workflow_v4_contract",
                str(self._contract_path(task.task_id)),
            )
            self.store.record_artifact(
                task.task_id,
                "workflow_state",
                "workflow_v4_state",
                str(self._state_path(task.task_id)),
            )
            self.store.record_activity(
                task.task_id,
                "workflow_v4",
                "workflow_prepared",
                "ok",
                f"profile={EXECUTION_PROFILE_V4} workflow={workflow_sha} contract={contract_sha}",
            )
            parallel = self._parallel_plan(contract)
            return {
                "schema_version": STATE_SCHEMA_VERSION_V4,
                "release_version": DISPLAY_VERSION,
                "task_id": task.task_id,
                "status": "prepared",
                "execution_profile": EXECUTION_PROFILE_V4,
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
                "supports_bounded_parallel_dag": True,
                "parallel_region_present": parallel is not None,
                "parallel_max_workers": WORKFLOW_V4_MAX_PARALLEL_WORKERS,
                "parallel_max_branches": WORKFLOW_V4_MAX_PARALLEL_BRANCHES,
                "budget": asdict(task_contract.execution_budget),
                "model_policy": asdict(task_contract.model_policy),
            }

    def _pause_for_approval(self, state: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
        task_id = str(state["task_id"])
        prior_status = self.store.get_task(task_id).status
        revision = int(state.get("revision", 0)) + 1
        checkpoint_fingerprint = _canonical_sha256(
            {
                "schema_version": STATE_SCHEMA_VERSION_V4,
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
            "workflow_v4",
            "approval_checkpoint_paused",
            "blocked",
            f"node={node['id']} revision={revision}",
        )
        return self._summary(state)

    def _child_runtime(self, task_id: str) -> tuple[TaskExecutionBudgetState, TaskModelAuthority]:
        attempt = self.bridge.begin(task_id)
        if attempt.execution_budget is None or attempt.model_authority is None:
            raise WorkflowStateError("parallel child runtime authority binding incomplete")
        return attempt.execution_budget, attempt.model_authority

    def _run_parallel_lane(
        self,
        *,
        parent_state: dict[str, Any],
        research_node: dict[str, Any],
        presentation_node: dict[str, Any],
        child_task_id: str,
    ) -> dict[str, Any]:
        options = dict(parent_state.get("options") or {})
        budget, authority = self._child_runtime(child_task_id)
        try:
            budget.reserve(steps=1)
            with inference_scope(
                child_task_id,
                agent_id="research",
                stage="workflow_v4_parallel_research",
                execution_budget=budget,
                model_authority=authority,
            ):
                self.orchestrator.research_agent.run(
                    child_task_id, self.store, self.artifacts, live=True
                )
            evidence_passed = self.bridge.record_research_evidence(
                child_task_id,
                task_status=self.store.get_task(child_task_id).status,
            )
            if not evidence_passed:
                if self.store.get_task(child_task_id).status != TaskStatus.FAILED:
                    self.store.set_status(child_task_id, TaskStatus.FAILED)
                return {
                    "task_id": child_task_id,
                    "research_node": research_node["id"],
                    "presentation_node": presentation_node["id"],
                    "verified": False,
                    "reason": "research_evidence_failed",
                }

            budget.reserve(steps=1)
            with inference_scope(
                child_task_id,
                agent_id="presentation",
                stage="workflow_v4_parallel_presentation",
                execution_budget=budget,
                model_authority=authority,
            ):
                self.orchestrator.presentation_agent.run(
                    child_task_id,
                    self.store,
                    self.artifacts,
                    live=True,
                    audience=options.get("audience", "R&D internal"),
                    purpose=options.get("purpose", "inform"),
                    language=options.get("language", "ja"),
                    slide_count=int(options.get("slide_count", 6)),
                    output_format="pptx",
                )
            schema_passed = self.bridge.record_presentation_validation(
                child_task_id,
                task_status=self.store.get_task(child_task_id).status,
            )
            verification = self.bridge.evaluate(child_task_id)
            verified = bool(schema_passed and verification.verified)
            self.store.set_status(
                child_task_id,
                TaskStatus.DONE if verified else TaskStatus.FAILED,
            )
            return {
                "task_id": child_task_id,
                "research_node": research_node["id"],
                "presentation_node": presentation_node["id"],
                "verified": verified,
                "reason": "verified" if verified else "required_validator_missing",
            }
        except Exception:
            try:
                if self.store.get_task(child_task_id).status != TaskStatus.FAILED:
                    self.store.set_status(child_task_id, TaskStatus.FAILED)
            except Exception:
                pass
            return {
                "task_id": child_task_id,
                "research_node": research_node["id"],
                "presentation_node": presentation_node["id"],
                "verified": False,
                "reason": "runtime_exception",
            }

    def _record_parent_parallel_validation(
        self,
        state: dict[str, Any],
        results: list[dict[str, Any]],
    ) -> bool:
        task_id = str(state["task_id"])
        child_refs = tuple(str(item["task_id"]) for item in results)
        all_verified = bool(results) and all(bool(item.get("verified")) for item in results)
        for validator in ("evidence", "schema"):
            existing = [
                int(row["attempt"])
                for row in self.store.validator_results_for_task(task_id)
                if str(row["validator"]) == validator
            ]
            self.bridge.ledger.record(
                task_id,
                validator,
                status="passed" if all_verified else "failed",
                reason_code=(
                    "PARALLEL_CHILDREN_VERIFIED"
                    if all_verified
                    else "PARALLEL_CHILD_UNVERIFIED"
                ),
                evidence_refs=child_refs,
                validator_version="parallel-aggregate/v1",
                attempt=max(existing, default=0) + 1,
            )
        state["last_validation"] = {
            "source": "parallel_branches",
            "passed": all_verified,
        }
        return all_verified

    def _run_parallel_region(
        self,
        state: dict[str, Any],
        contract: dict[str, Any],
        plan: dict[str, Any],
    ) -> bool:
        prior = state.get("parallel_region")
        if isinstance(prior, dict) and prior.get("status") in {"starting", "running"}:
            raise WorkflowStateError(
                "automatic replay of an interrupted parallel region is denied"
            )
        if isinstance(prior, dict) and prior.get("status") == "completed":
            raise WorkflowStateError("completed parallel region cannot be replayed")

        parent_budget, _ = self._runtime_context(state)
        parent_budget.reserve(steps=1)
        by_id = self._node_map(contract)
        state["parallel_region"] = {
            "status": "starting",
            "fork_node": plan["fork"],
            "join_node": plan["join"],
            "max_workers": WORKFLOW_V4_MAX_PARALLEL_WORKERS,
            "branches": [],
            "outcome": None,
        }
        state["updated_at"] = datetime.now(TZ).isoformat()
        self._write_state(state)

        branches: list[dict[str, Any]] = []
        for index, lane in enumerate(plan["lanes"], start=1):
            research_node = by_id[lane["research"]]
            child = self.store.create_task(
                f"{contract['title']} · parallel lane {index}",
                f"{contract['objective']} · lane={research_node['label']}",
            )
            branches.append(
                {
                    "task_id": child.task_id,
                    "research_node": lane["research"],
                    "presentation_node": lane["presentation"],
                    "status": "prepared",
                }
            )

        state["parallel_region"]["branches"] = branches
        state["parallel_region"]["status"] = "running"
        state["updated_at"] = datetime.now(TZ).isoformat()
        self._write_state(state)
        self.store.record_activity(
            str(state["task_id"]),
            "workflow_v4",
            "parallel_region_started",
            "ok",
            f"branches={len(branches)} max_workers={WORKFLOW_V4_MAX_PARALLEL_WORKERS}",
        )

        results: list[dict[str, Any]] = []
        try:
            with ThreadPoolExecutor(
                max_workers=WORKFLOW_V4_MAX_PARALLEL_WORKERS,
                thread_name_prefix="workspace-v4-lane",
            ) as pool:
                future_map = {}
                for branch in branches:
                    future = pool.submit(
                        self._run_parallel_lane,
                        parent_state=state,
                        research_node=by_id[branch["research_node"]],
                        presentation_node=by_id[branch["presentation_node"]],
                        child_task_id=branch["task_id"],
                    )
                    future_map[future] = branch["task_id"]
                for future in as_completed(future_map):
                    results.append(future.result())
        finally:
            # Shared model clients may be used by both workers. Never unload one
            # from a branch thread while the other branch can still be generating.
            self._release_agent_model(self.orchestrator.research_agent)
            self._release_agent_model(self.orchestrator.presentation_agent)

        results.sort(key=lambda item: str(item["task_id"]))
        all_verified = self._record_parent_parallel_validation(state, results)
        result_by_task = {str(item["task_id"]): item for item in results}
        for branch in state["parallel_region"]["branches"]:
            result = result_by_task.get(str(branch["task_id"]), {})
            branch["status"] = "verified" if result.get("verified") else "failed"
            branch["reason"] = str(result.get("reason") or "unknown")
        state["parallel_region"]["status"] = "completed"
        state["parallel_region"]["outcome"] = "passed" if all_verified else "failed"
        state["updated_at"] = datetime.now(TZ).isoformat()
        self._write_state(state)
        self.store.record_activity(
            str(state["task_id"]),
            "workflow_v4",
            "parallel_region_completed",
            "ok" if all_verified else "blocked",
            f"outcome={'passed' if all_verified else 'failed'} branches={len(results)}",
        )
        return all_verified

    def _complete_parallel_region(
        self,
        state: dict[str, Any],
        contract: dict[str, Any],
        plan: dict[str, Any],
    ) -> None:
        for node_id in [plan["fork"]]:
            if node_id not in state["completed_nodes"]:
                state["completed_nodes"].append(node_id)
        for lane in plan["lanes"]:
            for node_id in (lane["research"], lane["presentation"]):
                if node_id not in state["completed_nodes"]:
                    state["completed_nodes"].append(node_id)
        if plan["join"] not in state["completed_nodes"]:
            state["completed_nodes"].append(plan["join"])
        next_node = self._next_unconditional(plan["join"], contract)
        state["current_node"] = next_node
        state["revision"] = int(state.get("revision", 0)) + 1
        state["updated_at"] = datetime.now(TZ).isoformat()
        self._write_state(state)

    def _advance(self, state: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
        by_id = self._node_map(contract)
        parallel_plan = self._parallel_plan(contract)
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
                "workflow_v4",
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
            if action == "parallel_fork":
                if parallel_plan is None or node_id != parallel_plan["fork"]:
                    raise WorkflowStateError("parallel fork is not bound to the admitted region")
                self._run_parallel_region(state, contract, parallel_plan)
                self._complete_parallel_region(state, contract, parallel_plan)
                continue
            if action == "parallel_join":
                raise WorkflowStateError("parallel join cannot be entered independently")
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
        parallel = state.get("parallel_region")
        public_parallel = None
        if isinstance(parallel, dict):
            public_parallel = {
                "status": str(parallel.get("status") or "unknown"),
                "fork_node": parallel.get("fork_node"),
                "join_node": parallel.get("join_node"),
                "max_workers": int(parallel.get("max_workers") or 0),
                "outcome": parallel.get("outcome"),
                "branches": [
                    {
                        "task_id": str(item.get("task_id") or ""),
                        "research_node": item.get("research_node"),
                        "presentation_node": item.get("presentation_node"),
                        "status": str(item.get("status") or "unknown"),
                        "reason": str(item.get("reason") or ""),
                    }
                    for item in parallel.get("branches", [])
                    if isinstance(item, dict)
                ],
            }
        return {
            "schema_version": STATE_SCHEMA_VERSION_V4,
            "release_version": DISPLAY_VERSION,
            "task_id": str(state["task_id"]),
            "status": str(state.get("status") or "unknown"),
            "execution_profile": EXECUTION_PROFILE_V4,
            "revision": int(state.get("revision", 0)),
            "current_node": state.get("current_node"),
            "completed_nodes": list(state.get("completed_nodes") or []),
            "checkpoint": public_checkpoint,
            "last_validation": validation,
            "parallel_region": public_parallel,
            "terminal_reason": state.get("terminal_reason"),
            "error": state.get("error"),
        }


# Canonical aggregate-budget enforcement for bounded parallel execution.
from contextvars import ContextVar
from typing import Any

from .execution_budget import TaskExecutionBudgetState
from .linked_execution_budget import LinkedTaskExecutionBudgetState
from .model_authority import TaskModelAuthority


_ACTIVE_PARENT_BUDGET: ContextVar[TaskExecutionBudgetState | None] = ContextVar(
    "workspace_v4_parallel_parent_budget",
    default=None,
)


class BudgetedWorkflowStateMachineV4Controller(WorkflowStateMachineV4Controller):
    """Production V4 controller with aggregate parent budget enforcement.

    The base V4 state machine owns graph admission, child-task isolation and join
    semantics. This production controller strengthens only the execution-budget
    boundary: every child reservation is atomically charged to the child budget
    and the immutable parent workflow budget.
    """

    def _run_parallel_lane(
        self,
        *,
        parent_state: dict[str, Any],
        research_node: dict[str, Any],
        presentation_node: dict[str, Any],
        child_task_id: str,
    ) -> dict[str, Any]:
        parent_task_id = str(parent_state.get("task_id") or "").strip()
        if not parent_task_id:
            raise WorkflowStateError("parallel parent task identity is missing")
        parent_budget = TaskExecutionBudgetState.from_bound_contract(
            self.store,
            parent_task_id,
        )
        token = _ACTIVE_PARENT_BUDGET.set(parent_budget)
        try:
            return super()._run_parallel_lane(
                parent_state=parent_state,
                research_node=research_node,
                presentation_node=presentation_node,
                child_task_id=child_task_id,
            )
        finally:
            _ACTIVE_PARENT_BUDGET.reset(token)

    def _child_runtime(
        self,
        task_id: str,
    ) -> tuple[LinkedTaskExecutionBudgetState, TaskModelAuthority]:
        parent_budget = _ACTIVE_PARENT_BUDGET.get()
        if parent_budget is None:
            raise WorkflowStateError("parallel aggregate parent budget is not bound")
        child_budget, authority = super()._child_runtime(task_id)
        linked = LinkedTaskExecutionBudgetState.from_states(parent_budget, child_budget)
        return linked, authority
