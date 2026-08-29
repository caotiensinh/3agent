from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .artifacts import ArtifactManager
from .context_engine import ContextEngine
from .knowledge_plane import LocalKnowledgeIndex
from .models import TaskStatus
from .route_planner import DeterministicRoutePlanner
from .store import TaskStore
from .task_contract import TaskContractCompiler
from .validator_ledger import ValidatorLedger


RETRIEVAL_RESULT_SCHEMA = "workspace-deterministic-retrieval/v1"


@dataclass(frozen=True)
class DeterministicRetrievalResult:
    task_id: str
    status: str
    task_status: str
    route: dict
    artifact_path: str | None
    verification: dict
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "schema_version": RETRIEVAL_RESULT_SCHEMA,
            "task_id": self.task_id,
            "status": self.status,
            "task_status": self.task_status,
            "route": self.route,
            "artifact_path": self.artifact_path,
            "verification": self.verification,
            "error": self.error,
        }


class DeterministicRetrievalExecutor:
    """Verified local retrieval lane that performs zero LLM inference.

    This executor is intentionally narrow. It searches only the already-imported
    local public-knowledge mirror through ContextEngine. It has no Internet gateway,
    no model client and no escalation path. Task completion still requires an
    immutable TaskContract plus authoritative policy/evidence validator PASS.
    """

    def __init__(
        self,
        store: TaskStore,
        artifacts: ArtifactManager,
        knowledge_root: Path,
    ):
        self.store = store
        self.artifacts = artifacts
        self.knowledge_root = Path(knowledge_root)
        self.compiler = TaskContractCompiler()
        self.ledger = ValidatorLedger(store)

    @staticmethod
    def _artifact_ref(path: Path) -> str:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    def run(
        self,
        title: str,
        query: str,
        *,
        sensitivity: str = "confidential",
        risk_level: str = "low",
        max_hits: int = 8,
    ) -> DeterministicRetrievalResult:
        clean_title = str(title or "").strip()
        clean_query = str(query or "").strip()
        if not clean_title:
            raise ValueError("title is required")
        if not clean_query:
            raise ValueError("query is required")
        if not 1 <= int(max_hits) <= 20:
            raise ValueError("max_hits must be between 1 and 20")

        task = self.store.create_task(clean_title, clean_query)
        contract = self.compiler.compile(
            task_id=task.task_id,
            task_type="retrieval",
            sensitivity=sensitivity,
            risk_level=risk_level,
            allowed_sources=("local_public_knowledge_mirror",),
            allowed_tools=("search_docs", "read_file"),
            public_web=False,
            deterministic_only=True,
        )
        contract_digest = self.ledger.bind_contract(contract)
        self.ledger.record(
            task.task_id,
            "policy",
            status="passed",
            reason_code="POLICY_CONTRACT_VALIDATED",
            evidence_refs=(contract_digest,),
            validator_version="deterministic-retrieval-policy/v1",
            attempt=1,
        )

        route = DeterministicRoutePlanner.plan(contract)
        if route.route != "NO_LLM":
            self.store.set_status(task.task_id, TaskStatus.FAILED)
            raise RuntimeError("DETERMINISTIC_RETRIEVAL_ROUTE_NOT_NO_LLM")
        self.store.record_activity(
            task.task_id,
            "route_planner",
            "route_selected",
            "ok",
            (
                f"route={route.route} reason={route.reason_code} "
                f"initial={route.initial_model_tier} max={route.max_model_tier} "
                f"escalation={str(route.escalation_allowed).lower()}"
            ),
        )

        try:
            packed = ContextEngine(LocalKnowledgeIndex(self.knowledge_root)).build_public_evidence(
                clean_query,
                contract,
                max_hits=int(max_hits),
            )
        except Exception as exc:
            self.ledger.record(
                task.task_id,
                "evidence",
                status="failed",
                reason_code="DETERMINISTIC_RETRIEVAL_EXECUTION_FAILED",
                validator_version="deterministic-retrieval-evidence/v1",
                attempt=1,
            )
            self.store.set_status(task.task_id, TaskStatus.FAILED)
            verification = self.ledger.evaluate(task.task_id)
            return DeterministicRetrievalResult(
                task_id=task.task_id,
                status="failed",
                task_status=TaskStatus.FAILED.value,
                route=route.to_dict(),
                artifact_path=None,
                verification=verification.to_dict(),
                error=f"{type(exc).__name__}: {exc}"[:600],
            )

        payload = {
            "schema_version": RETRIEVAL_RESULT_SCHEMA,
            "task_id": task.task_id,
            "route": route.to_dict(),
            "contract_sha256": contract_digest,
            "context": packed.to_dict(),
        }
        json_path, _ = self.artifacts.write_task_artifact(
            "deterministic_retrieval",
            task.task_id,
            payload,
            packed.text or "No local evidence matched the deterministic retrieval query.",
        )
        artifact_ref = self._artifact_ref(json_path)
        self.store.record_artifact(
            task.task_id,
            "deterministic_retrieval",
            "retrieval_result",
            str(json_path),
            json.dumps(
                {
                    "schema_version": RETRIEVAL_RESULT_SCHEMA,
                    "route": "NO_LLM",
                    "artifact_sha256": artifact_ref,
                    "raw_content_in_validator_ledger": False,
                },
                separators=(",", ":"),
            ),
        )

        trace = packed.retrieval_trace or {}
        evidence_passed = bool(packed.evidence) and trace.get("hard_budget_respected") is True
        self.ledger.record(
            task.task_id,
            "evidence",
            status="passed" if evidence_passed else "failed",
            reason_code=(
                "DETERMINISTIC_RETRIEVAL_EVIDENCE_VERIFIED"
                if evidence_passed
                else "DETERMINISTIC_RETRIEVAL_EVIDENCE_MISSING"
            ),
            evidence_refs=(artifact_ref,),
            validator_version="deterministic-retrieval-evidence/v1",
            attempt=1,
        )

        verification = self.ledger.evaluate(task.task_id)
        if verification.verified:
            final_status = TaskStatus.DONE
            result_status = "completed"
        elif verification.missing_validators == ("human",) and not verification.failed_validators:
            final_status = TaskStatus.WAITING_HUMAN
            result_status = "blocked"
        else:
            final_status = TaskStatus.FAILED
            result_status = "failed"
        self.store.set_status(task.task_id, final_status)
        self.store.record_activity(
            task.task_id,
            "deterministic_retrieval",
            "execution_completed",
            "ok" if result_status == "completed" else result_status,
            (
                f"route=NO_LLM verified={str(verification.verified).lower()} "
                f"evidence_refs={len(packed.evidence)}"
            ),
        )
        return DeterministicRetrievalResult(
            task_id=task.task_id,
            status=result_status,
            task_status=final_status.value,
            route=route.to_dict(),
            artifact_path=str(json_path),
            verification=verification.to_dict(),
            error=None if evidence_passed else "DETERMINISTIC_RETRIEVAL_EVIDENCE_MISSING",
        )
