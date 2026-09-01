"""Authenticated, checkpoint-bound Phase 4J curation revision coordinator."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from .adaptive_learning_checkpoint import (
    LearningCheckpoint,
    LearningCheckpointAuthority,
    LearningCheckpointError,
    LearningStagingGateway,
)
from .adaptive_learning_contract import KnowledgeCandidate
from .adaptive_learning_curation import CurationProposalSet, KnowledgeCurationProposal
from .adaptive_learning_curation_revision_contract import (
    CurationRevisionContractError,
    CurationRevisionPacket,
    CurationRevisionResult,
    REVISION_ACTIONS,
    parse_strict_curation_revision_result,
)
from .adaptive_learning_evaluation import AdaptiveLearningDomainValidator
from .adaptive_learning_promotion import (
    LearningPromotionAuthorizationError,
    LearningReviewerAuthorizationPolicy,
)
from .adaptive_learning_reflection_worker import (
    ReflectionWorkerConfig,
    ReflectionWorkerError,
    assert_loopback_ollama_base_url,
)
from .adaptive_learning_store import AdaptiveLearningStore
from .workspace_auth import USER_ID_RE, WorkspaceAuthStore

APPROVAL_SCHEMA = "workspace-learning-curation-revision-approval/v1"
RECEIPT_SCHEMA = "workspace-learning-curation-revision-receipt/v1"
_MAX_STDERR_BYTES = 4096
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_APPROVAL_ID = re.compile(r"^curation-revision-approval:[0-9a-f]{64}$")


class CurationRevisionError(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code)
        super().__init__(self.reason_code)


class CurationRevisionAuthorizationError(PermissionError):
    pass


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha_payload(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _require_sha(value: Any, code: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA.fullmatch(text):
        raise CurationRevisionError(code)
    return text


def _actor_id(user_id: str) -> str:
    value = str(user_id or "").strip().lower()
    if not USER_ID_RE.fullmatch(value):
        raise CurationRevisionAuthorizationError("CURATION_REVISION_PRINCIPAL_INVALID")
    return f"workspace-user:{value}"


def _proposal_sha256(proposal: KnowledgeCurationProposal) -> str:
    proposal.validate()
    return _sha_payload(proposal.to_payload())


def _active_snapshot(
    store: AdaptiveLearningStore,
    item_id: str,
) -> tuple[dict[str, Any], KnowledgeCandidate]:
    with store.connect() as conn:
        store._assert_ledger_integrity(conn)
        row = store._active_row(conn, item_id)
        if row is None:
            raise CurationRevisionError("CURATION_REVISION_TARGET_NOT_ACTIVE")
        candidate = store._candidate_from_row(row)
        candidate.validate()
        return dict(row), candidate


def _proposal_from_set(
    proposal_set: CurationProposalSet,
    proposal_id: str,
) -> KnowledgeCurationProposal:
    proposal_set.validate()
    matches = [value for value in proposal_set.proposals if value.proposal_id == proposal_id]
    if len(matches) != 1:
        raise CurationRevisionError("CURATION_REVISION_PROPOSAL_NOT_FOUND")
    proposal = matches[0].validate()
    if proposal.curation_action not in REVISION_ACTIONS:
        raise CurationRevisionError("CURATION_REVISION_ACTION_FORBIDDEN")
    if not proposal.human_review_required:
        raise CurationRevisionError("CURATION_REVISION_HUMAN_REVIEW_REQUIRED")
    return proposal


@dataclass(frozen=True)
class AuthenticatedCurationRevisionApproval:
    approval_id: str
    proposal_id: str
    proposal_sha256: str
    proposal_set_sha256: str
    item_id: str
    knowledge_sha256: str
    candidate_sha256: str
    domain: str
    curation_action: str
    actor_id: str
    human_review_satisfied: bool
    domain_review_satisfied: bool
    expected_checkpoint_sequence: int
    expected_checkpoint_sha256: str
    expected_state_sha256: str
    capability_grants: tuple[str, ...] = ()
    schema_version: str = APPROVAL_SCHEMA

    def _base_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "proposal_id": self.proposal_id,
            "proposal_sha256": self.proposal_sha256,
            "proposal_set_sha256": self.proposal_set_sha256,
            "item_id": self.item_id,
            "knowledge_sha256": self.knowledge_sha256,
            "candidate_sha256": self.candidate_sha256,
            "domain": self.domain,
            "curation_action": self.curation_action,
            "actor_id": self.actor_id,
            "human_review_satisfied": self.human_review_satisfied,
            "domain_review_satisfied": self.domain_review_satisfied,
            "expected_checkpoint_sequence": self.expected_checkpoint_sequence,
            "expected_checkpoint_sha256": self.expected_checkpoint_sha256,
            "expected_state_sha256": self.expected_state_sha256,
            "capability_grants": list(self.capability_grants),
        }

    @classmethod
    def create(
        cls,
        *,
        proposal: KnowledgeCurationProposal,
        proposal_set: CurationProposalSet,
        actor_id: str,
        domain_review_satisfied: bool,
    ) -> "AuthenticatedCurationRevisionApproval":
        proposal.validate()
        proposal_set.validate()
        base = {
            "schema_version": APPROVAL_SCHEMA,
            "proposal_id": proposal.proposal_id,
            "proposal_sha256": _proposal_sha256(proposal),
            "proposal_set_sha256": proposal_set.proposal_set_sha256,
            "item_id": proposal.item_id,
            "knowledge_sha256": proposal.knowledge_sha256,
            "candidate_sha256": proposal.candidate_sha256,
            "domain": proposal.domain,
            "curation_action": proposal.curation_action,
            "actor_id": actor_id,
            "human_review_satisfied": True,
            "domain_review_satisfied": bool(domain_review_satisfied),
            "expected_checkpoint_sequence": proposal_set.checkpoint_sequence,
            "expected_checkpoint_sha256": proposal_set.checkpoint_sha256,
            "expected_state_sha256": proposal_set.state_sha256,
            "capability_grants": [],
        }
        approval_id = "curation-revision-approval:" + hashlib.sha256(
            _canonical(base).encode("utf-8")
        ).hexdigest()
        return cls(
            approval_id=approval_id,
            proposal_id=proposal.proposal_id,
            proposal_sha256=base["proposal_sha256"],
            proposal_set_sha256=proposal_set.proposal_set_sha256,
            item_id=proposal.item_id,
            knowledge_sha256=proposal.knowledge_sha256,
            candidate_sha256=proposal.candidate_sha256,
            domain=proposal.domain,
            curation_action=proposal.curation_action,
            actor_id=actor_id,
            human_review_satisfied=True,
            domain_review_satisfied=bool(domain_review_satisfied),
            expected_checkpoint_sequence=proposal_set.checkpoint_sequence,
            expected_checkpoint_sha256=proposal_set.checkpoint_sha256,
            expected_state_sha256=proposal_set.state_sha256,
        ).validate()

    def validate(self) -> "AuthenticatedCurationRevisionApproval":
        if self.schema_version != APPROVAL_SCHEMA:
            raise CurationRevisionError("CURATION_REVISION_APPROVAL_SCHEMA_INVALID")
        if self.curation_action not in REVISION_ACTIONS:
            raise CurationRevisionError("CURATION_REVISION_ACTION_FORBIDDEN")
        if self.capability_grants != ():
            raise CurationRevisionError("CURATION_REVISION_APPROVAL_CAPABILITY_FORBIDDEN")
        if not self.human_review_satisfied:
            raise CurationRevisionError("CURATION_REVISION_HUMAN_REVIEW_REQUIRED")
        if not self.proposal_id or len(self.proposal_id) > 128:
            raise CurationRevisionError("CURATION_REVISION_PROPOSAL_ID_INVALID")
        if not self.item_id or len(self.item_id) > 128:
            raise CurationRevisionError("CURATION_REVISION_ITEM_ID_INVALID")
        for value, code in (
            (self.proposal_sha256, "CURATION_REVISION_PROPOSAL_SHA_INVALID"),
            (self.proposal_set_sha256, "CURATION_REVISION_PROPOSAL_SET_SHA_INVALID"),
            (self.knowledge_sha256, "CURATION_REVISION_KNOWLEDGE_SHA_INVALID"),
            (self.candidate_sha256, "CURATION_REVISION_CANDIDATE_SHA_INVALID"),
            (self.expected_checkpoint_sha256, "CURATION_REVISION_CHECKPOINT_SHA_INVALID"),
            (self.expected_state_sha256, "CURATION_REVISION_STATE_SHA_INVALID"),
        ):
            _require_sha(value, code)
        if not self.actor_id.startswith("workspace-user:usr_"):
            raise CurationRevisionError("CURATION_REVISION_PRINCIPAL_INVALID")
        if not isinstance(self.expected_checkpoint_sequence, int) or isinstance(self.expected_checkpoint_sequence, bool) or self.expected_checkpoint_sequence < 1:
            raise CurationRevisionError("CURATION_REVISION_CHECKPOINT_SEQUENCE_INVALID")
        expected_id = "curation-revision-approval:" + hashlib.sha256(
            _canonical(self._base_payload()).encode("utf-8")
        ).hexdigest()
        if not _APPROVAL_ID.fullmatch(self.approval_id) or self.approval_id != expected_id:
            raise CurationRevisionError("CURATION_REVISION_APPROVAL_ID_MISMATCH")
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return {"approval_id": self.approval_id, **self._base_payload()}

    @property
    def sha256(self) -> str:
        return _sha_payload(self.to_payload())


class AuthenticatedCurationRevisionApprovalService:
    """Authenticate one reviewer and approve one exact adverse curation proposal."""

    def __init__(
        self,
        auth: WorkspaceAuthStore,
        store: AdaptiveLearningStore,
        authority: LearningCheckpointAuthority,
        reviewer_policy: LearningReviewerAuthorizationPolicy,
    ) -> None:
        self.__auth = auth
        self.__store = store
        self.__authority = authority
        self.__reviewer_policy = reviewer_policy
        self.__authority.verify(self.__store)

    def _principal(self, session_token: str, client_ip: str):
        user = self.__auth.user_for_session(session_token, client_ip)
        if user is None:
            raise CurationRevisionAuthorizationError("CURATION_REVISION_SESSION_INVALID")
        user_id = str(user.get("user_id") or "").strip().lower()
        actor = _actor_id(user_id)
        try:
            grant = self.__reviewer_policy.grant_for(user_id)
        except LearningPromotionAuthorizationError as exc:
            raise CurationRevisionAuthorizationError(
                "CURATION_REVISION_REVIEWER_NOT_AUTHORIZED"
            ) from exc
        if actor != f"workspace-user:{grant.normalized_user_id}":
            raise CurationRevisionAuthorizationError(
                "CURATION_REVISION_PRINCIPAL_GRANT_MISMATCH"
            )
        return actor, grant

    @staticmethod
    def _checkpoint_matches(checkpoint: LearningCheckpoint, proposal_set: CurationProposalSet) -> bool:
        return (
            checkpoint.sequence == proposal_set.checkpoint_sequence
            and checkpoint.checkpoint_sha256 == proposal_set.checkpoint_sha256
            and checkpoint.state_sha256 == proposal_set.state_sha256
        )

    def approve(
        self,
        *,
        proposal_set: CurationProposalSet,
        proposal_id: str,
        session_token: str,
        client_ip: str,
    ) -> AuthenticatedCurationRevisionApproval:
        proposal = _proposal_from_set(proposal_set, proposal_id)
        actor, grant = self._principal(session_token, client_ip)
        domain_satisfied = proposal.domain in grant.normalized_domains
        if proposal.domain_review_required and not domain_satisfied:
            raise CurationRevisionAuthorizationError(
                "CURATION_REVISION_DOMAIN_REVIEW_NOT_AUTHORIZED"
            )
        before = self.__authority.verify(self.__store)
        if not self._checkpoint_matches(before, proposal_set):
            raise CurationRevisionAuthorizationError(
                "CURATION_REVISION_PROPOSAL_SET_STALE"
            )
        row, active = _active_snapshot(self.__store, proposal.item_id)
        if (
            str(row["knowledge_sha256"]) != proposal.knowledge_sha256
            or str(row["candidate_sha256"]) != proposal.candidate_sha256
            or str(row["level"]) != proposal.active_level
            or active.domain != proposal.domain
        ):
            raise CurationRevisionAuthorizationError(
                "CURATION_REVISION_TARGET_CHANGED"
            )
        after = self.__authority.verify(self.__store)
        if before.checkpoint_sha256 != after.checkpoint_sha256:
            raise CurationRevisionAuthorizationError(
                "CURATION_REVISION_CHECKPOINT_CHANGED_DURING_APPROVAL"
            )
        return AuthenticatedCurationRevisionApproval.create(
            proposal=proposal,
            proposal_set=proposal_set,
            actor_id=actor,
            domain_review_satisfied=domain_satisfied,
        )


class CurationRevisionBoundCheckpointAuthority(LearningCheckpointAuthority):
    """One-shot expected-state binding consumed inside a checkpointed stage lock."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.__curation_expectation = threading.local()

    @contextmanager
    def expect_curation_stage(
        self,
        *,
        sequence: int,
        checkpoint_sha256: str,
        state_sha256: str,
    ) -> Iterator[None]:
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            raise LearningCheckpointError("CURATION_REVISION_EXPECTED_SEQUENCE_INVALID")
        checkpoint_hash = _require_sha(
            checkpoint_sha256, "CURATION_REVISION_EXPECTED_CHECKPOINT_SHA_INVALID"
        )
        state_hash = _require_sha(
            state_sha256, "CURATION_REVISION_EXPECTED_STATE_SHA_INVALID"
        )
        if getattr(self.__curation_expectation, "value", None) is not None:
            raise LearningCheckpointError("CURATION_REVISION_EXPECTATION_ALREADY_ACTIVE")
        self.__curation_expectation.value = (sequence, checkpoint_hash, state_hash)
        try:
            yield
        finally:
            self.__curation_expectation.value = None

    def _mutate(self, store: AdaptiveLearningStore, *, mutation_kind: str, **kwargs):
        expectation = getattr(self.__curation_expectation, "value", None)
        if expectation is not None and mutation_kind != "stage":
            raise LearningCheckpointError(
                "CURATION_REVISION_EXPECTATION_MUTATION_KIND_MISMATCH"
            )
        return super()._mutate(store, mutation_kind=mutation_kind, **kwargs)

    def _verify_store(self, store: AdaptiveLearningStore) -> LearningCheckpoint:
        checkpoint = super()._verify_store(store)
        expectation = getattr(self.__curation_expectation, "value", None)
        if expectation is None:
            return checkpoint
        self.__curation_expectation.value = None
        expected_sequence, expected_checkpoint, expected_state = expectation
        if checkpoint.sequence != expected_sequence:
            raise LearningCheckpointError("CURATION_REVISION_EXPECTED_SEQUENCE_MISMATCH")
        if checkpoint.checkpoint_sha256 != expected_checkpoint:
            raise LearningCheckpointError("CURATION_REVISION_EXPECTED_CHECKPOINT_MISMATCH")
        if checkpoint.state_sha256 != expected_state:
            raise LearningCheckpointError("CURATION_REVISION_EXPECTED_STATE_MISMATCH")
        return checkpoint


@dataclass(frozen=True)
class CurationRevisionWorkerExecutionConfig:
    base_url: str
    model: str
    timeout_seconds: int = 180
    keep_alive: str = "2m"

    def validate(self) -> "CurationRevisionWorkerExecutionConfig":
        try:
            assert_loopback_ollama_base_url(self.base_url)
            ReflectionWorkerConfig(
                self.base_url,
                self.model,
                self.timeout_seconds,
                self.keep_alive,
            ).validate()
        except ReflectionWorkerError as exc:
            raise CurationRevisionError(str(exc)) from exc
        return self


class IsolatedCurationRevisionRunner:
    """Invoke the no-tool Phase 4J worker in a separate Python process."""

    def __init__(
        self,
        config: CurationRevisionWorkerExecutionConfig,
        *,
        executor: Callable[..., Any] = subprocess.run,
        python_executable: str | None = None,
    ) -> None:
        self.config = config.validate()
        self.executor = executor
        self.python_executable = str(python_executable or sys.executable)

    def _environment(self) -> dict[str, str]:
        env = {
            "PYTHONIOENCODING": "utf-8",
            "WORKSPACE_CURATION_REVISION_OLLAMA_BASE_URL": assert_loopback_ollama_base_url(self.config.base_url),
            "WORKSPACE_CURATION_REVISION_MODEL": self.config.model,
            "WORKSPACE_CURATION_REVISION_TIMEOUT_SECONDS": str(int(self.config.timeout_seconds)),
            "WORKSPACE_CURATION_REVISION_KEEP_ALIVE": self.config.keep_alive,
        }
        for name in ("SYSTEMROOT", "WINDIR"):
            value = os.environ.get(name)
            if value:
                env[name] = value
        return env

    def run(self, packet: CurationRevisionPacket) -> CurationRevisionResult:
        packet.validate()
        try:
            with tempfile.TemporaryDirectory(prefix="workspace-curation-revision-") as tmp:
                completed = self.executor(
                    (
                        self.python_executable,
                        "-I",
                        "-m",
                        "three_agent.adaptive_learning_curation_revision_worker",
                    ),
                    input=_canonical(packet.to_payload()),
                    text=True,
                    encoding="utf-8",
                    errors="strict",
                    capture_output=True,
                    timeout=int(self.config.timeout_seconds) + 30,
                    cwd=tmp,
                    env=self._environment(),
                    shell=False,
                    close_fds=True,
                )
        except (OSError, subprocess.SubprocessError) as exc:
            raise CurationRevisionError("CURATION_REVISION_WORKER_EXECUTION_FAILED") from exc
        if int(getattr(completed, "returncode", 1)) != 0:
            stderr = str(getattr(completed, "stderr", "") or "")
            if len(stderr.encode("utf-8", errors="ignore")) > _MAX_STDERR_BYTES:
                stderr = stderr[:_MAX_STDERR_BYTES]
            raise CurationRevisionError("CURATION_REVISION_WORKER_FAILED")
        try:
            return parse_strict_curation_revision_result(str(getattr(completed, "stdout", "")))
        except CurationRevisionContractError as exc:
            raise CurationRevisionError(exc.reason_code) from exc


@dataclass(frozen=True)
class CurationRevisionReceipt:
    receipt_id: str
    approval_id: str
    proposal_id: str
    base_knowledge_sha256: str
    status: str
    result: str | None
    candidate_sha256: str | None
    reason_codes: tuple[str, ...]
    created_at: str
    updated_at: str
    record_sha256: str
    schema_version: str = RECEIPT_SCHEMA

    def signing_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["reason_codes"] = list(self.reason_codes)
        payload.pop("record_sha256")
        return payload

    def to_payload(self) -> dict[str, Any]:
        return {**self.signing_payload(), "record_sha256": self.record_sha256}


class CurationRevisionReceiptStore:
    """Parent-owned write-once metadata receipts for no-repeat revision reflection."""

    def __init__(self, root: Path):
        self.root = Path(root)

    @staticmethod
    def _receipt_id(approval: AuthenticatedCurationRevisionApproval) -> str:
        return "curation-revision-receipt:" + hashlib.sha256(
            _canonical(
                {
                    "schema_version": RECEIPT_SCHEMA,
                    "approval_id": approval.approval_id,
                    "proposal_id": approval.proposal_id,
                    "base_knowledge_sha256": approval.knowledge_sha256,
                }
            ).encode("utf-8")
        ).hexdigest()

    def _path(self, approval: AuthenticatedCurationRevisionApproval) -> Path:
        return self.root / (self._receipt_id(approval).split(":", 1)[1] + ".json")

    @classmethod
    def _record(
        cls,
        approval: AuthenticatedCurationRevisionApproval,
        *,
        status: str,
        result: str | None,
        candidate_sha256: str | None,
        reason_codes: tuple[str, ...],
        created_at: str,
        updated_at: str,
    ) -> CurationRevisionReceipt:
        base = {
            "schema_version": RECEIPT_SCHEMA,
            "receipt_id": cls._receipt_id(approval),
            "approval_id": approval.approval_id,
            "proposal_id": approval.proposal_id,
            "base_knowledge_sha256": approval.knowledge_sha256,
            "status": status,
            "result": result,
            "candidate_sha256": candidate_sha256,
            "reason_codes": list(reason_codes),
            "created_at": created_at,
            "updated_at": updated_at,
        }
        return CurationRevisionReceipt(
            receipt_id=base["receipt_id"],
            approval_id=approval.approval_id,
            proposal_id=approval.proposal_id,
            base_knowledge_sha256=approval.knowledge_sha256,
            status=status,
            result=result,
            candidate_sha256=candidate_sha256,
            reason_codes=reason_codes,
            created_at=created_at,
            updated_at=updated_at,
            record_sha256=_sha_payload(base),
        )

    @staticmethod
    def _parse(payload: Any) -> CurationRevisionReceipt:
        fields = {
            "schema_version", "receipt_id", "approval_id", "proposal_id",
            "base_knowledge_sha256", "status", "result", "candidate_sha256",
            "reason_codes", "created_at", "updated_at", "record_sha256",
        }
        if not isinstance(payload, dict) or set(payload) != fields or payload.get("schema_version") != RECEIPT_SCHEMA:
            raise CurationRevisionError("CURATION_REVISION_RECEIPT_INVALID")
        reasons = payload.get("reason_codes")
        if not isinstance(reasons, list) or len(reasons) > 16:
            raise CurationRevisionError("CURATION_REVISION_RECEIPT_INVALID")
        receipt = CurationRevisionReceipt(
            receipt_id=str(payload["receipt_id"]),
            approval_id=str(payload["approval_id"]),
            proposal_id=str(payload["proposal_id"]),
            base_knowledge_sha256=str(payload["base_knowledge_sha256"]),
            status=str(payload["status"]),
            result=None if payload["result"] is None else str(payload["result"]),
            candidate_sha256=None if payload["candidate_sha256"] is None else str(payload["candidate_sha256"]),
            reason_codes=tuple(str(x) for x in reasons),
            created_at=str(payload["created_at"]),
            updated_at=str(payload["updated_at"]),
            record_sha256=str(payload["record_sha256"]),
        )
        if receipt.status not in {"claimed", "completed"}:
            raise CurationRevisionError("CURATION_REVISION_RECEIPT_INVALID")
        if not _SHA.fullmatch(receipt.base_knowledge_sha256):
            raise CurationRevisionError("CURATION_REVISION_RECEIPT_INVALID")
        if receipt.candidate_sha256 is not None and not _SHA.fullmatch(receipt.candidate_sha256):
            raise CurationRevisionError("CURATION_REVISION_RECEIPT_INVALID")
        if receipt.record_sha256 != _sha_payload(receipt.signing_payload()):
            raise CurationRevisionError("CURATION_REVISION_RECEIPT_HASH_MISMATCH")
        return receipt

    def read(self, approval: AuthenticatedCurationRevisionApproval) -> CurationRevisionReceipt | None:
        path = self._path(approval)
        if not path.exists():
            return None
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024:
                raise CurationRevisionError("CURATION_REVISION_RECEIPT_INVALID")
            return self._parse(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            raise CurationRevisionError("CURATION_REVISION_RECEIPT_INVALID") from exc

    def claim(self, approval: AuthenticatedCurationRevisionApproval) -> CurationRevisionReceipt:
        approval.validate()
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            if os.name == "posix":
                self.root.chmod(0o700)
        except OSError:
            pass
        now = _now_z()
        receipt = self._record(
            approval,
            status="claimed",
            result=None,
            candidate_sha256=None,
            reason_codes=(),
            created_at=now,
            updated_at=now,
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self._path(approval), flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(_canonical(receipt.to_payload()))
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError as exc:
            existing = self.read(approval)
            code = "CURATION_REVISION_ALREADY_COMPLETED" if existing and existing.status == "completed" else "CURATION_REVISION_CLAIM_RECOVERY_REQUIRED"
            raise CurationRevisionError(code) from exc
        except OSError as exc:
            raise CurationRevisionError("CURATION_REVISION_RECEIPT_WRITE_FAILED") from exc
        return receipt

    def complete(
        self,
        approval: AuthenticatedCurationRevisionApproval,
        claimed: CurationRevisionReceipt,
        *,
        result: str,
        candidate_sha256: str | None = None,
        reason_codes: tuple[str, ...] = (),
    ) -> CurationRevisionReceipt:
        current = self.read(approval)
        if current is None or current.record_sha256 != claimed.record_sha256 or current.status != "claimed":
            raise CurationRevisionError("CURATION_REVISION_RECEIPT_CONCURRENT_CHANGE")
        completed = self._record(
            approval,
            status="completed",
            result=result,
            candidate_sha256=candidate_sha256,
            reason_codes=reason_codes,
            created_at=claimed.created_at,
            updated_at=_now_z(),
        )
        path = self._path(approval)
        temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(temp, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(_canonical(completed.to_payload()))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, path)
            if os.name == "posix":
                path.chmod(0o600)
        except OSError as exc:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
            raise CurationRevisionError("CURATION_REVISION_RECEIPT_WRITE_FAILED") from exc
        return completed


@dataclass(frozen=True)
class CurationRevisionOutcome:
    result: str
    approval_id: str
    proposal_id: str
    candidate_id: str | None = None
    candidate_sha256: str | None = None


class CurationRevisionCoordinator:
    """Trusted parent: exact approval -> isolated revision -> stage-only patch."""

    def __init__(
        self,
        store: AdaptiveLearningStore,
        authority: CurationRevisionBoundCheckpointAuthority,
        runner: IsolatedCurationRevisionRunner,
        receipt_store: CurationRevisionReceiptStore,
    ) -> None:
        self.__store = store
        self.__authority = authority
        self.__runner = runner
        self.__receipt_store = receipt_store
        self.__staging = LearningStagingGateway(store, authority)
        self.__authority.verify(self.__store)

    @staticmethod
    def _checkpoint_matches(
        checkpoint: LearningCheckpoint,
        approval: AuthenticatedCurationRevisionApproval,
    ) -> bool:
        return (
            checkpoint.sequence == approval.expected_checkpoint_sequence
            and checkpoint.checkpoint_sha256 == approval.expected_checkpoint_sha256
            and checkpoint.state_sha256 == approval.expected_state_sha256
        )

    @staticmethod
    def _metrics(proposal: KnowledgeCurationProposal) -> dict[str, int]:
        evidence = proposal.evidence
        return {
            "unique_task_observations": evidence.unique_task_observations,
            "isolated_task_observations": evidence.isolated_task_observations,
            "confounded_task_observations": evidence.confounded_task_observations,
            "isolated_verified_success": evidence.isolated_verified_success,
            "isolated_failed": evidence.isolated_failed,
            "isolated_waiting_human": evidence.isolated_waiting_human,
            "isolated_done_unverified": evidence.isolated_done_unverified,
        }

    def _bind(
        self,
        proposal_set: CurationProposalSet,
        approval: AuthenticatedCurationRevisionApproval,
    ) -> tuple[KnowledgeCurationProposal, dict[str, Any], KnowledgeCandidate]:
        approval.validate()
        proposal = _proposal_from_set(proposal_set, approval.proposal_id)
        if (
            proposal_set.proposal_set_sha256 != approval.proposal_set_sha256
            or _proposal_sha256(proposal) != approval.proposal_sha256
            or proposal.item_id != approval.item_id
            or proposal.knowledge_sha256 != approval.knowledge_sha256
            or proposal.candidate_sha256 != approval.candidate_sha256
            or proposal.domain != approval.domain
            or proposal.curation_action != approval.curation_action
        ):
            raise CurationRevisionError("CURATION_REVISION_APPROVAL_BINDING_MISMATCH")
        if proposal.domain_review_required and not approval.domain_review_satisfied:
            raise CurationRevisionError("CURATION_REVISION_DOMAIN_REVIEW_REQUIRED")
        checkpoint = self.__authority.verify(self.__store)
        if not self._checkpoint_matches(checkpoint, approval):
            raise CurationRevisionError("CURATION_REVISION_APPROVAL_STALE")
        row, active = _active_snapshot(self.__store, proposal.item_id)
        if (
            str(row["knowledge_sha256"]) != proposal.knowledge_sha256
            or str(row["candidate_sha256"]) != proposal.candidate_sha256
            or str(row["level"]) != proposal.active_level
            or active.domain != proposal.domain
        ):
            raise CurationRevisionError("CURATION_REVISION_TARGET_CHANGED")
        if active.sensitivity == "secret":
            raise CurationRevisionError("CURATION_REVISION_SECRET_NOT_SUPPORTED")
        return proposal, row, active

    def _packet(
        self,
        proposal_set: CurationProposalSet,
        proposal: KnowledgeCurationProposal,
        approval: AuthenticatedCurationRevisionApproval,
        row: dict[str, Any],
        active: KnowledgeCandidate,
    ) -> CurationRevisionPacket:
        return CurationRevisionPacket(
            approval_id=approval.approval_id,
            approval_sha256=approval.sha256,
            proposal_id=proposal.proposal_id,
            proposal_sha256=approval.proposal_sha256,
            proposal_set_sha256=proposal_set.proposal_set_sha256,
            item_id=proposal.item_id,
            knowledge_sha256=proposal.knowledge_sha256,
            candidate_sha256=proposal.candidate_sha256,
            checkpoint_sequence=approval.expected_checkpoint_sequence,
            checkpoint_sha256=approval.expected_checkpoint_sha256,
            state_sha256=approval.expected_state_sha256,
            domain=active.domain,
            sensitivity=active.sensitivity,
            risk_level=active.risk_level,
            active_level=str(row["level"]),
            kind=active.kind,
            execution_mode=active.execution_mode,
            curation_action=proposal.curation_action,
            revision_metrics=self._metrics(proposal),
            current_title=active.title,
            current_content=active.content,
            current_scope=active.scope,
        ).validate()

    @staticmethod
    def _candidate_id(approval: AuthenticatedCurationRevisionApproval) -> str:
        return "candidate:" + _sha_payload(
            {
                "schema_version": "workspace-learning-curation-revision-candidate-identity/v1",
                "approval_id": approval.approval_id,
                "item_id": approval.item_id,
                "base_knowledge_sha256": approval.knowledge_sha256,
            }
        ).split(":", 1)[1]

    @classmethod
    def _candidate_from_result(
        cls,
        active: KnowledgeCandidate,
        approval: AuthenticatedCurationRevisionApproval,
        result: CurationRevisionResult,
    ) -> KnowledgeCandidate:
        if result.result != "REVISION_CANDIDATE":
            raise CurationRevisionError("CURATION_REVISION_RESULT_NOT_CANDIDATE")
        if (
            result.title.strip() == active.title.strip()
            and result.content.strip() == active.content.strip()
            and result.scope.strip() == active.scope.strip()
        ):
            raise CurationRevisionError("CURATION_REVISION_NO_CHANGE")
        if len(active.evidence_ref_ids) >= 32 or len(active.evidence_hashes) >= 32:
            raise CurationRevisionError("CURATION_REVISION_EVIDENCE_CAPACITY_EXCEEDED")
        approval_ref = "curation-approval:" + approval.approval_id.rsplit(":", 1)[1]
        if approval_ref in active.evidence_ref_ids:
            raise CurationRevisionError("CURATION_REVISION_APPROVAL_EVIDENCE_DUPLICATE")
        candidate = KnowledgeCandidate(
            candidate_id=cls._candidate_id(approval),
            domain=active.domain,
            kind=active.kind,
            title=result.title.strip(),
            content=result.content.strip(),
            scope=result.scope.strip(),
            sensitivity=active.sensitivity,
            risk_level=active.risk_level,
            ownership="learner_managed",
            action="patch",
            execution_mode=active.execution_mode,
            source_experience_ids=active.source_experience_ids,
            source_experience_hashes=active.source_experience_hashes,
            source_domains=active.source_domains,
            source_sensitivities=active.source_sensitivities,
            source_task_ids=active.source_task_ids,
            source_outcomes=active.source_outcomes,
            evidence_ref_ids=active.evidence_ref_ids + (approval_ref,),
            evidence_hashes=active.evidence_hashes + (approval.sha256,),
            target_item_id=approval.item_id,
            base_item_sha256=approval.knowledge_sha256,
            created_at=_now_z(),
        ).validate()
        reasons = AdaptiveLearningDomainValidator.validate(candidate)
        if reasons:
            raise CurationRevisionError(
                "CURATION_REVISION_DOMAIN_VALIDATION_BLOCKED:" + ",".join(reasons)
            )
        return candidate

    def revise_and_stage(
        self,
        *,
        proposal_set: CurationProposalSet,
        approval: AuthenticatedCurationRevisionApproval,
    ) -> CurationRevisionOutcome:
        proposal, row, active = self._bind(proposal_set, approval)
        packet = self._packet(proposal_set, proposal, approval, row, active)
        claimed = self.__receipt_store.claim(approval)
        result = self.__runner.run(packet)
        if result.result == "NO_REVISION_VALUE":
            self.__receipt_store.complete(
                approval,
                claimed,
                result="NO_REVISION_VALUE",
                reason_codes=("NO_REVISION_VALUE",),
            )
            return CurationRevisionOutcome(
                result="NO_REVISION_VALUE",
                approval_id=approval.approval_id,
                proposal_id=proposal.proposal_id,
            )
        try:
            candidate = self._candidate_from_result(active, approval, result)
        except CurationRevisionError as exc:
            self.__receipt_store.complete(
                approval,
                claimed,
                result="REJECTED",
                reason_codes=(exc.reason_code.split(":", 1)[0],),
            )
            raise
        with self.__authority.expect_curation_stage(
            sequence=approval.expected_checkpoint_sequence,
            checkpoint_sha256=approval.expected_checkpoint_sha256,
            state_sha256=approval.expected_state_sha256,
        ):
            self.__staging.stage(candidate)
        self.__receipt_store.complete(
            approval,
            claimed,
            result="STAGED",
            candidate_sha256=candidate.sha256,
        )
        return CurationRevisionOutcome(
            result="STAGED",
            approval_id=approval.approval_id,
            proposal_id=proposal.proposal_id,
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
        )
