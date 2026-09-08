"""Fail-closed publication of human-approved CandidateSkill proposals.

This module is deliberately a bridge, not a second skill subsystem. The adaptive
learning store remains the canonical approval/provenance source and
``ApprovedSkillLoader`` remains the canonical production loader. Materialization
only turns one already-approved create candidate into that loader's existing
``SKILL.md`` + reviewed-reference registry format.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .adaptive_learning_checkpoint import LearningCheckpointAuthority
from .adaptive_learning_contract import KnowledgeCandidate
from .adaptive_learning_store import AdaptiveLearningStore
from .candidate_skill import CandidateSkill, CandidateSkillSecurityReceipt
from .candidate_skill_review import CandidateSkillApprovalResult
from .skills import ApprovedSkillLoader, MAX_SKILL_REFERENCE_BYTES, SkillSecurityError

MATERIALIZATION_SCHEMA = "workspace-approved-skill-materialization/v1"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVIEW_ID = "approval-review"
_REVIEW_FILE = "approval-review.md"


class CandidateSkillMaterializationError(RuntimeError):
    """Publication is not safe to expose to the production skill loader."""

    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code)
        super().__init__(self.reason_code)


def _canonical_json(payload: Any) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _plain_sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _agent_ids(values: Iterable[str]) -> tuple[str, ...]:
    normalized = tuple(dict.fromkeys(str(value or "").strip() for value in values))
    if not normalized or any(not _ID_RE.fullmatch(value) for value in normalized):
        raise CandidateSkillMaterializationError("MATERIALIZATION_AGENT_IDS_INVALID")
    return normalized


def _review_document(
    *,
    approval: CandidateSkillApprovalResult,
    candidate: KnowledgeCandidate,
    skill: CandidateSkill,
    security_receipt: CandidateSkillSecurityReceipt,
) -> str:
    """Render immutable, model-safe provenance without copying raw evidence bytes."""

    lines = [
        "# Approved Skill Materialization Review",
        "",
        f"- Schema: {MATERIALIZATION_SCHEMA}",
        f"- Candidate ID: {candidate.candidate_id}",
        f"- Candidate SHA-256: {candidate.sha256}",
        f"- Skill name: {skill.proposed_skill_name}",
        f"- Skill SHA-256: {skill.proposed_skill_sha256}",
        f"- Candidate provenance SHA-256: {skill.provenance_sha256}",
        f"- Security receipt SHA-256: {security_receipt.sha256}",
        f"- Approval review fingerprint: {approval.review_fingerprint}",
        f"- Approval actor: {approval.actor_id}",
        f"- Approval checkpoint sequence: {approval.checkpoint_sequence}",
        f"- Approval checkpoint state SHA-256: {approval.checkpoint_state_sha256}",
        f"- Source experience count: {len(candidate.source_experience_ids)}",
        f"- Source task count: {len(candidate.source_task_ids)}",
        f"- Evidence reference count: {len(candidate.evidence_ref_ids)}",
        "- Raw evidence included: false",
        "- Runtime capability grants: none",
        "",
        "## Source experience hashes",
        "",
        *(f"- {value}" for value in candidate.source_experience_hashes),
        "",
        "## Evidence hashes",
        "",
        *(f"- {value}" for value in candidate.evidence_hashes),
        "",
    ]
    return "\n".join(lines)


@dataclass(frozen=True)
class CandidateSkillMaterializationResult:
    candidate_id: str
    candidate_sha256: str
    skill_name: str
    skill_sha256: str
    review_sha256: str
    agent_ids: tuple[str, ...]
    publication_state: str = "materialized"
    schema_version: str = MATERIALIZATION_SCHEMA

    def validate(self) -> "CandidateSkillMaterializationResult":
        if self.schema_version != MATERIALIZATION_SCHEMA or self.publication_state != "materialized":
            raise CandidateSkillMaterializationError("MATERIALIZATION_RESULT_STATE_INVALID")
        if not _ID_RE.fullmatch(self.candidate_id):
            raise CandidateSkillMaterializationError("MATERIALIZATION_RESULT_ID_INVALID")
        for value in (self.candidate_sha256, self.skill_sha256, self.review_sha256):
            if not _SHA_RE.fullmatch(value):
                raise CandidateSkillMaterializationError("MATERIALIZATION_RESULT_SHA_INVALID")
        _agent_ids(self.agent_ids)
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        payload = asdict(self)
        payload["agent_ids"] = list(self.agent_ids)
        return payload


class CandidateSkillMaterializer:
    """Publish one approved create candidate into the canonical local skill registry."""

    def __init__(
        self,
        store: AdaptiveLearningStore,
        authority: LearningCheckpointAuthority,
        approved_root: Path,
    ) -> None:
        self._store = store
        self._authority = authority
        self._root = Path(approved_root).resolve()
        self._project_root = self._root.parent
        self._registry_path = self._root / "registry.json"
        self._lock_path = self._project_root / ".candidate-skill-materialization.lock"

    def _approved_candidate(
        self, approval: CandidateSkillApprovalResult
    ) -> tuple[KnowledgeCandidate, CandidateSkill, CandidateSkillSecurityReceipt]:
        try:
            approval.validate()
        except ValueError as exc:
            raise CandidateSkillMaterializationError("MATERIALIZATION_APPROVAL_INVALID") from exc

        try:
            checkpoint = self._authority.verify(self._store)
            active = self._store.active(approval.candidate_id)
        except Exception as exc:
            raise CandidateSkillMaterializationError("MATERIALIZATION_STORE_AUTHORITY_INVALID") from exc

        if checkpoint.sequence < approval.checkpoint_sequence:
            raise CandidateSkillMaterializationError("MATERIALIZATION_APPROVAL_CHECKPOINT_AHEAD")
        if (
            checkpoint.sequence == approval.checkpoint_sequence
            and checkpoint.state_sha256 != approval.checkpoint_state_sha256
        ):
            raise CandidateSkillMaterializationError("MATERIALIZATION_APPROVAL_CHECKPOINT_MISMATCH")
        if active is None:
            raise CandidateSkillMaterializationError("MATERIALIZATION_CANDIDATE_NOT_ACTIVE")
        if str(active.get("level")) not in {"approved", "enterprise"}:
            raise CandidateSkillMaterializationError("MATERIALIZATION_CANDIDATE_NOT_APPROVED")
        if str(active.get("disposition")) != "active_snapshot":
            raise CandidateSkillMaterializationError("MATERIALIZATION_CANDIDATE_NOT_ACTIVE")
        if str(active.get("candidate_sha256")) != approval.candidate_sha256:
            raise CandidateSkillMaterializationError("MATERIALIZATION_CANDIDATE_SHA_MISMATCH")

        try:
            candidate = KnowledgeCandidate.from_payload(active["candidate"])
            skill = CandidateSkill.from_candidate(candidate)
            receipt = CandidateSkillSecurityReceipt.create(candidate)
        except (TypeError, ValueError, KeyError) as exc:
            raise CandidateSkillMaterializationError("MATERIALIZATION_CANDIDATE_INVALID") from exc

        if candidate.sha256 != approval.candidate_sha256:
            raise CandidateSkillMaterializationError("MATERIALIZATION_CANDIDATE_SHA_MISMATCH")

        activation = any(
            str(row.get("event_type")) == "activate"
            and str(row.get("candidate_id")) == approval.candidate_id
            and str(row.get("candidate_sha256")) == approval.candidate_sha256
            and str(row.get("actor_id")) == approval.actor_id
            for row in self._store.ledger()
        )
        if not activation:
            raise CandidateSkillMaterializationError("MATERIALIZATION_APPROVAL_LEDGER_BINDING_MISSING")
        return candidate, skill, receipt

    def _acquire_lock(self) -> int:
        self._project_root.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self._lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise CandidateSkillMaterializationError("MATERIALIZATION_LOCKED") from exc
        os.write(fd, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(fd)
        return fd

    def _release_lock(self, fd: int) -> None:
        try:
            os.close(fd)
        finally:
            try:
                self._lock_path.unlink()
            except FileNotFoundError:
                pass

    def _registry(self) -> tuple[dict[str, Any], bytes | None]:
        self._root.mkdir(parents=True, exist_ok=True)
        loader = ApprovedSkillLoader(self._root)
        try:
            loader.audit_registry()
        except Exception as exc:
            raise CandidateSkillMaterializationError("MATERIALIZATION_EXISTING_REGISTRY_INVALID") from exc

        if not self._registry_path.exists():
            return (
                {
                    "schema_version": 1,
                    "policy": "approved-local-instruction-only",
                    "skills": {},
                },
                None,
            )
        previous = self._registry_path.read_bytes()
        try:
            payload = json.loads(previous.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CandidateSkillMaterializationError("MATERIALIZATION_EXISTING_REGISTRY_INVALID") from exc
        return payload, previous

    def _write_registry_atomic(self, payload: dict[str, Any]) -> None:
        raw = _canonical_json(payload)
        fd, temp_name = tempfile.mkstemp(prefix=".registry.", suffix=".tmp", dir=self._root)
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self._registry_path)
        finally:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass

    def _restore_registry(self, previous: bytes | None) -> None:
        if previous is None:
            try:
                self._registry_path.unlink()
            except FileNotFoundError:
                pass
            return
        fd, temp_name = tempfile.mkstemp(prefix=".registry.restore.", suffix=".tmp", dir=self._root)
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(previous)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self._registry_path)
        finally:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass

    def materialize(
        self,
        approval: CandidateSkillApprovalResult,
        *,
        agent_ids: Iterable[str],
    ) -> CandidateSkillMaterializationResult:
        candidate, skill, receipt = self._approved_candidate(approval)
        agents = _agent_ids(agent_ids)
        document = CandidateSkill.render_proposed_document(candidate)
        skill_bytes = document.encode("utf-8")
        if "sha256:" + _plain_sha(skill_bytes) != skill.proposed_skill_sha256:
            raise CandidateSkillMaterializationError("MATERIALIZATION_SKILL_BINDING_MISMATCH")

        review_text = _review_document(
            approval=approval,
            candidate=candidate,
            skill=skill,
            security_receipt=receipt,
        )
        review_bytes = review_text.encode("utf-8")
        if not 1 <= len(review_bytes) <= MAX_SKILL_REFERENCE_BYTES:
            raise CandidateSkillMaterializationError("MATERIALIZATION_REVIEW_SIZE_INVALID")
        review_plain_sha = _plain_sha(review_bytes)
        review_sha = "sha256:" + review_plain_sha

        fd = self._acquire_lock()
        stage_dir: Path | None = None
        final_dir = self._root / skill.proposed_skill_name
        final_created = False
        registry_committed = False
        previous_registry: bytes | None = None
        try:
            registry, previous_registry = self._registry()
            skills = registry.get("skills")
            if not isinstance(skills, dict):
                raise CandidateSkillMaterializationError("MATERIALIZATION_EXISTING_REGISTRY_INVALID")
            if skill.proposed_skill_name in skills or final_dir.exists() or final_dir.is_symlink():
                raise CandidateSkillMaterializationError("MATERIALIZATION_SKILL_EXISTS")

            stage_dir = Path(
                tempfile.mkdtemp(prefix=f".{skill.proposed_skill_name}.", dir=self._root)
            )
            references_dir = stage_dir / "references"
            references_dir.mkdir()
            (stage_dir / "SKILL.md").write_bytes(skill_bytes)
            (references_dir / _REVIEW_FILE).write_bytes(review_bytes)

            review_relative = PurePosixPath(
                self._root.name,
                skill.proposed_skill_name,
                "references",
                _REVIEW_FILE,
            ).as_posix()
            skills[skill.proposed_skill_name] = {
                "enabled": True,
                "agent_ids": list(agents),
                "instruction_only": True,
                "network_access": False,
                "credential_access": False,
                "persistent_self_modify": False,
                "external_code_vendored": False,
                "sha256": skill.proposed_skill_sha256.split(":", 1)[1],
                "review": review_relative,
                "provenance": [
                    f"candidate:{candidate.candidate_id}:{candidate.sha256}",
                    f"candidate-provenance:{skill.provenance_sha256}",
                    f"approval-review:{approval.review_fingerprint}",
                ],
                "references": {
                    _REVIEW_ID: {
                        "path": f"references/{_REVIEW_FILE}",
                        "sha256": review_plain_sha,
                        "size_bytes": len(review_bytes),
                        "provenance": [
                            candidate.sha256,
                            skill.provenance_sha256,
                            approval.review_fingerprint,
                            receipt.sha256,
                        ],
                        "content_class": "reviewed-reference",
                    }
                },
                "enterprise_tier": "E2",
                "risk_class": skill.risk_level,
            }

            os.replace(stage_dir, final_dir)
            stage_dir = None
            final_created = True
            self._write_registry_atomic(registry)
            registry_committed = True

            loader = ApprovedSkillLoader(self._root)
            loaded = loader.load_for_agent(agents[0], (skill.proposed_skill_name,))
            if len(loaded) != 1:
                raise CandidateSkillMaterializationError("MATERIALIZATION_PRODUCTION_LOAD_FAILED")

            return CandidateSkillMaterializationResult(
                candidate_id=candidate.candidate_id,
                candidate_sha256=candidate.sha256,
                skill_name=skill.proposed_skill_name,
                skill_sha256=skill.proposed_skill_sha256,
                review_sha256=review_sha,
                agent_ids=agents,
            ).validate()
        except CandidateSkillMaterializationError:
            if registry_committed:
                self._restore_registry(previous_registry)
            if final_created:
                shutil.rmtree(final_dir, ignore_errors=True)
            raise
        except (OSError, SkillSecurityError, ValueError, TypeError, KeyError) as exc:
            if registry_committed:
                self._restore_registry(previous_registry)
            if final_created:
                shutil.rmtree(final_dir, ignore_errors=True)
            raise CandidateSkillMaterializationError("MATERIALIZATION_PUBLICATION_FAILED") from exc
        finally:
            if stage_dir is not None:
                shutil.rmtree(stage_dir, ignore_errors=True)
            self._release_lock(fd)
