"""Immutable production supersession for approved learned skill revisions.

Phase 4H through 4K already own effectiveness observation, curation, revision,
deterministic evaluation, authenticated activation, and operator rollback. This
module adds only the production mirror: an already-activated exact ``kind=skill``
patch can replace the enabled production version without overwriting historical
reviewed bytes, and an already-completed operator rollback can restore that exact
historical package by an atomic registry flip.

No selector, loader, promotion primitive, rollback authority, model call, network,
credential, shell, or execution capability is introduced here.
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
from typing import Any, Mapping

from .adaptive_learning_checkpoint import LearningCheckpointAuthority
from .adaptive_learning_contract import KnowledgeCandidate
from .adaptive_learning_revision_evaluation import RevisionEvaluationPackage, RevisionRollbackPlan
from .adaptive_learning_store import AdaptiveLearningStore
from .candidate_skill import (
    CandidateSkillError,
    _render_document,
    _slug,
    _validate_domain_policy,
    _validate_rendered_document,
)
from .skills import ApprovedSkillLoader, MAX_SKILL_REFERENCE_BYTES, SkillSecurityError

SUPERSESSION_SCHEMA = "workspace-approved-skill-supersession/v1"
RESTORATION_SCHEMA = "workspace-approved-skill-production-restoration/v1"
PROMOTION_RESULT_SCHEMA = "workspace-adaptive-learning-promotion-result/v1"
_REVIEW_FILE = "approval-review.md"
_REVIEW_ID = "approval-review"
_LOCK_FILE = ".candidate-skill-materialization.lock"
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_PLAIN_SHA = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PROMOTION_FIELDS = {
    "schema_version",
    "status",
    "candidate_id",
    "candidate_sha256",
    "target_level",
    "actor_id",
    "validation_receipt_sha256",
    "checkpoint_sequence",
    "checkpoint_state_sha256",
}
_AUTHORITY_FLAGS = (
    "instruction_only",
    "network_access",
    "credential_access",
    "persistent_self_modify",
    "external_code_vendored",
)


class CandidateSkillSupersessionError(ValueError):
    """Production supersession/restoration cannot be proven safe and exact."""

    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code)
        super().__init__(self.reason_code)


def _canonical(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _plain_sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha(raw: bytes) -> str:
    return "sha256:" + _plain_sha(raw)


def _require_sha(value: Any, code: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA.fullmatch(text):
        raise CandidateSkillSupersessionError(code)
    return text


def _require_id(value: Any, code: str) -> str:
    text = str(value or "").strip()
    if not _ID.fullmatch(text):
        raise CandidateSkillSupersessionError(code)
    return text


def _agent_ids(entry: Mapping[str, Any]) -> tuple[str, ...]:
    raw = entry.get("agent_ids")
    if not isinstance(raw, list) or not raw:
        raise CandidateSkillSupersessionError("SUPERSESSION_BASE_AGENT_SCOPE_INVALID")
    values = tuple(str(value or "").strip() for value in raw)
    if any(not value or len(value) > 128 for value in values) or len(set(values)) != len(values):
        raise CandidateSkillSupersessionError("SUPERSESSION_BASE_AGENT_SCOPE_INVALID")
    return values


def _promotion(payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping) or set(payload) != _PROMOTION_FIELDS:
        raise CandidateSkillSupersessionError("SUPERSESSION_PROMOTION_RESULT_INVALID")
    data = dict(payload)
    if data.get("schema_version") != PROMOTION_RESULT_SCHEMA or data.get("status") != "promoted":
        raise CandidateSkillSupersessionError("SUPERSESSION_PROMOTION_RESULT_INVALID")
    if str(data.get("target_level") or "") not in {"approved", "enterprise"}:
        raise CandidateSkillSupersessionError("SUPERSESSION_PROMOTION_LEVEL_INVALID")
    _require_id(data.get("candidate_id"), "SUPERSESSION_PROMOTION_CANDIDATE_INVALID")
    _require_sha(data.get("candidate_sha256"), "SUPERSESSION_PROMOTION_CANDIDATE_SHA_INVALID")
    _require_sha(
        data.get("validation_receipt_sha256"),
        "SUPERSESSION_PROMOTION_RECEIPT_SHA_INVALID",
    )
    _require_sha(
        data.get("checkpoint_state_sha256"),
        "SUPERSESSION_PROMOTION_CHECKPOINT_STATE_INVALID",
    )
    actor = str(data.get("actor_id") or "").strip()
    if not actor.startswith("workspace-user:usr_") or len(actor) > 160:
        raise CandidateSkillSupersessionError("SUPERSESSION_PROMOTION_ACTOR_INVALID")
    sequence = data.get("checkpoint_sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise CandidateSkillSupersessionError("SUPERSESSION_PROMOTION_CHECKPOINT_INVALID")
    return data


def _revision_document(candidate: KnowledgeCandidate) -> tuple[str, bytes, str]:
    """Reuse canonical production rendering without widening create-only CandidateSkill."""

    candidate.validate()
    if candidate.kind != "skill" or candidate.action not in {"patch", "supersede"}:
        raise CandidateSkillSupersessionError("SUPERSESSION_SKILL_PATCH_REQUIRED")
    try:
        _validate_domain_policy(candidate)
        name = _slug(candidate.title, suffix=candidate.sha256.split(":", 1)[1])
        document = _render_document(
            name=name,
            title=candidate.title,
            scope=candidate.scope,
            content=candidate.content,
        )
        raw, digest = _validate_rendered_document(name, document)
    except CandidateSkillError as exc:
        raise CandidateSkillSupersessionError(exc.reason_code) from exc
    return name, raw, digest


def _review_document(
    *,
    package: RevisionEvaluationPackage,
    candidate: KnowledgeCandidate,
    promotion: Mapping[str, Any],
    base_skill_name: str,
    revised_skill_name: str,
) -> str:
    """Render metadata-only reviewed provenance; never copy raw evidence bytes."""

    return (
        "# Approved Learned Skill Revision Review\n\n"
        f"Item: `{package.item_id}`\n\n"
        f"Base production skill: `{base_skill_name}`\n\n"
        f"Revised production skill: `{revised_skill_name}`\n\n"
        f"Base candidate: `{package.base_candidate_id}`\n\n"
        f"Base candidate SHA-256: `{package.base_candidate_sha256}`\n\n"
        f"Base knowledge SHA-256: `{package.base_knowledge_sha256}`\n\n"
        f"Revised candidate: `{candidate.candidate_id}`\n\n"
        f"Revised candidate SHA-256: `{candidate.sha256}`\n\n"
        f"Revised knowledge SHA-256: `{package.candidate_knowledge_sha256}`\n\n"
        f"Revision evaluation SHA-256: `{package.evaluation_sha256}`\n\n"
        f"Curation approval: `{package.curation_approval_id}`\n\n"
        f"Curation approval SHA-256: `{package.curation_approval_sha256}`\n\n"
        f"Promotion actor: `{promotion['actor_id']}`\n\n"
        f"Promotion level: `{promotion['target_level']}`\n\n"
        f"Promotion validation receipt SHA-256: `{promotion['validation_receipt_sha256']}`\n\n"
        f"Promotion checkpoint sequence: `{promotion['checkpoint_sequence']}`\n\n"
        f"Promotion checkpoint state SHA-256: `{promotion['checkpoint_state_sha256']}`\n\n"
        "Authority: instruction-only reviewed knowledge. No capability grants.\n"
    )


@dataclass(frozen=True)
class CandidateSkillSupersessionResult:
    item_id: str
    base_skill_name: str
    revised_skill_name: str
    base_knowledge_sha256: str
    revised_knowledge_sha256: str
    revised_candidate_sha256: str
    revised_skill_sha256: str
    review_sha256: str
    checkpoint_sequence: int
    schema_version: str = SUPERSESSION_SCHEMA

    def validate(self) -> "CandidateSkillSupersessionResult":
        if self.schema_version != SUPERSESSION_SCHEMA:
            raise CandidateSkillSupersessionError("SUPERSESSION_RESULT_SCHEMA_INVALID")
        _require_id(self.item_id, "SUPERSESSION_RESULT_ITEM_INVALID")
        for value in (
            self.base_knowledge_sha256,
            self.revised_knowledge_sha256,
            self.revised_candidate_sha256,
            self.revised_skill_sha256,
            self.review_sha256,
        ):
            _require_sha(value, "SUPERSESSION_RESULT_SHA_INVALID")
        if not self.base_skill_name or not self.revised_skill_name:
            raise CandidateSkillSupersessionError("SUPERSESSION_RESULT_SKILL_NAME_INVALID")
        if self.base_skill_name == self.revised_skill_name:
            raise CandidateSkillSupersessionError("SUPERSESSION_RESULT_NAME_COLLISION")
        if not isinstance(self.checkpoint_sequence, int) or self.checkpoint_sequence < 1:
            raise CandidateSkillSupersessionError("SUPERSESSION_RESULT_CHECKPOINT_INVALID")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class CandidateSkillProductionRestorationResult:
    item_id: str
    restored_skill_name: str
    disabled_skill_name: str
    restored_knowledge_sha256: str
    disabled_knowledge_sha256: str
    checkpoint_sequence: int
    schema_version: str = RESTORATION_SCHEMA

    def validate(self) -> "CandidateSkillProductionRestorationResult":
        if self.schema_version != RESTORATION_SCHEMA:
            raise CandidateSkillSupersessionError("RESTORATION_RESULT_SCHEMA_INVALID")
        _require_id(self.item_id, "RESTORATION_RESULT_ITEM_INVALID")
        _require_sha(self.restored_knowledge_sha256, "RESTORATION_RESULT_SHA_INVALID")
        _require_sha(self.disabled_knowledge_sha256, "RESTORATION_RESULT_SHA_INVALID")
        if not self.restored_skill_name or not self.disabled_skill_name:
            raise CandidateSkillSupersessionError("RESTORATION_RESULT_SKILL_NAME_INVALID")
        if self.restored_skill_name == self.disabled_skill_name:
            raise CandidateSkillSupersessionError("RESTORATION_RESULT_NAME_COLLISION")
        if not isinstance(self.checkpoint_sequence, int) or self.checkpoint_sequence < 1:
            raise CandidateSkillSupersessionError("RESTORATION_RESULT_CHECKPOINT_INVALID")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


class CandidateSkillSupersessionManager:
    """Mirror already-authorized learning transitions into immutable production versions."""

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
        self._lock_path = self._project_root / _LOCK_FILE
        self._authority.verify(self._store)

    def _acquire_lock(self) -> int:
        self._project_root.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self._lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise CandidateSkillSupersessionError("SUPERSESSION_PRODUCTION_LOCKED") from exc
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

    def _registry(self) -> tuple[dict[str, Any], bytes]:
        loader = ApprovedSkillLoader(self._root)
        try:
            loader.audit_registry()
        except Exception as exc:
            raise CandidateSkillSupersessionError("SUPERSESSION_EXISTING_REGISTRY_INVALID") from exc
        if not self._registry_path.is_file():
            raise CandidateSkillSupersessionError("SUPERSESSION_REGISTRY_REQUIRED")
        previous = self._registry_path.read_bytes()
        try:
            payload = json.loads(previous.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CandidateSkillSupersessionError("SUPERSESSION_EXISTING_REGISTRY_INVALID") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("skills"), dict):
            raise CandidateSkillSupersessionError("SUPERSESSION_EXISTING_REGISTRY_INVALID")
        return payload, previous

    def _write_registry_atomic(self, payload: Mapping[str, Any]) -> None:
        self._root.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=".registry.", suffix=".tmp", dir=self._root)
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(_canonical(dict(payload)))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self._registry_path)
        finally:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass

    def _restore_registry(self, previous: bytes) -> None:
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

    @staticmethod
    def _matching_skill(
        skills: Mapping[str, Any],
        token: str,
        *,
        enabled: bool | None,
        code: str,
    ) -> tuple[str, dict[str, Any]]:
        matches: list[tuple[str, dict[str, Any]]] = []
        for name, raw in sorted(skills.items()):
            if not isinstance(raw, dict):
                continue
            if enabled is not None and raw.get("enabled") is not enabled:
                continue
            provenance = raw.get("provenance")
            if isinstance(provenance, list) and token in provenance:
                matches.append((name, raw))
        if len(matches) != 1:
            raise CandidateSkillSupersessionError(code)
        return matches[0]

    def _current_active_revision(
        self,
        package: RevisionEvaluationPackage,
        promotion: Mapping[str, Any],
    ) -> tuple[Any, KnowledgeCandidate]:
        package.validate()
        if package.result != "PASS" or package.kind != "skill":
            raise CandidateSkillSupersessionError("SUPERSESSION_PHASE4K_SKILL_PASS_REQUIRED")
        if str(promotion["candidate_id"]) != package.candidate_id:
            raise CandidateSkillSupersessionError("SUPERSESSION_PROMOTION_CANDIDATE_MISMATCH")
        if str(promotion["candidate_sha256"]) != package.candidate_sha256:
            raise CandidateSkillSupersessionError("SUPERSESSION_PROMOTION_CANDIDATE_MISMATCH")

        checkpoint = self._authority.verify(self._store)
        if (
            checkpoint.sequence != int(promotion["checkpoint_sequence"])
            or checkpoint.state_sha256 != str(promotion["checkpoint_state_sha256"])
        ):
            raise CandidateSkillSupersessionError("SUPERSESSION_PROMOTION_CHECKPOINT_STALE")
        active = self._store.active(package.item_id)
        if active is None:
            raise CandidateSkillSupersessionError("SUPERSESSION_REVISION_NOT_ACTIVE")
        if (
            str(active.get("knowledge_sha256") or "") != package.candidate_knowledge_sha256
            or str(active.get("candidate_sha256") or "") != package.candidate_sha256
            or str(active.get("level") or "") != str(promotion["target_level"])
        ):
            raise CandidateSkillSupersessionError("SUPERSESSION_ACTIVE_REVISION_MISMATCH")
        try:
            candidate = KnowledgeCandidate.from_payload(active["candidate"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CandidateSkillSupersessionError("SUPERSESSION_ACTIVE_CANDIDATE_INVALID") from exc
        if (
            candidate.candidate_id != package.candidate_id
            or candidate.sha256 != package.candidate_sha256
            or candidate.kind != "skill"
            or candidate.action not in {"patch", "supersede"}
            or candidate.target_item_id != package.item_id
            or candidate.base_item_sha256 != package.base_knowledge_sha256
        ):
            raise CandidateSkillSupersessionError("SUPERSESSION_ACTIVE_CANDIDATE_BINDING_INVALID")

        events = [
            row
            for row in self._store.ledger()
            if str(row.get("item_id")) == package.item_id
            and str(row.get("event_type")) in {"activate", "enterprise"}
        ]
        if not events:
            raise CandidateSkillSupersessionError("SUPERSESSION_ACTIVATION_LEDGER_MISSING")
        event = events[-1]
        if (
            str(event.get("candidate_id") or "") != package.candidate_id
            or str(event.get("candidate_sha256") or "") != package.candidate_sha256
            or str(event.get("before_sha256") or "") != package.base_knowledge_sha256
            or str(event.get("after_sha256") or "") != package.candidate_knowledge_sha256
            or str(event.get("actor_id") or "") != str(promotion["actor_id"])
        ):
            raise CandidateSkillSupersessionError("SUPERSESSION_ACTIVATION_LEDGER_MISMATCH")
        return checkpoint, candidate

    @staticmethod
    def _authority_entry(base: Mapping[str, Any]) -> dict[str, Any]:
        entry: dict[str, Any] = {}
        for field in _AUTHORITY_FLAGS:
            if field not in base:
                raise CandidateSkillSupersessionError("SUPERSESSION_BASE_AUTHORITY_INVALID")
            entry[field] = base[field]
        if entry["instruction_only"] is not True or any(
            entry[field] is not False for field in _AUTHORITY_FLAGS if field != "instruction_only"
        ):
            raise CandidateSkillSupersessionError("SUPERSESSION_BASE_AUTHORITY_INVALID")
        entry["agent_ids"] = list(_agent_ids(base))
        if "enterprise_tier" in base:
            entry["enterprise_tier"] = base["enterprise_tier"]
        return entry

    def supersede(
        self,
        *,
        package: RevisionEvaluationPackage,
        promotion_result: Mapping[str, Any],
    ) -> CandidateSkillSupersessionResult:
        promotion = _promotion(promotion_result)
        checkpoint, candidate = self._current_active_revision(package, promotion)
        revised_name, skill_bytes, skill_sha = _revision_document(candidate)

        fd = self._acquire_lock()
        stage_dir: Path | None = None
        final_dir = self._root / revised_name
        final_created = False
        registry_committed = False
        previous_registry: bytes | None = None
        try:
            registry, previous_registry = self._registry()
            skills = registry["skills"]
            base_token = f"candidate:{package.base_candidate_id}:{package.base_candidate_sha256}"
            base_name, base_entry = self._matching_skill(
                skills,
                base_token,
                enabled=True,
                code="SUPERSESSION_BASE_PRODUCTION_NOT_EXACT",
            )
            if revised_name == base_name or revised_name in skills or final_dir.exists() or final_dir.is_symlink():
                raise CandidateSkillSupersessionError("SUPERSESSION_REVISED_SKILL_EXISTS")

            authority_entry = self._authority_entry(base_entry)
            review_text = _review_document(
                package=package,
                candidate=candidate,
                promotion=promotion,
                base_skill_name=base_name,
                revised_skill_name=revised_name,
            )
            review_bytes = review_text.encode("utf-8")
            if not 1 <= len(review_bytes) <= MAX_SKILL_REFERENCE_BYTES:
                raise CandidateSkillSupersessionError("SUPERSESSION_REVIEW_SIZE_INVALID")
            review_plain_sha = _plain_sha(review_bytes)
            review_sha = "sha256:" + review_plain_sha

            stage_dir = Path(tempfile.mkdtemp(prefix=f".{revised_name}.", dir=self._root))
            references = stage_dir / "references"
            references.mkdir()
            (stage_dir / "SKILL.md").write_bytes(skill_bytes)
            (references / _REVIEW_FILE).write_bytes(review_bytes)

            base_provenance = base_entry.get("provenance")
            if not isinstance(base_provenance, list) or not base_provenance:
                raise CandidateSkillSupersessionError("SUPERSESSION_BASE_PROVENANCE_INVALID")
            base_item_token = f"learning-item:{package.item_id}:{package.base_knowledge_sha256}"
            if base_item_token not in base_provenance:
                base_provenance.append(base_item_token)
            base_entry["enabled"] = False

            review_relative = PurePosixPath(
                self._root.name,
                revised_name,
                "references",
                _REVIEW_FILE,
            ).as_posix()
            revised_entry = {
                **authority_entry,
                "enabled": True,
                "sha256": skill_sha.split(":", 1)[1],
                "review": review_relative,
                "provenance": [
                    f"candidate:{candidate.candidate_id}:{candidate.sha256}",
                    f"learning-item:{package.item_id}:{package.candidate_knowledge_sha256}",
                    f"supersedes-candidate:{package.base_candidate_id}:{package.base_candidate_sha256}",
                    f"supersedes-knowledge:{package.base_knowledge_sha256}",
                    f"revision-evaluation:{package.evaluation_sha256}",
                    f"curation-approval:{package.curation_approval_id}:{package.curation_approval_sha256}",
                ],
                "references": {
                    _REVIEW_ID: {
                        "path": f"references/{_REVIEW_FILE}",
                        "sha256": review_plain_sha,
                        "size_bytes": len(review_bytes),
                        "provenance": [
                            candidate.sha256,
                            package.candidate_knowledge_sha256,
                            package.evaluation_sha256,
                            package.curation_approval_sha256,
                            str(promotion["validation_receipt_sha256"]),
                        ],
                        "content_class": "reviewed-reference",
                    }
                },
                "risk_class": candidate.risk_level,
            }
            skills[revised_name] = revised_entry

            os.replace(stage_dir, final_dir)
            stage_dir = None
            final_created = True
            self._write_registry_atomic(registry)
            registry_committed = True

            loader = ApprovedSkillLoader(self._root)
            loader.audit_registry()
            loaded = loader.load_for_agent(authority_entry["agent_ids"][0], (revised_name,))
            if len(loaded) != 1:
                raise CandidateSkillSupersessionError("SUPERSESSION_PRODUCTION_LOAD_FAILED")

            return CandidateSkillSupersessionResult(
                item_id=package.item_id,
                base_skill_name=base_name,
                revised_skill_name=revised_name,
                base_knowledge_sha256=package.base_knowledge_sha256,
                revised_knowledge_sha256=package.candidate_knowledge_sha256,
                revised_candidate_sha256=candidate.sha256,
                revised_skill_sha256=skill_sha,
                review_sha256=review_sha,
                checkpoint_sequence=checkpoint.sequence,
            ).validate()
        except CandidateSkillSupersessionError:
            if registry_committed and previous_registry is not None:
                self._restore_registry(previous_registry)
            if final_created:
                shutil.rmtree(final_dir, ignore_errors=True)
            raise
        except (OSError, SkillSecurityError, ValueError, TypeError, KeyError) as exc:
            if registry_committed and previous_registry is not None:
                self._restore_registry(previous_registry)
            if final_created:
                shutil.rmtree(final_dir, ignore_errors=True)
            raise CandidateSkillSupersessionError("SUPERSESSION_PUBLICATION_FAILED") from exc
        finally:
            if stage_dir is not None:
                shutil.rmtree(stage_dir, ignore_errors=True)
            self._release_lock(fd)

    def restore_after_operator_rollback(
        self,
        plan: RevisionRollbackPlan,
    ) -> CandidateSkillProductionRestorationResult:
        plan.validate()
        checkpoint = self._authority.verify(self._store)
        active = self._store.active(plan.item_id)
        if active is None or str(active.get("knowledge_sha256") or "") != plan.target_knowledge_sha256:
            raise CandidateSkillSupersessionError("RESTORATION_LEARNING_ROLLBACK_REQUIRED")

        events = [row for row in self._store.ledger() if str(row.get("item_id")) == plan.item_id]
        if not events:
            raise CandidateSkillSupersessionError("RESTORATION_ROLLBACK_LEDGER_MISSING")
        event = events[-1]
        if (
            str(event.get("event_type") or "") != "rollback"
            or str(event.get("before_sha256") or "") != plan.expected_current_sha256
            or str(event.get("after_sha256") or "") != plan.target_knowledge_sha256
        ):
            raise CandidateSkillSupersessionError("RESTORATION_ROLLBACK_LEDGER_MISMATCH")

        fd = self._acquire_lock()
        registry_committed = False
        previous_registry: bytes | None = None
        try:
            registry, previous_registry = self._registry()
            skills = registry["skills"]
            target_token = f"learning-item:{plan.item_id}:{plan.target_knowledge_sha256}"
            current_token = f"learning-item:{plan.item_id}:{plan.expected_current_sha256}"
            target_name, target_entry = self._matching_skill(
                skills,
                target_token,
                enabled=False,
                code="RESTORATION_TARGET_PRODUCTION_NOT_EXACT",
            )
            current_name, current_entry = self._matching_skill(
                skills,
                current_token,
                enabled=True,
                code="RESTORATION_CURRENT_PRODUCTION_NOT_EXACT",
            )
            if target_name == current_name:
                raise CandidateSkillSupersessionError("RESTORATION_PRODUCTION_IDENTITY_COLLISION")
            if _agent_ids(target_entry) != _agent_ids(current_entry):
                raise CandidateSkillSupersessionError("RESTORATION_AGENT_SCOPE_CHANGED")
            for field in _AUTHORITY_FLAGS:
                if target_entry.get(field) != current_entry.get(field):
                    raise CandidateSkillSupersessionError("RESTORATION_AUTHORITY_POLICY_CHANGED")

            # Disabled packages are not fully checked by audit_registry; validate
            # exact historical bytes before making this version runtime-visible.
            loader = ApprovedSkillLoader(self._root)
            loader._validate_skill(target_name, target_entry)

            target_entry["enabled"] = True
            current_entry["enabled"] = False
            self._write_registry_atomic(registry)
            registry_committed = True

            loader = ApprovedSkillLoader(self._root)
            loader.audit_registry()
            loaded = loader.load_for_agent(_agent_ids(target_entry)[0], (target_name,))
            if len(loaded) != 1:
                raise CandidateSkillSupersessionError("RESTORATION_PRODUCTION_LOAD_FAILED")

            return CandidateSkillProductionRestorationResult(
                item_id=plan.item_id,
                restored_skill_name=target_name,
                disabled_skill_name=current_name,
                restored_knowledge_sha256=plan.target_knowledge_sha256,
                disabled_knowledge_sha256=plan.expected_current_sha256,
                checkpoint_sequence=checkpoint.sequence,
            ).validate()
        except CandidateSkillSupersessionError:
            if registry_committed and previous_registry is not None:
                self._restore_registry(previous_registry)
            raise
        except (OSError, SkillSecurityError, ValueError, TypeError, KeyError) as exc:
            if registry_committed and previous_registry is not None:
                self._restore_registry(previous_registry)
            raise CandidateSkillSupersessionError("RESTORATION_PUBLICATION_FAILED") from exc
        finally:
            self._release_lock(fd)
