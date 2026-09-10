"""Authenticated operator promotion boundary for WorkSpace adaptive learning.

This module does not add a learning mutation primitive. It binds an existing
WorkSpace session and explicit local reviewer authorization to the existing
checkpointed ``LearningOperatorGateway``. Public/OAuth identity remains
identity-only: authorization always comes from the local WorkSpace principal
and this local reviewer policy.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
from contextlib import contextmanager
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Iterable, Iterator

from .adaptive_learning_checkpoint import (
    LearningCheckpoint,
    LearningCheckpointAuthority,
    LearningCheckpointError,
    LearningOperatorGateway,
)
from .adaptive_learning_contract import DOMAINS, KnowledgeCandidate, LearningValidationReceipt
from .workspace_auth import USER_ID_RE, WorkspaceAuthStore

if TYPE_CHECKING:
    from .adaptive_learning_store import AdaptiveLearningStore

PROMOTION_RESULT_SCHEMA = "workspace-adaptive-learning-promotion-result/v1"
PROMOTION_LEVELS = {"approved", "enterprise"}
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")


class LearningPromotionAuthorizationError(PermissionError):
    """The authenticated principal is not authorized for this promotion."""


def _canonical_sha256(payload: object) -> str:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _actor_id(user_id: str) -> str:
    value = str(user_id or "").strip().lower()
    if not USER_ID_RE.fullmatch(value):
        raise LearningPromotionAuthorizationError("PROMOTION_PRINCIPAL_INVALID")
    return f"workspace-user:{value}"


def _target_level(value: str) -> str:
    level = str(value or "").strip().lower()
    if level not in PROMOTION_LEVELS:
        raise LearningPromotionAuthorizationError("PROMOTION_TARGET_LEVEL_FORBIDDEN")
    return level


def _state_sha256(value: str) -> str:
    digest = str(value or "").strip().lower()
    if not _SHA.fullmatch(digest):
        raise LearningPromotionAuthorizationError("PROMOTION_CHECKPOINT_STATE_INVALID")
    return digest


@dataclass(frozen=True)
class LearningReviewerGrant:
    """Trusted local authorization assigned to one stable WorkSpace user.

    ``allowed_levels`` grants the ability to conduct the promotion ceremony.
    ``reviewer_domains`` is separate: it is the explicit domain-review
    entitlement used for domains such as network/security. Neither is inferred
    from WorkSpace ``admin`` role, profile text, department or external IdP.
    """

    user_id: str
    allowed_levels: tuple[str, ...]
    reviewer_domains: tuple[str, ...] = ()

    def validate(self) -> "LearningReviewerGrant":
        user_id = str(self.user_id or "").strip().lower()
        if not USER_ID_RE.fullmatch(user_id):
            raise ValueError("PROMOTION_GRANT_USER_ID_INVALID")
        levels = tuple(str(value or "").strip().lower() for value in self.allowed_levels)
        if not levels or len(set(levels)) != len(levels) or any(
            value not in PROMOTION_LEVELS for value in levels
        ):
            raise ValueError("PROMOTION_GRANT_LEVELS_INVALID")
        domains = tuple(str(value or "").strip().lower() for value in self.reviewer_domains)
        if len(set(domains)) != len(domains) or any(value not in DOMAINS for value in domains):
            raise ValueError("PROMOTION_GRANT_DOMAINS_INVALID")
        return self

    @property
    def normalized_user_id(self) -> str:
        self.validate()
        return str(self.user_id).strip().lower()

    @property
    def normalized_levels(self) -> frozenset[str]:
        self.validate()
        return frozenset(str(value).strip().lower() for value in self.allowed_levels)

    @property
    def normalized_domains(self) -> frozenset[str]:
        self.validate()
        return frozenset(str(value).strip().lower() for value in self.reviewer_domains)


class LearningReviewerAuthorizationPolicy:
    """Immutable in-process reviewer authorization allowlist."""

    def __init__(self, grants: Iterable[LearningReviewerGrant]):
        by_user: dict[str, LearningReviewerGrant] = {}
        for grant in tuple(grants):
            grant.validate()
            user_id = grant.normalized_user_id
            if user_id in by_user:
                raise ValueError("PROMOTION_GRANT_DUPLICATE_USER")
            by_user[user_id] = grant
        self.__grants = by_user

    def grant_for(self, user_id: str) -> LearningReviewerGrant:
        value = str(user_id or "").strip().lower()
        grant = self.__grants.get(value)
        if grant is None:
            raise LearningPromotionAuthorizationError("PROMOTION_REVIEWER_NOT_AUTHORIZED")
        return grant


class PromotionBoundCheckpointAuthority(LearningCheckpointAuthority):
    """Phase 4E expected-state binding layered on the existing checkpoint authority.

    The base authority remains responsible for verification, locking, mutation
    delta checks, journal append and witness advancement. This subclass only
    places a one-shot expected checkpoint into thread-local ceremony state.
    ``_verify_store`` consumes and checks it while the base ``_mutate`` lock is
    already held, before the store operation executes.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.__promotion_expectation = threading.local()

    @contextmanager
    def expect_promotion(
        self,
        *,
        sequence: int,
        state_sha256: str,
    ) -> Iterator[None]:
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            raise LearningCheckpointError("PROMOTION_EXPECTED_SEQUENCE_INVALID")
        state = _state_sha256(state_sha256)
        if getattr(self.__promotion_expectation, "value", None) is not None:
            raise LearningCheckpointError("PROMOTION_EXPECTATION_ALREADY_ACTIVE")
        self.__promotion_expectation.value = (sequence, state)
        try:
            yield
        finally:
            self.__promotion_expectation.value = None

    def _mutate(self, store: "AdaptiveLearningStore", *, mutation_kind: str, **kwargs):
        expectation = getattr(self.__promotion_expectation, "value", None)
        if expectation is not None and mutation_kind != "promote":
            raise LearningCheckpointError("PROMOTION_EXPECTATION_MUTATION_KIND_MISMATCH")
        return super()._mutate(store, mutation_kind=mutation_kind, **kwargs)

    def _verify_store(self, store: "AdaptiveLearningStore") -> LearningCheckpoint:
        checkpoint = super()._verify_store(store)
        expectation = getattr(self.__promotion_expectation, "value", None)
        if expectation is None:
            return checkpoint
        # Consume only at the pre-mutation verification reached by base _mutate.
        self.__promotion_expectation.value = None
        expected_sequence, expected_state = expectation
        if checkpoint.sequence != expected_sequence:
            raise LearningCheckpointError("PROMOTION_EXPECTED_SEQUENCE_MISMATCH")
        if checkpoint.state_sha256 != expected_state:
            raise LearningCheckpointError("PROMOTION_EXPECTED_STATE_MISMATCH")
        return checkpoint


@dataclass(frozen=True)
class LearningPromotionCeremony:
    """Non-secret state binding prepared immediately before operator review.

    This object is not a bearer credential. Promotion still re-authenticates the
    WorkSpace session and re-authorizes the principal. The expected checkpoint
    fields make the ceremony one-shot with respect to learning-store state.
    """

    candidate_id: str
    candidate_sha256: str
    domain: str
    target_level: str
    actor_id: str
    expected_checkpoint_sequence: int
    expected_state_sha256: str

    def validate(self) -> "LearningPromotionCeremony":
        if not self.candidate_id or len(self.candidate_id) > 128:
            raise LearningPromotionAuthorizationError("PROMOTION_CANDIDATE_ID_INVALID")
        if not _SHA.fullmatch(str(self.candidate_sha256 or "").strip().lower()):
            raise LearningPromotionAuthorizationError("PROMOTION_CANDIDATE_SHA_INVALID")
        if self.domain not in DOMAINS:
            raise LearningPromotionAuthorizationError("PROMOTION_DOMAIN_INVALID")
        _target_level(self.target_level)
        if not str(self.actor_id or "").startswith("workspace-user:usr_"):
            raise LearningPromotionAuthorizationError("PROMOTION_PRINCIPAL_INVALID")
        if (
            not isinstance(self.expected_checkpoint_sequence, int)
            or isinstance(self.expected_checkpoint_sequence, bool)
            or self.expected_checkpoint_sequence < 1
        ):
            raise LearningPromotionAuthorizationError("PROMOTION_CHECKPOINT_SEQUENCE_INVALID")
        _state_sha256(self.expected_state_sha256)
        return self


class AuthenticatedLearningPromotionService:
    """Authenticate, authorize and bind one checkpointed learning promotion."""

    def __init__(
        self,
        auth: WorkspaceAuthStore,
        store: "AdaptiveLearningStore",
        authority: PromotionBoundCheckpointAuthority,
        reviewer_policy: LearningReviewerAuthorizationPolicy,
    ) -> None:
        self.__auth = auth
        self.__authority = authority
        self.__operator = LearningOperatorGateway(store, authority)
        self.__reviewer_policy = reviewer_policy

    def _principal(self, session_token: str, client_ip: str) -> tuple[dict, LearningReviewerGrant]:
        user = self.__auth.user_for_session(session_token, client_ip)
        if user is None:
            raise LearningPromotionAuthorizationError("PROMOTION_SESSION_INVALID")
        user_id = str(user.get("user_id") or "").strip().lower()
        actor = _actor_id(user_id)
        grant = self.__reviewer_policy.grant_for(user_id)
        # Deliberately do not infer authority from user["role"].
        if actor != f"workspace-user:{grant.normalized_user_id}":
            raise LearningPromotionAuthorizationError("PROMOTION_PRINCIPAL_GRANT_MISMATCH")
        return user, grant

    @staticmethod
    def _authorize_candidate(
        grant: LearningReviewerGrant,
        candidate: KnowledgeCandidate,
        target_level: str,
    ) -> None:
        if target_level not in grant.normalized_levels:
            raise LearningPromotionAuthorizationError("PROMOTION_LEVEL_NOT_AUTHORIZED")
        if candidate.domain in {"network", "security"} and candidate.domain not in grant.normalized_domains:
            raise LearningPromotionAuthorizationError("PROMOTION_DOMAIN_REVIEW_NOT_AUTHORIZED")

    def prepare(
        self,
        *,
        session_token: str,
        client_ip: str,
        candidate: KnowledgeCandidate,
        target_level: str,
    ) -> LearningPromotionCeremony:
        candidate.validate()
        level = _target_level(target_level)
        user, grant = self._principal(session_token, client_ip)
        self._authorize_candidate(grant, candidate, level)
        checkpoint = self.__operator.verify()
        return LearningPromotionCeremony(
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
            domain=candidate.domain,
            target_level=level,
            actor_id=_actor_id(str(user["user_id"])),
            expected_checkpoint_sequence=checkpoint.sequence,
            expected_state_sha256=checkpoint.state_sha256,
        ).validate()

    def promote(
        self,
        *,
        ceremony: LearningPromotionCeremony,
        session_token: str,
        client_ip: str,
        candidate: KnowledgeCandidate,
        receipt: LearningValidationReceipt,
    ) -> dict[str, object]:
        ceremony.validate()
        candidate.validate()
        receipt.validate()
        user, grant = self._principal(session_token, client_ip)
        actor = _actor_id(str(user["user_id"]))

        if actor != ceremony.actor_id:
            raise LearningPromotionAuthorizationError("PROMOTION_PRINCIPAL_CHANGED")
        if (
            candidate.candidate_id != ceremony.candidate_id
            or candidate.sha256 != ceremony.candidate_sha256
            or candidate.domain != ceremony.domain
        ):
            raise LearningPromotionAuthorizationError("PROMOTION_CANDIDATE_CHANGED")
        level = _target_level(ceremony.target_level)
        self._authorize_candidate(grant, candidate, level)
        if receipt.candidate_id != candidate.candidate_id or receipt.candidate_sha256 != candidate.sha256:
            raise LearningPromotionAuthorizationError("PROMOTION_RECEIPT_CANDIDATE_MISMATCH")

        # Reviewer identities in an incoming receipt are assertions, not authority.
        # They may only name the principal authenticated for this ceremony.
        if receipt.human_reviewer_id not in {None, actor}:
            raise LearningPromotionAuthorizationError("PROMOTION_HUMAN_REVIEWER_MISMATCH")
        if receipt.domain_reviewer_id not in {None, actor}:
            raise LearningPromotionAuthorizationError("PROMOTION_DOMAIN_REVIEWER_MISMATCH")
        if receipt.domain_reviewer_id is not None and candidate.domain not in grant.normalized_domains:
            raise LearningPromotionAuthorizationError("PROMOTION_DOMAIN_REVIEW_NOT_AUTHORIZED")

        bound_receipt = replace(
            receipt,
            human_reviewer_id=actor,
            domain_reviewer_id=(actor if candidate.domain in grant.normalized_domains else None),
        ).validate()
        receipt_sha256 = _canonical_sha256(bound_receipt.to_payload())

        # The expectation is checked and consumed by _verify_store while the
        # inherited checkpoint mutation lock is held and before store.promote.
        with self.__authority.expect_promotion(
            sequence=ceremony.expected_checkpoint_sequence,
            state_sha256=ceremony.expected_state_sha256,
        ):
            self.__operator.promote(
                candidate.candidate_id,
                target_level=level,
                receipt=bound_receipt,
                actor_id=actor,
                reason_code="AUTHENTICATED_PROMOTION_GATE_PASSED",
            )
        after = self.__operator.verify()
        return {
            "schema_version": PROMOTION_RESULT_SCHEMA,
            "status": "promoted",
            "candidate_id": candidate.candidate_id,
            "candidate_sha256": candidate.sha256,
            "target_level": level,
            "actor_id": actor,
            "validation_receipt_sha256": receipt_sha256,
            "checkpoint_sequence": after.sequence,
            "checkpoint_state_sha256": after.state_sha256,
        }
