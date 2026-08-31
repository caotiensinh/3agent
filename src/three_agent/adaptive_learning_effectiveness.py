"""Deterministic observational feedback for reused adaptive knowledge.

Phase 4H measures authoritative task outcomes observed after exact approved
knowledge versions were made available to a task. It deliberately does not claim
causality and exposes no promotion, archive, rollback, remediation, model, network,
or execution authority.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .adaptive_learning_contract import DOMAINS, SENSITIVITIES
from .adaptive_learning_retrieval import LearningContext
from .models import TaskStatus
from .store import TaskStore
from .validator_ledger import TaskVerificationState, ValidatorLedger

REUSE_RECEIPT_SCHEMA = "workspace-learning-reuse-receipt/v1"
EFFECTIVENESS_SNAPSHOT_SCHEMA = "workspace-learning-effectiveness/v1"
REUSE_ACTIVITY_AGENT = "learning_effectiveness"
REUSE_ACTIVITY_ACTION = "learning_reuse_observed"
INTERPRETATION = "observational_non_causal"

OUTCOME_VERIFIED_SUCCESS = "VERIFIED_SUCCESS_OBSERVED_AFTER_REUSE"
OUTCOME_FAILED = "FAILED_OBSERVED_AFTER_REUSE"
OUTCOME_WAITING_HUMAN = "WAITING_HUMAN_OBSERVED_AFTER_REUSE"
OUTCOME_PENDING = "PENDING_OBSERVED_AFTER_REUSE"
OUTCOME_DONE_UNVERIFIED = "DONE_UNVERIFIED_OBSERVED_AFTER_REUSE"

SIGNAL_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"
SIGNAL_SUPPORT = "SUPPORT_OBSERVED"
SIGNAL_REVIEW = "REVIEW_RECOMMENDED"
SIGNAL_DOMAIN_REVIEW = "DOMAIN_REVIEW_RECOMMENDED"

_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_RECEIPT_ID = re.compile(r"^reuse:[0-9a-f]{64}$")
_MAX_ITEMS = 8


class LearningEffectivenessError(ValueError):
    """Reuse telemetry or authoritative outcome state cannot be trusted safely."""


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha_payload(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _require_identifier(value: Any, *, field: str, limit: int = 128) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit or any(ch in text for ch in "\r\n\x00"):
        raise LearningEffectivenessError(f"invalid {field}")
    return text


@dataclass(frozen=True, order=True)
class LearningReuseItemRef:
    item_id: str
    knowledge_sha256: str

    def validate(self) -> "LearningReuseItemRef":
        _require_identifier(self.item_id, field="item_id")
        if not _SHA.fullmatch(self.knowledge_sha256):
            raise LearningEffectivenessError("invalid knowledge_sha256")
        return self

    def to_payload(self) -> dict[str, str]:
        self.validate()
        return {
            "item_id": self.item_id,
            "knowledge_sha256": self.knowledge_sha256,
        }


@dataclass(frozen=True)
class LearningReuseReceipt:
    receipt_id: str
    task_id: str
    query_sha256: str
    domain: str
    task_sensitivity: str
    items: tuple[LearningReuseItemRef, ...]
    schema_version: str = REUSE_RECEIPT_SCHEMA

    @classmethod
    def create(cls, task_id: str, context: LearningContext) -> "LearningReuseReceipt":
        if not isinstance(context, LearningContext):
            raise LearningEffectivenessError("LearningContext required")
        context.validate()
        stable_task_id = _require_identifier(task_id, field="task_id")
        items = tuple(
            sorted(
                {
                    LearningReuseItemRef(item.item_id, item.knowledge_sha256).validate()
                    for item in context.items
                }
            )
        )
        if not items or len(items) > _MAX_ITEMS:
            raise LearningEffectivenessError("reuse receipt requires 1..8 exact knowledge items")
        base = {
            "schema_version": REUSE_RECEIPT_SCHEMA,
            "task_id": stable_task_id,
            "query_sha256": context.query_sha256,
            "domain": context.domain,
            "task_sensitivity": context.task_sensitivity,
            "items": [item.to_payload() for item in items],
        }
        receipt_id = "reuse:" + hashlib.sha256(_canonical(base).encode("utf-8")).hexdigest()
        return cls(
            receipt_id=receipt_id,
            task_id=stable_task_id,
            query_sha256=context.query_sha256,
            domain=context.domain,
            task_sensitivity=context.task_sensitivity,
            items=items,
        ).validate()

    def _base_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "query_sha256": self.query_sha256,
            "domain": self.domain,
            "task_sensitivity": self.task_sensitivity,
            "items": [item.to_payload() for item in self.items],
        }

    def validate(self) -> "LearningReuseReceipt":
        if self.schema_version != REUSE_RECEIPT_SCHEMA:
            raise LearningEffectivenessError("reuse receipt schema mismatch")
        _require_identifier(self.task_id, field="task_id")
        if not _SHA.fullmatch(self.query_sha256):
            raise LearningEffectivenessError("invalid query_sha256")
        if self.domain not in DOMAINS:
            raise LearningEffectivenessError("invalid reuse domain")
        if self.task_sensitivity not in SENSITIVITIES:
            raise LearningEffectivenessError("invalid reuse sensitivity")
        if not self.items or len(self.items) > _MAX_ITEMS:
            raise LearningEffectivenessError("invalid reuse item count")
        if tuple(sorted(set(self.items))) != self.items:
            raise LearningEffectivenessError("reuse items must be unique and sorted")
        for item in self.items:
            item.validate()
        expected = "reuse:" + hashlib.sha256(
            _canonical(self._base_payload()).encode("utf-8")
        ).hexdigest()
        if not _RECEIPT_ID.fullmatch(self.receipt_id) or self.receipt_id != expected:
            raise LearningEffectivenessError("reuse receipt identity mismatch")
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return {"receipt_id": self.receipt_id, **self._base_payload()}

    def to_json(self) -> str:
        return _canonical(self.to_payload())

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "LearningReuseReceipt":
        if not isinstance(payload, Mapping):
            raise LearningEffectivenessError("reuse receipt object required")
        expected_fields = {
            "receipt_id",
            "schema_version",
            "task_id",
            "query_sha256",
            "domain",
            "task_sensitivity",
            "items",
        }
        if set(payload) != expected_fields:
            raise LearningEffectivenessError("reuse receipt fields mismatch")
        raw_items = payload.get("items")
        if not isinstance(raw_items, list):
            raise LearningEffectivenessError("reuse items array required")
        items: list[LearningReuseItemRef] = []
        for raw in raw_items:
            if not isinstance(raw, Mapping) or set(raw) != {"item_id", "knowledge_sha256"}:
                raise LearningEffectivenessError("reuse item fields mismatch")
            items.append(
                LearningReuseItemRef(
                    item_id=str(raw.get("item_id") or ""),
                    knowledge_sha256=str(raw.get("knowledge_sha256") or ""),
                ).validate()
            )
        return cls(
            receipt_id=str(payload.get("receipt_id") or ""),
            task_id=str(payload.get("task_id") or ""),
            query_sha256=str(payload.get("query_sha256") or ""),
            domain=str(payload.get("domain") or ""),
            task_sensitivity=str(payload.get("task_sensitivity") or ""),
            items=tuple(items),
            schema_version=str(payload.get("schema_version") or ""),
        ).validate()

    @classmethod
    def from_json(cls, raw: str) -> "LearningReuseReceipt":
        try:
            payload = json.loads(str(raw))
        except json.JSONDecodeError as exc:
            raise LearningEffectivenessError("reuse receipt JSON invalid") from exc
        return cls.from_payload(payload)


def record_learning_reuse(
    store: TaskStore,
    task_id: str,
    context: LearningContext,
) -> LearningReuseReceipt | None:
    """Record one metadata-only exact-knowledge reuse observation.

    Empty contexts are intentional no-ops. Duplicate activity rows are safe because
    the analyzer deduplicates exact receipt IDs and, more importantly, counts each
    task at most once per exact knowledge SHA.
    """

    if not isinstance(context, LearningContext):
        raise LearningEffectivenessError("LearningContext required")
    context.validate()
    if not context.items:
        return None
    task = store.get_task(task_id)
    if task.task_id != task_id:
        raise LearningEffectivenessError("task identity mismatch")
    contract = store.task_contract_for_task(task_id)
    if not isinstance(contract, dict):
        raise LearningEffectivenessError("bound TaskContract required for reuse receipt")
    if str(contract.get("task_id") or "") != task_id:
        raise LearningEffectivenessError("TaskContract task mismatch")
    if str(contract.get("sensitivity") or "").strip().lower() != context.task_sensitivity:
        raise LearningEffectivenessError("TaskContract sensitivity mismatch")

    receipt = LearningReuseReceipt.create(task_id, context)
    store.record_activity(
        task_id,
        REUSE_ACTIVITY_AGENT,
        REUSE_ACTIVITY_ACTION,
        "ok",
        receipt.to_json(),
    )
    return receipt


@dataclass(frozen=True)
class KnowledgeEffectivenessSignal:
    item_id: str
    knowledge_sha256: str
    domain: str
    unique_task_observations: int
    unique_reuse_receipts: int
    isolated_task_observations: int
    confounded_task_observations: int
    verified_success_after_reuse: int
    failed_after_reuse: int
    waiting_human_after_reuse: int
    pending_after_reuse: int
    done_unverified_after_reuse: int
    isolated_verified_success: int
    isolated_failed: int
    isolated_waiting_human: int
    isolated_done_unverified: int
    advisory_signal: str
    interpretation: str = INTERPRETATION

    def to_payload(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "knowledge_sha256": self.knowledge_sha256,
            "domain": self.domain,
            "unique_task_observations": self.unique_task_observations,
            "unique_reuse_receipts": self.unique_reuse_receipts,
            "isolated_task_observations": self.isolated_task_observations,
            "confounded_task_observations": self.confounded_task_observations,
            "verified_success_after_reuse": self.verified_success_after_reuse,
            "failed_after_reuse": self.failed_after_reuse,
            "waiting_human_after_reuse": self.waiting_human_after_reuse,
            "pending_after_reuse": self.pending_after_reuse,
            "done_unverified_after_reuse": self.done_unverified_after_reuse,
            "isolated_verified_success": self.isolated_verified_success,
            "isolated_failed": self.isolated_failed,
            "isolated_waiting_human": self.isolated_waiting_human,
            "isolated_done_unverified": self.isolated_done_unverified,
            "advisory_signal": self.advisory_signal,
            "interpretation": self.interpretation,
        }


@dataclass(frozen=True)
class LearningEffectivenessSnapshot:
    signals: tuple[KnowledgeEffectivenessSignal, ...]
    unique_receipt_count: int
    unique_task_count: int
    schema_version: str = EFFECTIVENESS_SNAPSHOT_SCHEMA
    interpretation: str = INTERPRETATION

    def _base_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "interpretation": self.interpretation,
            "unique_receipt_count": self.unique_receipt_count,
            "unique_task_count": self.unique_task_count,
            "signals": [signal.to_payload() for signal in self.signals],
        }

    @property
    def snapshot_sha256(self) -> str:
        return _sha_payload(self._base_payload())

    def to_payload(self) -> dict[str, Any]:
        return {**self._base_payload(), "snapshot_sha256": self.snapshot_sha256}


@dataclass(frozen=True)
class _TaskOutcome:
    code: str
    verification_sha256: str


class DeterministicLearningEffectivenessAnalyzer:
    """Join reuse receipts with authoritative task/validator state.

    The analyzer reads WorkSpace metadata only. It never reads learned content,
    prompts, evidence bytes, model output, paths, or credentials, and it exposes no
    learning-store mutation API.
    """

    __slots__ = ("store", "ledger")

    def __init__(self, store: TaskStore):
        self.store = store
        self.ledger = ValidatorLedger(store)

    def _receipts(self) -> tuple[LearningReuseReceipt, ...]:
        with self.store.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, task_id, details
                FROM activities
                WHERE agent_id = ? AND action = ?
                ORDER BY id
                """,
                (REUSE_ACTIVITY_AGENT, REUSE_ACTIVITY_ACTION),
            ).fetchall()
        by_id: dict[str, LearningReuseReceipt] = {}
        for row in rows:
            try:
                receipt = LearningReuseReceipt.from_json(str(row["details"]))
            except LearningEffectivenessError as exc:
                raise LearningEffectivenessError(
                    f"REUSE_RECEIPT_INVALID:activity_id={int(row['id'])}"
                ) from exc
            if str(row["task_id"] or "") != receipt.task_id:
                raise LearningEffectivenessError("REUSE_RECEIPT_TASK_LEDGER_MISMATCH")
            existing = by_id.get(receipt.receipt_id)
            if existing is not None and existing != receipt:
                raise LearningEffectivenessError("REUSE_RECEIPT_ID_COLLISION")
            by_id[receipt.receipt_id] = receipt
        return tuple(by_id[key] for key in sorted(by_id))

    def _outcome(self, task_id: str) -> _TaskOutcome:
        task = self.store.get_task(task_id)
        verification: TaskVerificationState = self.ledger.evaluate(task_id)
        verification_sha = _sha_payload(verification.to_dict())
        if task.status == TaskStatus.DONE:
            code = OUTCOME_VERIFIED_SUCCESS if verification.verified else OUTCOME_DONE_UNVERIFIED
        elif task.status == TaskStatus.FAILED:
            code = OUTCOME_FAILED
        elif task.status == TaskStatus.WAITING_HUMAN:
            code = OUTCOME_WAITING_HUMAN
        else:
            code = OUTCOME_PENDING
        return _TaskOutcome(code=code, verification_sha256=verification_sha)

    @staticmethod
    def _signal(
        *,
        domain: str,
        isolated_success: int,
        isolated_failed: int,
        isolated_waiting: int,
        isolated_done_unverified: int,
    ) -> str:
        adverse = isolated_failed + isolated_done_unverified
        if domain in {"network", "security"}:
            if adverse >= 1 or isolated_waiting >= 2:
                return SIGNAL_DOMAIN_REVIEW
        else:
            if adverse >= 2 or isolated_waiting >= 3:
                return SIGNAL_REVIEW
        if isolated_success >= 3 and adverse == 0 and isolated_waiting == 0:
            return SIGNAL_SUPPORT
        return SIGNAL_INSUFFICIENT

    def snapshot(self) -> LearningEffectivenessSnapshot:
        receipts = self._receipts()
        by_task: dict[str, list[LearningReuseReceipt]] = {}
        for receipt in receipts:
            by_task.setdefault(receipt.task_id, []).append(receipt)

        # One task contributes at most one outcome observation to an exact
        # knowledge version. If any other knowledge version was made available in
        # that task, every item observation for the task is marked confounded.
        per_item: dict[tuple[str, str, str], dict[str, Any]] = {}
        for task_id in sorted(by_task):
            task_receipts = by_task[task_id]
            refs: dict[tuple[str, str, str], LearningReuseItemRef] = {}
            receipt_counts: dict[tuple[str, str, str], set[str]] = {}
            domains_by_item: dict[tuple[str, str], set[str]] = {}
            for receipt in task_receipts:
                for item in receipt.items:
                    domains_by_item.setdefault(
                        (item.item_id, item.knowledge_sha256), set()
                    ).add(receipt.domain)
                    key = (item.item_id, item.knowledge_sha256, receipt.domain)
                    refs[key] = item
                    receipt_counts.setdefault(key, set()).add(receipt.receipt_id)
            for identity, domains in domains_by_item.items():
                if len(domains) != 1:
                    raise LearningEffectivenessError("REUSE_DOMAIN_CONFLICT")

            confounded = len({(item.item_id, item.knowledge_sha256) for item in refs.values()}) > 1
            outcome = self._outcome(task_id)
            for key in sorted(refs):
                item_id, knowledge_sha, domain = key
                bucket = per_item.setdefault(
                    key,
                    {
                        "tasks": set(),
                        "receipts": set(),
                        "isolated": 0,
                        "confounded": 0,
                        "outcomes": {
                            OUTCOME_VERIFIED_SUCCESS: 0,
                            OUTCOME_FAILED: 0,
                            OUTCOME_WAITING_HUMAN: 0,
                            OUTCOME_PENDING: 0,
                            OUTCOME_DONE_UNVERIFIED: 0,
                        },
                        "isolated_outcomes": {
                            OUTCOME_VERIFIED_SUCCESS: 0,
                            OUTCOME_FAILED: 0,
                            OUTCOME_WAITING_HUMAN: 0,
                            OUTCOME_PENDING: 0,
                            OUTCOME_DONE_UNVERIFIED: 0,
                        },
                        "verification": set(),
                    },
                )
                bucket["tasks"].add(task_id)
                bucket["receipts"].update(receipt_counts[key])
                bucket["verification"].add(outcome.verification_sha256)
                bucket["outcomes"][outcome.code] += 1
                if confounded:
                    bucket["confounded"] += 1
                else:
                    bucket["isolated"] += 1
                    bucket["isolated_outcomes"][outcome.code] += 1

        signals: list[KnowledgeEffectivenessSignal] = []
        for (item_id, knowledge_sha, domain), bucket in sorted(per_item.items()):
            outcomes = bucket["outcomes"]
            isolated = bucket["isolated_outcomes"]
            advisory = self._signal(
                domain=domain,
                isolated_success=isolated[OUTCOME_VERIFIED_SUCCESS],
                isolated_failed=isolated[OUTCOME_FAILED],
                isolated_waiting=isolated[OUTCOME_WAITING_HUMAN],
                isolated_done_unverified=isolated[OUTCOME_DONE_UNVERIFIED],
            )
            signals.append(
                KnowledgeEffectivenessSignal(
                    item_id=item_id,
                    knowledge_sha256=knowledge_sha,
                    domain=domain,
                    unique_task_observations=len(bucket["tasks"]),
                    unique_reuse_receipts=len(bucket["receipts"]),
                    isolated_task_observations=int(bucket["isolated"]),
                    confounded_task_observations=int(bucket["confounded"]),
                    verified_success_after_reuse=outcomes[OUTCOME_VERIFIED_SUCCESS],
                    failed_after_reuse=outcomes[OUTCOME_FAILED],
                    waiting_human_after_reuse=outcomes[OUTCOME_WAITING_HUMAN],
                    pending_after_reuse=outcomes[OUTCOME_PENDING],
                    done_unverified_after_reuse=outcomes[OUTCOME_DONE_UNVERIFIED],
                    isolated_verified_success=isolated[OUTCOME_VERIFIED_SUCCESS],
                    isolated_failed=isolated[OUTCOME_FAILED],
                    isolated_waiting_human=isolated[OUTCOME_WAITING_HUMAN],
                    isolated_done_unverified=isolated[OUTCOME_DONE_UNVERIFIED],
                    advisory_signal=advisory,
                )
            )

        return LearningEffectivenessSnapshot(
            signals=tuple(signals),
            unique_receipt_count=len(receipts),
            unique_task_count=len(by_task),
        )
