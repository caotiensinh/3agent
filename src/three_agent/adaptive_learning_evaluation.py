"""Offline/synthetic evaluation for WorkSpace adaptive-learning candidates.

The replay path is deterministic and local-only. It creates synthetic
ExperienceRecord/KnowledgeCandidate objects, runs contract validation plus
narrow domain safety checks, and emits metadata-only results.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .adaptive_learning_contract import (
    ACTIONS,
    DOMAINS,
    EXECUTION_MODES,
    KINDS,
    OUTCOMES,
    RISK_LEVELS,
    SENSITIVITIES,
    EvidenceReference,
    ExperienceRecord,
    KnowledgeCandidate,
    LearningContractError,
)

LEARNING_CORPUS_SCHEMA = "workspace-learning-evaluation-corpus/v1"
LEARNING_REPLAY_SCHEMA = "workspace-learning-evaluation-replay/v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_EXPECTED_KEYS = {"accepted", "reason_codes"}
_CASE_KEYS = {
    "case_id",
    "domain",
    "kind",
    "source_outcome",
    "source_sensitivity",
    "evidence_sensitivity",
    "candidate_sensitivity",
    "risk_level",
    "action",
    "execution_mode",
    "content",
    "expected",
}

_NETWORK_FORBIDDEN = (
    ("NETWORK_ACTIVE_SCAN_FORBIDDEN", re.compile(r"\b(?:nmap|masscan)\b", re.I)),
    ("NETWORK_LOAD_TEST_FORBIDDEN", re.compile(r"\b(?:iperf3?|speedtest)\b", re.I)),
    ("NETWORK_PACKET_INJECTION_FORBIDDEN", re.compile(r"\b(?:arpspoof|hping3?|tcpreplay)\b|packet\s+injection|arp\s+(?:spoof|poison)", re.I)),
    ("NETWORK_CONFIGURATION_FORBIDDEN", re.compile(r"configure\s+terminal|\bwrite\s+memory\b|\binterface\s+shutdown\b|\bno\s+shutdown\b|change\s+(?:the\s+)?(?:router|switch|firewall)\s+config", re.I)),
)
_SECURITY_FORBIDDEN = (
    ("SECURITY_AUTOMATIC_BLOCK_FORBIDDEN", re.compile(r"\b(?:iptables|nft)\b.*\b(?:add|insert|drop|reject)\b|block\s+(?:the\s+)?(?:account|host|ip)", re.I)),
    ("SECURITY_ACCOUNT_MUTATION_FORBIDDEN", re.compile(r"(?:disable|lock|delete)\s+(?:the\s+)?account|rotate\s+(?:the\s+)?credentials?", re.I)),
    ("SECURITY_HOST_MUTATION_FORBIDDEN", re.compile(r"kill\s+(?:the\s+)?process|quarantine\s+(?:the\s+)?host", re.I)),
    ("SECURITY_ALERT_SUPPRESSION_FORBIDDEN", re.compile(r"suppress\s+all\s+alerts|disable\s+(?:the\s+)?alerts?", re.I)),
)


class LearningEvaluationError(ValueError):
    pass


def _canonical_sha256(payload: Any) -> str:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _enum(value: Any, allowed: set[str], name: str) -> str:
    text = str(value or "").strip()
    if text not in allowed:
        raise LearningEvaluationError(f"unsupported {name}: {text}")
    return text


def _case_id(value: Any) -> str:
    text = str(value or "").strip()
    if not _ID.fullmatch(text):
        raise LearningEvaluationError("case_id must be a compact stable identifier")
    return text


def _reason_codes(values: Any) -> tuple[str, ...]:
    if not isinstance(values, list):
        raise LearningEvaluationError("expected.reason_codes must be a list")
    result: list[str] = []
    for value in values:
        code = str(value or "").strip().upper()
        if not re.fullmatch(r"[A-Z0-9][A-Z0-9_]{0,95}", code) or code in result:
            raise LearningEvaluationError("invalid expected reason code")
        result.append(code)
    return tuple(result)


@dataclass(frozen=True)
class LearningEvaluationCase:
    case_id: str
    domain: str
    kind: str
    source_outcome: str
    source_sensitivity: str
    evidence_sensitivity: str
    candidate_sensitivity: str
    risk_level: str
    action: str
    execution_mode: str
    content: str
    expected_accepted: bool
    expected_reason_codes: tuple[str, ...]

    @classmethod
    def from_payload(cls, payload: Any) -> "LearningEvaluationCase":
        if not isinstance(payload, dict) or set(payload) != _CASE_KEYS:
            raise LearningEvaluationError("learning evaluation case has unsupported fields")
        expected = payload.get("expected")
        if not isinstance(expected, dict) or set(expected) != _EXPECTED_KEYS:
            raise LearningEvaluationError("case expected payload must be strict")
        accepted = expected.get("accepted")
        if not isinstance(accepted, bool):
            raise LearningEvaluationError("expected.accepted must be boolean")
        content = str(payload.get("content") or "").strip()
        if not content or len(content) > 4000:
            raise LearningEvaluationError("case content must be 1..4000 characters")
        return cls(
            case_id=_case_id(payload.get("case_id")),
            domain=_enum(payload.get("domain"), DOMAINS, "domain"),
            kind=_enum(payload.get("kind"), KINDS, "kind"),
            source_outcome=_enum(payload.get("source_outcome"), OUTCOMES, "source_outcome"),
            source_sensitivity=_enum(payload.get("source_sensitivity"), SENSITIVITIES, "source_sensitivity"),
            evidence_sensitivity=_enum(payload.get("evidence_sensitivity"), SENSITIVITIES, "evidence_sensitivity"),
            candidate_sensitivity=_enum(payload.get("candidate_sensitivity"), SENSITIVITIES, "candidate_sensitivity"),
            risk_level=_enum(payload.get("risk_level"), RISK_LEVELS, "risk_level"),
            action=_enum(payload.get("action"), ACTIONS, "action"),
            execution_mode=_enum(payload.get("execution_mode"), EXECUTION_MODES, "execution_mode"),
            content=content,
            expected_accepted=accepted,
            expected_reason_codes=_reason_codes(expected.get("reason_codes")),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "domain": self.domain,
            "kind": self.kind,
            "source_outcome": self.source_outcome,
            "source_sensitivity": self.source_sensitivity,
            "evidence_sensitivity": self.evidence_sensitivity,
            "candidate_sensitivity": self.candidate_sensitivity,
            "risk_level": self.risk_level,
            "action": self.action,
            "execution_mode": self.execution_mode,
            "content": self.content,
            "expected": {
                "accepted": self.expected_accepted,
                "reason_codes": list(self.expected_reason_codes),
            },
        }


@dataclass(frozen=True)
class LearningEvaluationCorpus:
    corpus_id: str
    cases: tuple[LearningEvaluationCase, ...]
    source_path: Path

    @classmethod
    def load(cls, path: Path) -> "LearningEvaluationCorpus":
        source = Path(path)
        payload = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or set(payload) != {"schema_version", "corpus_id", "cases"}:
            raise LearningEvaluationError("learning corpus payload must be strict")
        if payload.get("schema_version") != LEARNING_CORPUS_SCHEMA:
            raise LearningEvaluationError(f"learning corpus schema must be {LEARNING_CORPUS_SCHEMA}")
        corpus_id = _case_id(payload.get("corpus_id"))
        raw_cases = payload.get("cases")
        if not isinstance(raw_cases, list) or not 1 <= len(raw_cases) <= 128:
            raise LearningEvaluationError("learning corpus must contain 1..128 cases")
        cases = tuple(LearningEvaluationCase.from_payload(item) for item in raw_cases)
        ids = [item.case_id for item in cases]
        if len(ids) != len(set(ids)):
            raise LearningEvaluationError("case_id values must be unique")
        return cls(corpus_id=corpus_id, cases=cases, source_path=source)

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema_version": LEARNING_CORPUS_SCHEMA,
            "corpus_id": self.corpus_id,
            "cases": [case.to_payload() for case in self.cases],
        }

    @property
    def sha256(self) -> str:
        return _canonical_sha256(self.to_payload())


class AdaptiveLearningDomainValidator:
    """Narrow content guard for offline candidate evaluation.

    This is defense-in-depth. It does not replace capability authority: even a
    candidate that passes this validator receives no permission to execute the
    described operation.
    """

    @staticmethod
    def validate(candidate: KnowledgeCandidate) -> tuple[str, ...]:
        candidate.validate()
        reasons: list[str] = []
        content = candidate.content
        if candidate.domain == "network":
            for code, pattern in _NETWORK_FORBIDDEN:
                if pattern.search(content):
                    reasons.append(code)
        elif candidate.domain == "security":
            for code, pattern in _SECURITY_FORBIDDEN:
                if pattern.search(content):
                    reasons.append(code)
        elif candidate.domain == "analyst" and candidate.kind == "analytical_pattern":
            lower = content.lower()
            if not any(token in lower for token in ("observation", "observed", "known fact")):
                reasons.append("ANALYST_OBSERVATION_SEPARATION_MISSING")
            if "hypothesis" not in lower:
                reasons.append("ANALYST_HYPOTHESIS_SEPARATION_MISSING")
            if not any(token in lower for token in ("missing evidence", "unknown", "confidence")):
                reasons.append("ANALYST_UNCERTAINTY_BOUNDARY_MISSING")
        return tuple(dict.fromkeys(reasons))


class AdaptiveLearningEvaluationReplay:
    @staticmethod
    def _contract_error_reason(exc: LearningContractError) -> str:
        message = str(exc).lower()
        if "sensitivity cannot downgrade" in message:
            return "CLASSIFICATION_DOWNGRADE"
        if "requires verified-success" in message:
            return "UNVERIFIED_PROCEDURAL_LEARNING"
        if "failed security scan" in message:
            return "PERSISTENCE_SECURITY_SCAN_FAILED"
        if "base_item_sha256" in message or "target_item_id" in message:
            return "READ_BEFORE_WRITE_LINEAGE_MISSING"
        return "CONTRACT_REJECTED"

    @staticmethod
    def replay_case(case: LearningEvaluationCase) -> dict[str, Any]:
        suffix = case.case_id.replace("_", "-")
        evidence = EvidenceReference(
            ref_id=f"evidence:{suffix}",
            sha256="sha256:" + hashlib.sha256(f"evidence:{case.case_id}".encode()).hexdigest(),
            source_type="synthetic_fixture",
            source_task_id=f"task:{suffix}",
            sensitivity=case.evidence_sensitivity,
            collection_mode="synthetic",
            created_at="2026-08-31T00:00:00Z",
            vendor_family="synthetic",
            version="v1",
        )
        try:
            experience = ExperienceRecord(
                experience_id=f"experience:{suffix}",
                domain=case.domain,
                task_id=f"task:{suffix}",
                outcome=case.source_outcome,
                sensitivity=case.source_sensitivity,
                summary="Synthetic offline fixture for deterministic adaptive-learning validation.",
                evidence=(evidence,),
                created_at="2026-08-31T00:00:01Z",
            ).validate()
            kwargs: dict[str, Any] = {}
            if case.action != "create":
                kwargs.update(
                    target_item_id=f"knowledge:{suffix}",
                    base_item_sha256="sha256:" + "b" * 64,
                )
            candidate = KnowledgeCandidate.from_experiences(
                candidate_id=f"candidate:{suffix}",
                domain=case.domain,
                kind=case.kind,
                title=f"Synthetic {case.case_id}",
                content=case.content,
                scope="offline-evaluation",
                sensitivity=case.candidate_sensitivity,
                risk_level=case.risk_level,
                ownership="learner_managed",
                action=case.action,
                execution_mode=case.execution_mode,
                experiences=(experience,),
                created_at="2026-08-31T00:00:02Z",
                **kwargs,
            )
        except LearningContractError as exc:
            reasons = (AdaptiveLearningEvaluationReplay._contract_error_reason(exc),)
        else:
            reasons = AdaptiveLearningDomainValidator.validate(candidate)
        accepted = not reasons
        passed = accepted == case.expected_accepted and reasons == case.expected_reason_codes
        return {
            "case_id": case.case_id,
            "passed": passed,
            "accepted": accepted,
            "reason_codes": list(reasons),
        }

    @classmethod
    def replay(cls, corpus: LearningEvaluationCorpus, *, source_ref: str) -> dict[str, Any]:
        source = str(source_ref or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{40}", source):
            raise LearningEvaluationError("source_ref must be an exact 40-hex Git commit SHA")
        results = [cls.replay_case(case) for case in corpus.cases]
        passed_count = sum(1 for result in results if result["passed"])
        return {
            "schema_version": LEARNING_REPLAY_SCHEMA,
            "corpus_id": corpus.corpus_id,
            "corpus_sha256": corpus.sha256,
            "source_ref": source,
            "case_count": len(results),
            "passed_count": passed_count,
            "failed_count": len(results) - passed_count,
            "passed": passed_count == len(results),
            "cases": results,
        }
