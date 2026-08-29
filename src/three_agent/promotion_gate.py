from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .evaluation_lab import EvaluationCorpus, REPLAY_SCHEMA
from .metric_registry import DEFAULT_METRIC_REGISTRY, METRIC_REGISTRY_ID

PROMOTION_POLICY_SCHEMA = "workspace-promotion-policy/v1"
PROMOTION_EVIDENCE_SCHEMA = "workspace-promotion-evidence/v1"
PROMOTION_RECEIPT_SCHEMA = "workspace-promotion-receipt/v1"
PROMOTION_CLASSES = (
    "golden",
    "replay",
    "regression",
    "adversarial_security",
    "edge_large_context",
    "efficiency_cache_concurrency",
)
_REPOSITORY_CLASSES = {"golden", "regression", "adversarial_security"}
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CHECK_RE = re.compile(r"^[A-Z0-9][A-Z0-9_]{0,95}$")
_EVIDENCE_REF_RE = re.compile(
    r"^(?:sha256:[0-9a-f]{64}|[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255})$"
)
_EVIDENCE_KEYS = {
    "schema_version",
    "evidence_id",
    "corpus_class",
    "corpus_id",
    "corpus_sha256",
    "metric_registry_id",
    "metric_registry_sha256",
    "baseline_ref",
    "candidate_ref",
    "checks",
    "security_passed",
    "evidence_refs",
    "label_commitment_sha256",
    "evaluator_attested",
}


class PromotionGateError(ValueError):
    """Promotion evidence is incomplete, inconsistent, or unsafe."""


def _canonical_sha256(payload: Any) -> str:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _compact_id(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not _ID_RE.fullmatch(text):
        raise PromotionGateError(f"{field} must be a compact stable identifier")
    return text


def _git_sha(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if not _GIT_SHA_RE.fullmatch(text):
        raise PromotionGateError(f"{field} must be an exact 40-hex Git SHA")
    return text


def _sha256(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise PromotionGateError(f"{field} must be a sha256:<64-hex> value")
    return text


def _safe_relative_path(value: Any, field: str) -> str:
    text = str(value or "").strip().replace("\\", "/")
    path = Path(text)
    if not text or path.is_absolute() or ".." in path.parts or len(text) > 240:
        raise PromotionGateError(f"{field} must be a safe repository-relative path")
    return text


def _safe_refs(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or not values:
        raise PromotionGateError("evidence_refs must be a non-empty sequence")
    refs: list[str] = []
    for raw in values:
        ref = str(raw or "").strip()
        if not _EVIDENCE_REF_RE.fullmatch(ref):
            raise PromotionGateError(
                "evidence_refs accept compact identifiers/hashes only; raw content is forbidden"
            )
        if ref not in refs:
            refs.append(ref)
        if len(refs) > 32:
            raise PromotionGateError("at most 32 evidence_refs are allowed")
    return tuple(refs)


def _validated_checks(values: Any, field: str) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or not values:
        raise PromotionGateError(f"{field} must be a non-empty sequence")
    checks: list[str] = []
    for raw in values:
        check = str(raw or "").strip().upper()
        if not _CHECK_RE.fullmatch(check):
            raise PromotionGateError(f"invalid check identifier in {field}: {check}")
        if check not in checks:
            checks.append(check)
    return tuple(checks)


@dataclass(frozen=True)
class PromotionClassSpec:
    class_id: str
    source_kind: str
    source_ref: str | None
    required_checks: tuple[str, ...]
    holdout_commitment_required: bool
    evaluator_attestation_required: bool

    @classmethod
    def from_payload(cls, class_id: str, payload: Any) -> "PromotionClassSpec":
        if not isinstance(payload, dict):
            raise PromotionGateError(f"promotion class {class_id} must be an object")
        allowed = {
            "source_kind",
            "source_ref",
            "required_checks",
            "holdout_commitment_required",
            "evaluator_attestation_required",
        }
        if set(payload) != allowed:
            raise PromotionGateError(f"promotion class {class_id} has unsupported fields")
        raw_ref = payload.get("source_ref")
        normalized_ref = None if raw_ref is None else str(raw_ref).strip().replace("\\", "/")
        return cls(
            class_id=str(class_id).strip(),
            source_kind=str(payload.get("source_kind") or "").strip(),
            source_ref=normalized_ref,
            required_checks=tuple(payload.get("required_checks") or ()),
            holdout_commitment_required=payload.get("holdout_commitment_required"),
            evaluator_attestation_required=payload.get("evaluator_attestation_required"),
        ).validate()

    def validate(self) -> "PromotionClassSpec":
        if self.class_id not in PROMOTION_CLASSES:
            raise PromotionGateError(f"unsupported promotion class: {self.class_id}")
        if self.source_kind not in {
            "repository_corpus",
            "external_replay",
            "external_holdout",
            "external_benchmark",
        }:
            raise PromotionGateError(f"unsupported source_kind for {self.class_id}")
        if self.source_kind == "repository_corpus":
            _safe_relative_path(self.source_ref, f"{self.class_id}.source_ref")
            if self.class_id not in _REPOSITORY_CLASSES:
                raise PromotionGateError(
                    f"repository_corpus is not authorized for promotion class {self.class_id}"
                )
        elif self.source_ref is not None:
            raise PromotionGateError(
                f"external promotion class {self.class_id} must not embed repository source_ref"
            )
        _validated_checks(self.required_checks, f"{self.class_id}.required_checks")
        if not isinstance(self.holdout_commitment_required, bool) or not isinstance(
            self.evaluator_attestation_required, bool
        ):
            raise PromotionGateError(
                f"{self.class_id} holdout/attestation flags must be boolean"
            )
        if self.holdout_commitment_required and not self.evaluator_attestation_required:
            raise PromotionGateError(
                f"{self.class_id} holdout commitments require evaluator attestation"
            )
        return self

    def to_payload(self) -> dict[str, Any]:
        return {
            "source_kind": self.source_kind,
            "source_ref": self.source_ref,
            "required_checks": list(_validated_checks(self.required_checks, "required_checks")),
            "holdout_commitment_required": self.holdout_commitment_required,
            "evaluator_attestation_required": self.evaluator_attestation_required,
        }


@dataclass(frozen=True)
class PromotionPolicy:
    policy_id: str
    metric_registry_id: str
    classes: tuple[PromotionClassSpec, ...]
    source_path: Path

    @classmethod
    def load(cls, path: Path) -> "PromotionPolicy":
        source = Path(path)
        payload = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema_version") != PROMOTION_POLICY_SCHEMA:
            raise PromotionGateError(
                f"promotion policy schema must be {PROMOTION_POLICY_SCHEMA}"
            )
        if set(payload) != {"schema_version", "policy_id", "metric_registry_id", "classes"}:
            raise PromotionGateError("promotion policy contains unsupported fields")
        raw_classes = payload.get("classes")
        if not isinstance(raw_classes, dict) or set(raw_classes) != set(PROMOTION_CLASSES):
            raise PromotionGateError(
                "promotion policy must declare exactly all mandatory corpus classes"
            )
        return cls(
            policy_id=_compact_id(payload.get("policy_id"), "policy_id"),
            metric_registry_id=str(payload.get("metric_registry_id") or "").strip(),
            classes=tuple(
                PromotionClassSpec.from_payload(class_id, raw_classes[class_id])
                for class_id in PROMOTION_CLASSES
            ),
            source_path=source,
        ).validate()

    def validate(self) -> "PromotionPolicy":
        _compact_id(self.policy_id, "policy_id")
        if self.metric_registry_id != METRIC_REGISTRY_ID:
            raise PromotionGateError("promotion policy metric registry is not current")
        if tuple(item.class_id for item in self.classes) != PROMOTION_CLASSES:
            raise PromotionGateError("promotion classes must match mandatory v1 order")
        for item in self.classes:
            item.validate()
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": PROMOTION_POLICY_SCHEMA,
            "policy_id": self.policy_id,
            "metric_registry_id": self.metric_registry_id,
            "classes": {item.class_id: item.to_payload() for item in self.classes},
        }

    @property
    def sha256(self) -> str:
        return _canonical_sha256(self.to_payload())

    def by_id(self) -> dict[str, PromotionClassSpec]:
        self.validate()
        return {item.class_id: item for item in self.classes}


@dataclass(frozen=True)
class PromotionEvidence:
    evidence_id: str
    corpus_class: str
    corpus_id: str
    corpus_sha256: str
    metric_registry_id: str
    metric_registry_sha256: str
    baseline_ref: str
    candidate_ref: str
    checks: dict[str, bool]
    security_passed: bool
    evidence_refs: tuple[str, ...]
    label_commitment_sha256: str | None
    evaluator_attested: bool

    @classmethod
    def from_payload(cls, payload: Any) -> "PromotionEvidence":
        if not isinstance(payload, dict) or set(payload) != _EVIDENCE_KEYS:
            raise PromotionGateError(
                "promotion evidence must contain exactly the metadata-only v1 fields"
            )
        if payload.get("schema_version") != PROMOTION_EVIDENCE_SCHEMA:
            raise PromotionGateError(
                f"promotion evidence schema must be {PROMOTION_EVIDENCE_SCHEMA}"
            )
        raw_checks = payload.get("checks")
        if not isinstance(raw_checks, dict) or not raw_checks:
            raise PromotionGateError("promotion evidence checks must be a non-empty object")
        checks = {str(name).strip().upper(): value for name, value in raw_checks.items()}
        label_raw = payload.get("label_commitment_sha256")
        label_hash = None if label_raw is None else str(label_raw).strip().lower()
        return cls(
            evidence_id=str(payload.get("evidence_id") or "").strip(),
            corpus_class=str(payload.get("corpus_class") or "").strip(),
            corpus_id=str(payload.get("corpus_id") or "").strip(),
            corpus_sha256=str(payload.get("corpus_sha256") or "").strip().lower(),
            metric_registry_id=str(payload.get("metric_registry_id") or "").strip(),
            metric_registry_sha256=str(payload.get("metric_registry_sha256") or "").strip().lower(),
            baseline_ref=str(payload.get("baseline_ref") or "").strip().lower(),
            candidate_ref=str(payload.get("candidate_ref") or "").strip().lower(),
            checks=checks,
            security_passed=payload.get("security_passed"),
            evidence_refs=tuple(payload.get("evidence_refs") or ()),
            label_commitment_sha256=label_hash,
            evaluator_attested=payload.get("evaluator_attested"),
        ).validate()

    @classmethod
    def load(cls, path: Path) -> "PromotionEvidence":
        return cls.from_payload(json.loads(Path(path).read_text(encoding="utf-8")))

    def validate(self) -> "PromotionEvidence":
        _compact_id(self.evidence_id, "evidence_id")
        if self.corpus_class not in PROMOTION_CLASSES:
            raise PromotionGateError("promotion evidence corpus_class is invalid")
        _compact_id(self.corpus_id, "corpus_id")
        _sha256(self.corpus_sha256, "corpus_sha256")
        if self.metric_registry_id != METRIC_REGISTRY_ID:
            raise PromotionGateError("promotion evidence metric registry id mismatch")
        if _sha256(
            self.metric_registry_sha256, "metric_registry_sha256"
        ) != DEFAULT_METRIC_REGISTRY.sha256:
            raise PromotionGateError("promotion evidence metric registry fingerprint mismatch")
        baseline = _git_sha(self.baseline_ref, "baseline_ref")
        candidate = _git_sha(self.candidate_ref, "candidate_ref")
        if baseline == candidate:
            raise PromotionGateError("candidate_ref must differ from baseline_ref")
        if not isinstance(self.checks, dict) or not self.checks:
            raise PromotionGateError("promotion evidence checks must be a non-empty object")
        for name, value in self.checks.items():
            if not _CHECK_RE.fullmatch(str(name).strip().upper()) or not isinstance(value, bool):
                raise PromotionGateError("promotion evidence checks must be boolean compact IDs")
        if not isinstance(self.security_passed, bool) or not isinstance(self.evaluator_attested, bool):
            raise PromotionGateError("security/evaluator flags must be boolean")
        if self.label_commitment_sha256 is not None:
            _sha256(self.label_commitment_sha256, "label_commitment_sha256")
        _safe_refs(self.evidence_refs)
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": PROMOTION_EVIDENCE_SCHEMA,
            "evidence_id": self.evidence_id,
            "corpus_class": self.corpus_class,
            "corpus_id": self.corpus_id,
            "corpus_sha256": self.corpus_sha256,
            "metric_registry_id": self.metric_registry_id,
            "metric_registry_sha256": self.metric_registry_sha256,
            "baseline_ref": self.baseline_ref,
            "candidate_ref": self.candidate_ref,
            "checks": dict(sorted(self.checks.items())),
            "security_passed": self.security_passed,
            "evidence_refs": list(self.evidence_refs),
            "label_commitment_sha256": self.label_commitment_sha256,
            "evaluator_attested": self.evaluator_attested,
        }


def _validate_replay_report(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema_version") != REPLAY_SCHEMA:
        raise PromotionGateError(f"replay report schema must be {REPLAY_SCHEMA}")
    if payload.get("passed") is not True:
        raise PromotionGateError("repository replay report must pass before evidence creation")
    source_ref = _git_sha(payload.get("source_ref"), "replay.source_ref")
    corpus_class = str(payload.get("corpus_class") or "").strip()
    if corpus_class not in _REPOSITORY_CLASSES:
        raise PromotionGateError("repository replay evidence supports only repository corpus classes")
    corpus_id = _compact_id(payload.get("corpus_id"), "replay.corpus_id")
    corpus_hash = _sha256(payload.get("corpus_sha256"), "replay.corpus_sha256")
    case_count = payload.get("case_count")
    passed_count = payload.get("passed_count")
    failed_count = payload.get("failed_count")
    if (
        isinstance(case_count, bool)
        or not isinstance(case_count, int)
        or case_count < 1
        or passed_count != case_count
        or failed_count != 0
    ):
        raise PromotionGateError("repository replay report case accounting is inconsistent")
    return {
        "source_ref": source_ref,
        "corpus_class": corpus_class,
        "corpus_id": corpus_id,
        "corpus_sha256": corpus_hash,
    }


def build_repository_replay_evidence(
    baseline_report: dict[str, Any],
    candidate_report: dict[str, Any],
    *,
    evidence_id: str,
) -> PromotionEvidence:
    baseline = _validate_replay_report(baseline_report)
    candidate = _validate_replay_report(candidate_report)
    if baseline["source_ref"] == candidate["source_ref"]:
        raise PromotionGateError("baseline and candidate replay source refs must differ")
    for key in ("corpus_class", "corpus_id", "corpus_sha256"):
        if baseline[key] != candidate[key]:
            raise PromotionGateError(f"baseline/candidate replay {key} mismatch")
    class_id = str(candidate["corpus_class"])
    if class_id == "adversarial_security":
        checks = {"ADVERSARIAL_REPLAY_PASS": True, "SECURITY_GATE_PASS": True}
    else:
        checks = {"CONTROL_PLANE_REPLAY_PASS": True}
    return PromotionEvidence.from_payload(
        {
            "schema_version": PROMOTION_EVIDENCE_SCHEMA,
            "evidence_id": _compact_id(evidence_id, "evidence_id"),
            "corpus_class": class_id,
            "corpus_id": candidate["corpus_id"],
            "corpus_sha256": candidate["corpus_sha256"],
            "metric_registry_id": METRIC_REGISTRY_ID,
            "metric_registry_sha256": DEFAULT_METRIC_REGISTRY.sha256,
            "baseline_ref": baseline["source_ref"],
            "candidate_ref": candidate["source_ref"],
            "checks": checks,
            "security_passed": True,
            "evidence_refs": [
                _canonical_sha256(baseline_report),
                _canonical_sha256(candidate_report),
            ],
            "label_commitment_sha256": None,
            "evaluator_attested": False,
        }
    )


class PromotionPipeline:
    """Fail-closed production promotion admission over all mandatory D7 classes."""

    @staticmethod
    def _repository_expectation(
        spec: PromotionClassSpec,
        *,
        repo_root: Path,
    ) -> tuple[str, str] | None:
        spec.validate()
        if spec.source_kind != "repository_corpus":
            return None
        if spec.source_ref is None:
            raise PromotionGateError("repository corpus source_ref is missing")
        root = Path(repo_root).resolve()
        path = (root / spec.source_ref).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise PromotionGateError("repository corpus path escapes repo_root") from exc
        corpus = EvaluationCorpus.load(path)
        if corpus.corpus_class != spec.class_id:
            raise PromotionGateError(
                f"repository corpus class mismatch for {spec.class_id}"
            )
        return corpus.corpus_id, corpus.sha256

    @classmethod
    def evaluate(
        cls,
        policy: PromotionPolicy,
        evidence: Iterable[PromotionEvidence],
        *,
        repo_root: Path,
        baseline_ref: str,
        candidate_ref: str,
        rollback_ref: str,
    ) -> dict[str, Any]:
        policy.validate()
        baseline = _git_sha(baseline_ref, "baseline_ref")
        candidate = _git_sha(candidate_ref, "candidate_ref")
        rollback = _git_sha(rollback_ref, "rollback_ref")
        if baseline == candidate:
            raise PromotionGateError("candidate_ref must differ from baseline_ref")
        if rollback != baseline:
            raise PromotionGateError(
                "v1 rollback_ref must exactly equal the evaluated baseline_ref"
            )

        failures: list[str] = []
        by_class: dict[str, PromotionEvidence] = {}
        for row in evidence:
            row.validate()
            if row.corpus_class in by_class:
                failures.append(f"DUPLICATE_EVIDENCE:{row.corpus_class}")
                continue
            by_class[row.corpus_class] = row

        class_results: dict[str, Any] = {}
        specs = policy.by_id()
        for class_id in PROMOTION_CLASSES:
            spec = specs[class_id]
            row = by_class.get(class_id)
            class_failures: list[str] = []
            expected_repo = cls._repository_expectation(spec, repo_root=repo_root)
            if row is None:
                class_failures.append("EVIDENCE_MISSING")
            else:
                if row.baseline_ref != baseline or row.candidate_ref != candidate:
                    class_failures.append("SOURCE_LINEAGE_MISMATCH")
                if row.metric_registry_id != METRIC_REGISTRY_ID:
                    class_failures.append("METRIC_REGISTRY_ID_MISMATCH")
                if row.metric_registry_sha256 != DEFAULT_METRIC_REGISTRY.sha256:
                    class_failures.append("METRIC_REGISTRY_SHA_MISMATCH")
                if not row.security_passed:
                    class_failures.append("SECURITY_GATE_FAILED")
                for check in spec.required_checks:
                    if row.checks.get(check) is not True:
                        class_failures.append(f"REQUIRED_CHECK_FAILED:{check}")
                if expected_repo is not None:
                    expected_id, expected_hash = expected_repo
                    if row.corpus_id != expected_id or row.corpus_sha256 != expected_hash:
                        class_failures.append("REPOSITORY_CORPUS_LINEAGE_MISMATCH")
                if spec.holdout_commitment_required and row.label_commitment_sha256 is None:
                    class_failures.append("HOLDOUT_LABEL_COMMITMENT_MISSING")
                if spec.evaluator_attestation_required and not row.evaluator_attested:
                    class_failures.append("EVALUATOR_ATTESTATION_MISSING")
            if class_failures:
                failures.extend(f"{class_id}:{item}" for item in class_failures)
            class_results[class_id] = {
                "passed": not class_failures,
                "failures": class_failures,
                "evidence_id": row.evidence_id if row is not None else None,
                "corpus_sha256": row.corpus_sha256 if row is not None else None,
                "evidence_refs": list(row.evidence_refs) if row is not None else [],
                "label_commitment_sha256": (
                    row.label_commitment_sha256 if row is not None else None
                ),
            }

        accepted = not failures and len(by_class) == len(PROMOTION_CLASSES)
        receipt: dict[str, Any] = {
            "schema_version": PROMOTION_RECEIPT_SCHEMA,
            "accepted": accepted,
            "policy_id": policy.policy_id,
            "policy_sha256": policy.sha256,
            "baseline_ref": baseline,
            "candidate_ref": candidate,
            "rollback_ref": rollback,
            "metric_registry_id": METRIC_REGISTRY_ID,
            "metric_registry_sha256": DEFAULT_METRIC_REGISTRY.sha256,
            "classes": class_results,
            "failures": failures,
            "security": {
                "all_mandatory_classes_required": True,
                "waiver_path_available": False,
                "raw_holdout_labels_embedded": False,
                "raw_prompts_embedded": False,
                "raw_evidence_embedded": False,
                "rollback_lineage_required": True,
            },
        }
        receipt["receipt_sha256"] = _canonical_sha256(receipt)
        return receipt


def _write_json(path: Path, payload: dict[str, Any], *, force: bool) -> Path:
    target = Path(path)
    if target.exists() and not force:
        raise FileExistsError(f"output already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(target)
    return target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workspace-promotion",
        description="WorkSpace fail-closed D7 production promotion gate",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    replay = sub.add_parser("replay-evidence")
    replay.add_argument("--baseline-report", required=True)
    replay.add_argument("--candidate-report", required=True)
    replay.add_argument("--evidence-id", required=True)
    replay.add_argument("--output", required=True)
    replay.add_argument("--force", action="store_true")

    check = sub.add_parser("check")
    check.add_argument("--policy", required=True)
    check.add_argument("--repo-root", default=".")
    check.add_argument("--baseline-ref", required=True)
    check.add_argument("--candidate-ref", required=True)
    check.add_argument("--rollback-ref", required=True)
    check.add_argument("--evidence", action="append", required=True)
    check.add_argument("--output")
    check.add_argument("--force", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "replay-evidence":
            baseline = json.loads(Path(args.baseline_report).read_text(encoding="utf-8"))
            candidate = json.loads(Path(args.candidate_report).read_text(encoding="utf-8"))
            evidence = build_repository_replay_evidence(
                baseline,
                candidate,
                evidence_id=args.evidence_id,
            )
            payload = evidence.to_payload()
            _write_json(Path(args.output), payload, force=args.force)
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return 0

        policy = PromotionPolicy.load(Path(args.policy))
        evidence = [PromotionEvidence.load(Path(path)) for path in args.evidence]
        receipt = PromotionPipeline.evaluate(
            policy,
            evidence,
            repo_root=Path(args.repo_root),
            baseline_ref=args.baseline_ref,
            candidate_ref=args.candidate_ref,
            rollback_ref=args.rollback_ref,
        )
        if args.output:
            _write_json(Path(args.output), receipt, force=args.force)
        print(json.dumps(receipt, ensure_ascii=False, indent=2))
        return 0 if receipt["accepted"] else 3
    except (
        OSError,
        json.JSONDecodeError,
        PromotionGateError,
        FileExistsError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {
                    "schema_version": PROMOTION_RECEIPT_SCHEMA,
                    "accepted": False,
                    "error": f"{type(exc).__name__}: {exc}",
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
