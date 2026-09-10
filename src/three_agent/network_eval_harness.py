from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

HARNESS_MANIFEST_SCHEMA = "workspace-network-specialist-corpus-manifest/v1"
SPECIALISTS = {
    "intrusion-trace-hunting",
    "log-incident-diagnosis",
    "host-log-forensics",
}
CASE_CLASSES = {
    "positive",
    "negative",
    "near_miss",
    "ambiguous",
    "insufficient_evidence",
    "telemetry_gap",
}
PROMOTION_DATASET_STATUSES = {"enterprise_approved", "operator_verified"}
NON_POSITIVE_CASE_CLASSES = CASE_CLASSES - {"positive"}
FORBIDDEN_VISIBLE_KEYS = {
    "case_class",
    "ground_truth",
    "hidden_ground_truth",
    "hidden_ground_truth_ref",
    "answer_key",
    "expected_answer",
    "expected_root_cause",
    "expected_attack_path",
    "expected_forensic_findings",
    "verified_remediation",
}


class NetworkHarnessError(ValueError):
    """A corpus or case violates the specialist evaluation boundary."""


def _bounded(value: Any, field: str, *, max_len: int = 512) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len:
        raise NetworkHarnessError(f"{field} must be a non-empty bounded string")
    return text


def _string_tuple(
    value: Any,
    field: str,
    *,
    min_items: int = 1,
    max_items: int = 256,
) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise NetworkHarnessError(f"{field} must be a list")
    if not min_items <= len(value) <= max_items:
        raise NetworkHarnessError(
            f"{field} must contain {min_items}..{max_items} items"
        )
    items = tuple(_bounded(item, field) for item in value)
    if len(set(items)) != len(items):
        raise NetworkHarnessError(f"{field} must not contain duplicates")
    return items


def _sha256(value: Any, field: str) -> str:
    text = _bounded(value, field, max_len=71)
    if not text.startswith("sha256:") or len(text) != 71:
        raise NetworkHarnessError(f"{field} must be sha256:<64-hex>")
    try:
        int(text[7:], 16)
    except ValueError as exc:
        raise NetworkHarnessError(f"{field} must be sha256:<64-hex>") from exc
    return text


def canonical_sha256(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _reject_hidden_truth_fields(value: Any, path: str = "visible_input") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            if key_text in FORBIDDEN_VISIBLE_KEYS:
                raise NetworkHarnessError(
                    f"hidden ground-truth field {key_text!r} is forbidden in {path}"
                )
            _reject_hidden_truth_fields(child, f"{path}.{key_text}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_hidden_truth_fields(child, f"{path}[{index}]")


@dataclass(frozen=True)
class CaseManifest:
    case_id: str
    dataset_id: str
    dataset_status: str
    specialist_target: str
    case_class: str
    source_object_refs: tuple[str, ...]
    source_sha256: tuple[str, ...]
    provenance_ref: str
    incident_start: str
    incident_end: str
    visible_evidence_refs: tuple[str, ...]
    hidden_ground_truth_ref: str

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CaseManifest":
        specialist = _bounded(
            value.get("specialist_target"), "specialist_target", max_len=80
        )
        if specialist not in SPECIALISTS:
            raise NetworkHarnessError(
                f"specialist_target must be one of {sorted(SPECIALISTS)}"
            )

        case_class = _bounded(value.get("case_class"), "case_class", max_len=48)
        if case_class not in CASE_CLASSES:
            raise NetworkHarnessError(
                f"case_class must be one of {sorted(CASE_CLASSES)}"
            )

        status = _bounded(value.get("dataset_status"), "dataset_status", max_len=48)
        if status not in PROMOTION_DATASET_STATUSES:
            raise NetworkHarnessError(
                "promotion/evaluation corpus cases require enterprise_approved or operator_verified dataset status"
            )

        source_refs = _string_tuple(
            value.get("source_object_refs"), "source_object_refs", max_items=64
        )
        source_hashes_raw = value.get("source_sha256")
        if not isinstance(source_hashes_raw, (list, tuple)):
            raise NetworkHarnessError("source_sha256 must be a list")
        source_hashes = tuple(
            _sha256(item, "source_sha256") for item in source_hashes_raw
        )
        if len(source_refs) != len(source_hashes):
            raise NetworkHarnessError(
                "source_object_refs and source_sha256 must have the same length"
            )

        visible_refs = _string_tuple(
            value.get("visible_evidence_refs"), "visible_evidence_refs", max_items=512
        )
        hidden_ref = _bounded(
            value.get("hidden_ground_truth_ref"),
            "hidden_ground_truth_ref",
            max_len=512,
        )
        if hidden_ref in visible_refs or hidden_ref in source_refs:
            raise NetworkHarnessError(
                "hidden_ground_truth_ref must not be exposed as visible evidence or source input"
            )

        return cls(
            case_id=_bounded(value.get("case_id"), "case_id", max_len=128),
            dataset_id=_bounded(value.get("dataset_id"), "dataset_id", max_len=80),
            dataset_status=status,
            specialist_target=specialist,
            case_class=case_class,
            source_object_refs=source_refs,
            source_sha256=source_hashes,
            provenance_ref=_bounded(
                value.get("provenance_ref"), "provenance_ref", max_len=512
            ),
            incident_start=_bounded(
                value.get("incident_start"), "incident_start", max_len=64
            ),
            incident_end=_bounded(
                value.get("incident_end"), "incident_end", max_len=64
            ),
            visible_evidence_refs=visible_refs,
            hidden_ground_truth_ref=hidden_ref,
        )

    def visible_contract(self) -> dict[str, Any]:
        """Return only fields that a specialist runner is allowed to observe."""

        payload = {
            "case_id": self.case_id,
            "dataset_id": self.dataset_id,
            "specialist_target": self.specialist_target,
            "incident_start": self.incident_start,
            "incident_end": self.incident_end,
            "visible_evidence_refs": list(self.visible_evidence_refs),
            "provenance_ref": self.provenance_ref,
        }
        _reject_hidden_truth_fields(payload)
        return payload

    def scorer_contract(self) -> dict[str, Any]:
        """Return scorer-only labels/references that must never enter specialist input."""

        return {
            "case_id": self.case_id,
            "case_class": self.case_class,
            "hidden_ground_truth_ref": self.hidden_ground_truth_ref,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "dataset_id": self.dataset_id,
            "dataset_status": self.dataset_status,
            "specialist_target": self.specialist_target,
            "case_class": self.case_class,
            "source_object_refs": list(self.source_object_refs),
            "source_sha256": list(self.source_sha256),
            "provenance_ref": self.provenance_ref,
            "incident_start": self.incident_start,
            "incident_end": self.incident_end,
            "visible_evidence_refs": list(self.visible_evidence_refs),
            "hidden_ground_truth_ref": self.hidden_ground_truth_ref,
        }


@dataclass(frozen=True)
class CorpusManifest:
    manifest_id: str
    purpose: str
    cases: tuple[CaseManifest, ...]
    schema_version: str = HARNESS_MANIFEST_SCHEMA

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CorpusManifest":
        if value.get("schema_version") != HARNESS_MANIFEST_SCHEMA:
            raise NetworkHarnessError(
                f"unsupported manifest schema; expected {HARNESS_MANIFEST_SCHEMA}"
            )
        purpose = _bounded(value.get("purpose"), "purpose", max_len=48)
        if purpose not in {"fixture", "holdout", "evaluation"}:
            raise NetworkHarnessError(
                "purpose must be fixture, holdout, or evaluation"
            )
        raw_cases = value.get("cases")
        if not isinstance(raw_cases, list) or not raw_cases:
            raise NetworkHarnessError("cases must be a non-empty list")
        cases = tuple(CaseManifest.from_dict(item) for item in raw_cases)
        ids = [case.case_id for case in cases]
        if len(ids) != len(set(ids)):
            raise NetworkHarnessError("case_id values must be unique")

        if purpose in {"holdout", "evaluation"}:
            non_positive = sum(
                1 for case in cases if case.case_class in NON_POSITIVE_CASE_CLASSES
            )
            if non_positive / len(cases) < 0.25:
                raise NetworkHarnessError(
                    "holdout/evaluation manifest requires at least 25% non-positive cases"
                )

        return cls(
            manifest_id=_bounded(value.get("manifest_id"), "manifest_id", max_len=128),
            purpose=purpose,
            cases=cases,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "manifest_id": self.manifest_id,
            "purpose": self.purpose,
            "cases": [case.as_dict() for case in self.cases],
        }

    def fingerprint(self) -> str:
        return canonical_sha256(self.as_dict())

    def _case(self, case_id: str) -> CaseManifest:
        for case in self.cases:
            if case.case_id == case_id:
                return case
        raise NetworkHarnessError(f"unknown case_id: {case_id}")

    def visible_case(self, case_id: str) -> dict[str, Any]:
        return self._case(case_id).visible_contract()

    def scorer_case(self, case_id: str) -> dict[str, Any]:
        """Scorer-only accessor. Never pass this result to a specialist runner."""

        return self._case(case_id).scorer_contract()


def build_specialist_input(
    case: CaseManifest,
    evidence_by_ref: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Build a bounded specialist payload from exactly the case-visible evidence refs."""

    missing = [ref for ref in case.visible_evidence_refs if ref not in evidence_by_ref]
    if missing:
        raise NetworkHarnessError(f"missing visible evidence refs: {missing}")

    unexpected = set(evidence_by_ref) - set(case.visible_evidence_refs)
    if unexpected:
        raise NetworkHarnessError(
            f"out-of-case evidence supplied to specialist input: {sorted(unexpected)}"
        )

    evidence = []
    for ref in case.visible_evidence_refs:
        item = dict(evidence_by_ref[ref])
        _reject_hidden_truth_fields(item, f"evidence[{ref}]")
        item.setdefault("evidence_id", ref)
        if item["evidence_id"] != ref:
            raise NetworkHarnessError(
                f"evidence_id mismatch for ref {ref}: {item['evidence_id']!r}"
            )
        evidence.append(item)

    payload = case.visible_contract()
    payload["evidence"] = evidence
    _reject_hidden_truth_fields(payload)
    return payload
