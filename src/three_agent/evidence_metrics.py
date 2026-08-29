from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable, Any

from .artifacts import ArtifactManager
from .store import TaskStore


@dataclass(frozen=True)
class EvidenceCoverageMetrics:
    selected_tasks: int
    tasks_with_claim_accounting: int
    tasks_without_claim_accounting: int
    malformed_handoffs: int
    material_claims_requiring_evidence: int
    evidence_supported_material_claims: int
    unsupported_material_claims: int
    evidence_coverage: float | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "workspace-evidence-coverage/v1",
            "selected_tasks": self.selected_tasks,
            "tasks_with_claim_accounting": self.tasks_with_claim_accounting,
            "tasks_without_claim_accounting": self.tasks_without_claim_accounting,
            "malformed_handoffs": self.malformed_handoffs,
            "material_claims_requiring_evidence": self.material_claims_requiring_evidence,
            "evidence_supported_material_claims": self.evidence_supported_material_claims,
            "unsupported_material_claims": self.unsupported_material_claims,
            "evidence_coverage": self.evidence_coverage,
        }


class EvidenceCoverageAggregator:
    """Aggregate D3-05 from deterministic Research handoff claim accounting.

    The aggregator never re-reads prose to decide whether a statement is supported.
    It consumes only explicit claim-accounting integers produced by the Research
    evidence gates. Task-level percentages are not averaged; claim counts are
    summed first, then one aggregate coverage ratio is computed.
    """

    def __init__(self, store: TaskStore, artifacts: ArtifactManager):
        self.store = store
        self.artifacts = artifacts

    @staticmethod
    def _count(value: Any) -> int | None:
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        return None

    def snapshot(self, task_ids: Iterable[str] | None = None) -> EvidenceCoverageMetrics:
        if task_ids is None:
            selected = [task.task_id for task in self.store.list_tasks()]
        else:
            selected = list(
                dict.fromkeys(
                    str(task_id).strip()
                    for task_id in task_ids
                    if str(task_id).strip()
                )
            )
            for task_id in selected:
                self.store.get_task(task_id)

        with_accounting = 0
        without_accounting = 0
        malformed = 0
        required_total = 0
        supported_total = 0
        unsupported_total = 0

        for task_id in selected:
            path = self.artifacts.find_latest_task_artifact(
                "research", task_id, suffix="_handoff.json"
            )
            if path is None:
                without_accounting += 1
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                malformed += 1
                without_accounting += 1
                continue
            if not isinstance(payload, dict):
                malformed += 1
                without_accounting += 1
                continue
            quality = payload.get("quality_metrics")
            if not isinstance(quality, dict):
                without_accounting += 1
                continue
            required = self._count(quality.get("material_claims_requiring_evidence"))
            supported = self._count(quality.get("evidence_supported_material_claims"))
            unsupported = self._count(quality.get("unsupported_material_claims"))
            if (
                required is None
                or supported is None
                or unsupported is None
                or supported + unsupported != required
            ):
                malformed += 1
                without_accounting += 1
                continue
            with_accounting += 1
            required_total += required
            supported_total += supported
            unsupported_total += unsupported

        coverage = round(supported_total / required_total, 6) if required_total else None
        return EvidenceCoverageMetrics(
            selected_tasks=len(selected),
            tasks_with_claim_accounting=with_accounting,
            tasks_without_claim_accounting=without_accounting,
            malformed_handoffs=malformed,
            material_claims_requiring_evidence=required_total,
            evidence_supported_material_claims=supported_total,
            unsupported_material_claims=unsupported_total,
            evidence_coverage=coverage,
        )
