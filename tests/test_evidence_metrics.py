import tempfile
import unittest
from pathlib import Path

from three_agent.artifacts import ArtifactManager
from three_agent.evidence_metrics import EvidenceCoverageAggregator
from three_agent.research_quality import evidence_claim_accounting
from three_agent.store import TaskStore


class EvidenceCoverageTests(unittest.TestCase):
    def test_claim_accounting_counts_only_explicit_material_claim_candidates(self):
        research = {
            "verified_facts": [
                {"claim": "F1", "source_ids": ["S1"]},
                {"claim": "F2", "source_ids": ["S2"]},
            ],
            "inferences": [{"claim": "I1", "source_ids": ["S1", "S2"]}],
            "unresolved_items": [
                "Uncited model claim rejected: unsupported fact",
                "Uncited model inference rejected: unsupported inference",
                "Core requirement unresolved: geography",
                "Generic open question",
            ],
            "rejected_numeric_claims": ["Unsupported 99% claim"],
        }
        metric = evidence_claim_accounting(research)
        self.assertEqual(metric["evidence_supported_material_claims"], 3)
        self.assertEqual(metric["unsupported_material_claims"], 3)
        self.assertEqual(metric["material_claims_requiring_evidence"], 6)
        self.assertEqual(metric["uncited_rejected_material_claims"], 2)
        self.assertEqual(metric["quantitative_rejected_material_claims"], 1)
        self.assertEqual(metric["evidence_coverage"], 0.5)

    def test_constraint_gaps_and_generic_unresolved_are_not_fabricated_as_claims(self):
        metric = evidence_claim_accounting(
            {
                "verified_facts": [],
                "inferences": [],
                "unresolved_items": [
                    "Core requirement unresolved: latest",
                    "No source passed the source suitability gate for this task.",
                ],
                "rejected_numeric_claims": [],
            }
        )
        self.assertEqual(metric["material_claims_requiring_evidence"], 0)
        self.assertIsNone(metric["evidence_coverage"])

    def test_aggregator_sums_claims_before_computing_ratio(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TaskStore(root / "tasks.db")
            store.initialize()
            artifacts = ArtifactManager(root / "data")
            first = store.create_task("A", "A")
            second = store.create_task("B", "B")
            artifacts.write_research_handoff(
                first.task_id,
                {
                    "quality_metrics": {
                        "material_claims_requiring_evidence": 4,
                        "evidence_supported_material_claims": 2,
                        "unsupported_material_claims": 2,
                    }
                },
            )
            artifacts.write_research_handoff(
                second.task_id,
                {
                    "quality_metrics": {
                        "material_claims_requiring_evidence": 3,
                        "evidence_supported_material_claims": 3,
                        "unsupported_material_claims": 0,
                    }
                },
            )
            result = EvidenceCoverageAggregator(store, artifacts).snapshot()
            self.assertEqual(result.material_claims_requiring_evidence, 7)
            self.assertEqual(result.evidence_supported_material_claims, 5)
            self.assertEqual(result.unsupported_material_claims, 2)
            self.assertEqual(result.evidence_coverage, 0.714286)
            self.assertEqual(result.tasks_with_claim_accounting, 2)

    def test_missing_and_inconsistent_handoffs_are_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TaskStore(root / "tasks.db")
            store.initialize()
            artifacts = ArtifactManager(root / "data")
            missing = store.create_task("Missing", "Missing")
            bad = store.create_task("Bad", "Bad")
            artifacts.write_research_handoff(
                bad.task_id,
                {
                    "quality_metrics": {
                        "material_claims_requiring_evidence": 5,
                        "evidence_supported_material_claims": 4,
                        "unsupported_material_claims": 0,
                    }
                },
            )
            result = EvidenceCoverageAggregator(store, artifacts).snapshot(
                [missing.task_id, bad.task_id]
            )
            self.assertEqual(result.tasks_with_claim_accounting, 0)
            self.assertEqual(result.tasks_without_claim_accounting, 2)
            self.assertEqual(result.malformed_handoffs, 1)
            self.assertIsNone(result.evidence_coverage)

    def test_metric_payload_is_versioned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TaskStore(root / "tasks.db")
            store.initialize()
            payload = EvidenceCoverageAggregator(
                store, ArtifactManager(root / "data")
            ).snapshot([]).to_dict()
            self.assertEqual(payload["schema_version"], "workspace-evidence-coverage/v1")
            self.assertIn("tasks_without_claim_accounting", payload)


if __name__ == "__main__":
    unittest.main()
