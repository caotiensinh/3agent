from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from three_agent.adaptive_learning_checkpoint import (
    HmacCheckpointKeyring,
    LearningCheckpointAuthority,
    LearningCheckpointError,
    LearningOperatorGateway,
    LearningStagingGateway,
)
from three_agent.adaptive_learning_contract import (
    EvidenceReference,
    ExperienceRecord,
    KnowledgeCandidate,
    LearningValidationReceipt,
)
from three_agent.adaptive_learning_retrieval import (
    LearningRetrievalGateway,
    LearningRetrievalQuery,
)
from three_agent.adaptive_learning_runtime import AdaptiveLearningRuntimeError
from three_agent.adaptive_learning_store import AdaptiveLearningStore
from three_agent.config import AppConfig, GatewayConfig, LLMConfig
from three_agent.orchestrator import Orchestrator

NOW = "2026-08-31T05:20:00Z"
STORE_ID = "learning-store:workspace"
KEY_ID = "key:v1"
KEY = b"phase-4d-production-checkpoint-key-0001"
POSIX_KEY_PROVIDER_ONLY = (
    "Phase 4D production checkpoint key-file provider is intentionally POSIX-only"
)


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _candidate() -> KnowledgeCandidate:
    task_id = "task:phase4d-approved"
    evidence = EvidenceReference(
        ref_id="evidence:phase4d-approved",
        sha256=_hash("phase4d-evidence"),
        source_type="task_artifact",
        source_task_id=task_id,
        sensitivity="confidential",
        collection_mode="offline",
        created_at=NOW,
        vendor_family="workspace",
        version="1",
    )
    experience = ExperienceRecord(
        experience_id="experience:phase4d-approved",
        domain="analyst",
        task_id=task_id,
        outcome="verified_success",
        sensitivity="confidential",
        summary="Verified local analyst experience for production retrieval wiring.",
        evidence=(evidence,),
        created_at=NOW,
    )
    return KnowledgeCandidate.from_experiences(
        candidate_id="knowledge:phase4d-approved",
        domain="analyst",
        kind="analytical_pattern",
        title="Verified gateway diagnosis pattern",
        content="Use the verified local gateway diagnosis evidence before drawing a conclusion.",
        scope="local analyst synthesis only",
        sensitivity="confidential",
        risk_level="medium",
        ownership="learner_managed",
        action="create",
        execution_mode="analysis_only",
        experiences=(experience,),
        created_at=NOW,
    )


def _receipt(candidate: KnowledgeCandidate, level: str) -> LearningValidationReceipt:
    return LearningValidationReceipt(
        receipt_id=f"receipt:phase4d:{level}",
        candidate_id=candidate.candidate_id,
        candidate_sha256=candidate.sha256,
        checks={"SCHEMA": True, "EVIDENCE": True, "SECURITY": True},
        validator_ids=("validator:policy", "validator:evidence"),
        evidence_ref_ids=candidate.evidence_ref_ids,
        evidence_hashes=candidate.evidence_hashes,
        domain_reviewer_id=None,
        human_reviewer_id="reviewer:human" if level == "approved" else None,
        created_at=NOW,
    )


class AdaptiveLearningRuntimeWiringTests(unittest.TestCase):
    @staticmethod
    def _profiles(root: Path) -> Path:
        profiles = root / "profiles"
        profiles.mkdir(parents=True, exist_ok=True)
        source_profiles = Path(__file__).resolve().parents[1] / "profiles"
        for name in ("agent_research.md", "agent_presentation.md", "agent_daily_report.md"):
            (profiles / name).write_text(
                (source_profiles / name).read_text(encoding="utf-8"),
                encoding="utf-8",
            )
        return profiles

    def _config(
        self,
        root: Path,
        *,
        runtime: dict | None = None,
        environment: str = "test",
        confidentiality_mode: str = "confidential",
    ) -> AppConfig:
        raw = {}
        if runtime is not None:
            raw = {"adaptive_learning": {"runtime_retrieval": runtime}}
        return AppConfig(
            environment=environment,
            test_mode_full_access=True,
            database_path=root / "tasks" / "tasks.db",
            artifact_root=root / "artifacts",
            profile_root=self._profiles(root),
            llm=LLMConfig("ollama", "http://127.0.0.1:11434", "", 5),
            internet_gateway=GatewayConfig(True, True, root / "internet.jsonl"),
            execution_gateway=GatewayConfig(True, True, root / "execution.jsonl"),
            raw=raw,
            confidentiality_mode=confidentiality_mode,
        )

    @staticmethod
    def _runtime(paths: dict[str, Path], *, enabled: bool = True, key_path: Path | None = None) -> dict:
        return {
            "enabled": enabled,
            "store_path": str(paths["store"]),
            "checkpoint_journal_path": str(paths["journal"]),
            "trusted_head_witness_path": str(paths["witness"]),
            "store_id": STORE_ID,
            "active_key_id": KEY_ID,
            "key_files": {KEY_ID: str(key_path or paths["key"])},
            "domain": "analyst",
        }

    @staticmethod
    def _learning_paths(root: Path) -> dict[str, Path]:
        return {
            "store": root / "learning" / "learning.db",
            "journal": root / "checkpoint" / "journal.jsonl",
            "witness": root / "trusted-head" / "head.json",
            "key": root / "secrets" / "checkpoint.key",
        }

    def _approved_fixture(self, root: Path) -> dict[str, Path]:
        paths = self._learning_paths(root)
        paths["key"].parent.mkdir(parents=True, exist_ok=True)
        paths["key"].write_bytes(KEY)
        paths["key"].chmod(0o600)

        store = AdaptiveLearningStore(paths["store"])
        authority = LearningCheckpointAuthority(
            paths["journal"],
            paths["witness"],
            HmacCheckpointKeyring({KEY_ID: KEY}, active_key_id=KEY_ID),
            store_id=STORE_ID,
        )
        authority.bootstrap(store)
        learner = LearningStagingGateway(store, authority)
        operator = LearningOperatorGateway(store, authority)
        candidate = _candidate()
        learner.stage(candidate)
        operator.promote(
            candidate.candidate_id,
            target_level="validated",
            receipt=_receipt(candidate, "validated"),
        )
        operator.promote(
            candidate.candidate_id,
            target_level="approved",
            receipt=_receipt(candidate, "approved"),
        )
        return paths

    def test_disabled_default_is_noop_and_does_not_touch_learning_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._learning_paths(root)
            runtime = self._runtime(paths, enabled=False)
            orch = Orchestrator(self._config(root, runtime=runtime))

            self.assertIsNone(orch.learning_retrieval)
            self.assertIsNone(orch.research_agent.learning_retrieval)
            self.assertFalse(paths["store"].exists())
            self.assertFalse(paths["journal"].exists())
            self.assertFalse(paths["witness"].exists())
            self.assertFalse(paths["key"].exists())

    @unittest.skipUnless(os.name == "posix", POSIX_KEY_PROVIDER_ONLY)
    def test_valid_existing_authenticated_store_is_wired_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._approved_fixture(root)
            orch = Orchestrator(self._config(root, runtime=self._runtime(paths)))

            self.assertIsInstance(orch.learning_retrieval, LearningRetrievalGateway)
            self.assertIs(orch.research_agent.learning_retrieval, orch.learning_retrieval)
            self.assertEqual(orch.research_agent.learning_domain, "analyst")
            context = orch.learning_retrieval.retrieve(
                LearningRetrievalQuery(
                    query="gateway diagnosis pattern",
                    domain="analyst",
                    task_sensitivity="confidential",
                )
            )
            self.assertEqual(len(context.items), 1)
            self.assertEqual(context.items[0].item_id, "knowledge:phase4d-approved")

            with self.assertRaises(sqlite3.OperationalError):
                with orch.learning_retrieval._store.connect() as conn:
                    conn.execute("CREATE TABLE phase4d_write_must_fail(x INTEGER)")

    @unittest.skipUnless(os.name == "posix", POSIX_KEY_PROVIDER_ONLY)
    def test_missing_checkpoint_fails_closed_without_auto_bootstrap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._learning_paths(root)
            paths["key"].parent.mkdir(parents=True, exist_ok=True)
            paths["key"].write_bytes(KEY)
            paths["key"].chmod(0o600)
            AdaptiveLearningStore(paths["store"])

            with self.assertRaisesRegex(LearningCheckpointError, "CHECKPOINT_REQUIRED"):
                Orchestrator(self._config(root, runtime=self._runtime(paths)))
            self.assertFalse(paths["journal"].exists())
            self.assertFalse(paths["witness"].exists())

    def test_missing_store_fails_without_creating_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._learning_paths(root)
            paths["key"].parent.mkdir(parents=True, exist_ok=True)
            paths["key"].write_bytes(KEY)
            paths["key"].chmod(0o600)

            with self.assertRaisesRegex(AdaptiveLearningRuntimeError, "LEARNING_STORE_MISSING"):
                Orchestrator(self._config(root, runtime=self._runtime(paths)))
            self.assertFalse(paths["store"].exists())

    @unittest.skipUnless(os.name == "posix", POSIX_KEY_PROVIDER_ONLY)
    def test_wrong_checkpoint_key_fails_startup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._approved_fixture(root)
            wrong = root / "secrets" / "wrong.key"
            wrong.write_bytes(b"wrong-phase-4d-production-key-material-0001")
            wrong.chmod(0o600)

            with self.assertRaisesRegex(LearningCheckpointError, "MAC_MISMATCH"):
                Orchestrator(
                    self._config(root, runtime=self._runtime(paths, key_path=wrong))
                )

    def test_public_research_zone_cannot_mount_adaptive_runtime_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._learning_paths(root)
            runtime = self._runtime(paths)
            with self.assertRaisesRegex(
                AdaptiveLearningRuntimeError,
                "ADAPTIVE_RUNTIME_PUBLIC_RESEARCH_FORBIDDEN",
            ):
                Orchestrator(
                    self._config(
                        root,
                        runtime=runtime,
                        environment="public-research-zone",
                        confidentiality_mode="public-research",
                    )
                )
            self.assertFalse(paths["store"].exists())

    def test_invalid_enabled_domain_fails_before_filesystem_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._learning_paths(root)
            runtime = self._runtime(paths)
            runtime["domain"] = "model_selected"
            with self.assertRaisesRegex(
                AdaptiveLearningRuntimeError,
                "ADAPTIVE_RUNTIME_DOMAIN_INVALID",
            ):
                Orchestrator(self._config(root, runtime=runtime))
            self.assertFalse(paths["store"].exists())

    @unittest.skipUnless(os.name == "posix", POSIX_KEY_PROVIDER_ONLY)
    def test_smoke_exposes_status_only_not_learning_paths_or_key_material(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._approved_fixture(root)
            orch = Orchestrator(self._config(root, runtime=self._runtime(paths)))
            smoke = orch.smoke()
            serialized = json.dumps(smoke, ensure_ascii=False, sort_keys=True)

            self.assertTrue(smoke["adaptive_learning_retrieval_enabled"])
            self.assertEqual(smoke["adaptive_learning_retrieval_domain"], "analyst")
            for path in paths.values():
                self.assertNotIn(str(path), serialized)
            self.assertNotIn(KEY.decode("ascii"), serialized)

    @unittest.skipUnless(os.name == "posix", POSIX_KEY_PROVIDER_ONLY)
    def test_research_agent_receives_no_learning_mutation_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._approved_fixture(root)
            orch = Orchestrator(self._config(root, runtime=self._runtime(paths)))
            gateway = orch.research_agent.learning_retrieval
            self.assertIsNotNone(gateway)
            for method in (
                "stage",
                "promote",
                "archive",
                "rollback",
                "rotate_key",
                "bootstrap",
                "sign",
            ):
                self.assertFalse(hasattr(gateway, method), method)

    @unittest.skipIf(os.name == "posix", "non-POSIX fail-closed contract")
    def test_enabled_runtime_fails_closed_on_non_posix_without_key_provider_invention(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._learning_paths(root)
            paths["key"].parent.mkdir(parents=True, exist_ok=True)
            paths["key"].write_bytes(KEY)
            AdaptiveLearningStore(paths["store"])

            with self.assertRaisesRegex(
                LearningCheckpointError,
                "CHECKPOINT_KEY_FILE_PROVIDER_POSIX_ONLY",
            ):
                Orchestrator(self._config(root, runtime=self._runtime(paths)))

            self.assertTrue(paths["store"].exists())
            self.assertFalse(paths["journal"].exists())
            self.assertFalse(paths["witness"].exists())


if __name__ == "__main__":
    unittest.main()
