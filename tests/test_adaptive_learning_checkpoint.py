from __future__ import annotations

import json
import shutil
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
from three_agent.adaptive_learning_store import AdaptiveLearningStore

NOW = "2026-08-31T03:30:00Z"
H1 = "sha256:" + "1" * 64
STORE_ID = "learning-store:default"
OLD_KEY = b"old-checkpoint-key-material-0001"
NEW_KEY = b"new-checkpoint-key-material-0002"


def approved_candidate() -> tuple[
    KnowledgeCandidate,
    LearningValidationReceipt,
    LearningValidationReceipt,
]:
    evidence = EvidenceReference(
        ref_id="evidence:checkpoint",
        sha256=H1,
        source_type="syslog",
        source_task_id="task:checkpoint",
        sensitivity="confidential",
        collection_mode="passive",
        created_at=NOW,
        vendor_family="Cisco CBS250",
        version="3.x",
    )
    experience = ExperienceRecord(
        experience_id="experience:checkpoint",
        domain="network",
        task_id="task:checkpoint",
        outcome="verified_success",
        sensitivity="confidential",
        summary="Verified passive read-only analysis sequence for checkpoint tests.",
        evidence=(evidence,),
        created_at=NOW,
    )
    candidate = KnowledgeCandidate.from_experiences(
        candidate_id="candidate:checkpoint",
        domain="network",
        kind="skill",
        title="Checkpoint protected network analysis",
        content="Correlate passive evidence and preserve uncertainty before conclusion.",
        scope="offline-read-only-analysis",
        sensitivity="confidential",
        risk_level="high",
        ownership="learner_managed",
        action="create",
        execution_mode="read_only",
        experiences=(experience,),
        created_at=NOW,
    )

    def receipt(receipt_id: str, *, reviewed: bool) -> LearningValidationReceipt:
        return LearningValidationReceipt(
            receipt_id=receipt_id,
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
            checks={"SCHEMA": True, "EVIDENCE": True, "SECURITY": True},
            validator_ids=("validator:policy", "validator:evidence"),
            evidence_ref_ids=candidate.evidence_ref_ids,
            evidence_hashes=candidate.evidence_hashes,
            domain_reviewer_id="reviewer:network" if reviewed else None,
            human_reviewer_id="reviewer:human" if reviewed else None,
            created_at=NOW,
        )

    return candidate, receipt("receipt:checkpoint:validated", reviewed=False), receipt(
        "receipt:checkpoint:approved", reviewed=True
    )


def keyring(*, active: str = "key:v1", include_old: bool = True, include_new: bool = False):
    keys: dict[str, bytes] = {}
    if include_old:
        keys["key:v1"] = OLD_KEY
    if include_new:
        keys["key:v2"] = NEW_KEY
    return HmacCheckpointKeyring(keys, active_key_id=active)


class AdaptiveLearningCheckpointTests(unittest.TestCase):
    def _environment(self, root: Path):
        store = AdaptiveLearningStore(root / "learning.db")
        authority = LearningCheckpointAuthority(
            root / "checkpoint" / "learning-checkpoints.jsonl",
            keyring(),
            store_id=STORE_ID,
        )
        authority.bootstrap(store)
        return store, authority

    def test_bootstrap_and_checkpointed_stage_promote(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, authority = self._environment(root)
            candidate, validated_receipt, approved_receipt = approved_candidate()
            learner = LearningStagingGateway(store, authority)
            operator = LearningOperatorGateway(store, authority)

            bootstrap = authority.verify(store)
            self.assertEqual(bootstrap.sequence, 1)
            self.assertEqual(bootstrap.mutation_kind, "bootstrap")

            learner.stage(candidate)
            after_stage = operator.verify()
            self.assertEqual(after_stage.sequence, 2)
            self.assertEqual(after_stage.mutation_kind, "stage")

            operator.promote(
                candidate.candidate_id,
                target_level="validated",
                receipt=validated_receipt,
            )
            self.assertEqual(operator.verify().sequence, 3)

            operator.promote(
                candidate.candidate_id,
                target_level="approved",
                receipt=approved_receipt,
            )
            final = operator.verify()
            self.assertEqual(final.sequence, 4)
            self.assertEqual(final.mutation_kind, "promote")
            self.assertIsNotNone(store.active(candidate.candidate_id))

            journal = authority.journal_path.read_text(encoding="utf-8")
            self.assertNotIn(candidate.content, journal)
            self.assertNotIn("Verified passive read-only analysis sequence", journal)
            self.assertNotIn(OLD_KEY.decode("ascii"), journal)

    def test_startup_requires_authenticated_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = AdaptiveLearningStore(root / "learning.db")
            authority = LearningCheckpointAuthority(
                root / "checkpoint.jsonl",
                keyring(),
                store_id=STORE_ID,
            )
            with self.assertRaisesRegex(LearningCheckpointError, "CHECKPOINT_REQUIRED"):
                LearningStagingGateway(store, authority)
            with self.assertRaisesRegex(LearningCheckpointError, "CHECKPOINT_REQUIRED"):
                LearningOperatorGateway(store, authority)

    def test_partial_ledger_tamper_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, authority = self._environment(root)
            candidate, _, _ = approved_candidate()
            LearningStagingGateway(store, authority).stage(candidate)

            with store.connect() as conn:
                conn.execute("DROP TRIGGER learning_ledger_no_update")
                conn.execute(
                    "UPDATE learning_ledger SET reason_code='FORGED' WHERE seq=2"
                )

            with self.assertRaisesRegex(
                LearningCheckpointError, "LEARNING_LEDGER_INTEGRITY_FAILED"
            ):
                authority.verify(store)

    def test_version_tamper_with_unchanged_ledger_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, authority = self._environment(root)
            candidate, _, _ = approved_candidate()
            LearningStagingGateway(store, authority).stage(candidate)
            self.assertTrue(store.verify_ledger()["passed"])

            tampered = dict(candidate.to_payload())
            tampered["title"] = "Tampered checkpoint candidate"
            with store.connect() as conn:
                conn.execute("DROP TRIGGER learning_versions_no_update")
                conn.execute(
                    "UPDATE learning_versions SET candidate_json=? WHERE candidate_id=?",
                    (json.dumps(tampered, sort_keys=True), candidate.candidate_id),
                )

            self.assertTrue(store.verify_ledger()["passed"])
            with self.assertRaisesRegex(
                LearningCheckpointError, "LEARNING_VERSION_INTEGRITY_FAILED"
            ):
                authority.verify(store)

    def test_complete_database_rewrite_without_checkpoint_key_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "learning.db"
            store, authority = self._environment(root)
            candidate, _, _ = approved_candidate()
            LearningStagingGateway(store, authority).stage(candidate)
            authority.verify(store)

            db_path.unlink()
            rewritten = AdaptiveLearningStore(db_path)
            self.assertTrue(rewritten.verify_ledger()["passed"])
            with self.assertRaisesRegex(
                LearningCheckpointError, "CHECKPOINT_STORE_STATE_MISMATCH"
            ):
                authority.verify(rewritten)

    def test_stale_database_restore_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "learning.db"
            stale_path = root / "stale.db"
            store, authority = self._environment(root)

            source = sqlite3.connect(db_path)
            destination = sqlite3.connect(stale_path)
            try:
                source.backup(destination)
            finally:
                destination.close()
                source.close()

            candidate, _, _ = approved_candidate()
            LearningStagingGateway(store, authority).stage(candidate)
            latest = authority.verify(store)
            self.assertEqual(latest.sequence, 2)

            shutil.copyfile(stale_path, db_path)
            restored = AdaptiveLearningStore(db_path)
            self.assertTrue(restored.verify_ledger()["passed"])
            with self.assertRaisesRegex(
                LearningCheckpointError, "CHECKPOINT_STORE_STATE_MISMATCH"
            ):
                authority.verify(restored)

    def test_wrong_and_missing_keys_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, authority = self._environment(root)
            authority.verify(store)

            wrong = LearningCheckpointAuthority(
                authority.journal_path,
                HmacCheckpointKeyring({"key:v1": b"x" * 32}, active_key_id="key:v1"),
                store_id=STORE_ID,
            )
            with self.assertRaisesRegex(LearningCheckpointError, "CHECKPOINT_MAC_MISMATCH"):
                wrong.verify(store)

            missing = LearningCheckpointAuthority(
                authority.journal_path,
                HmacCheckpointKeyring({"key:v2": NEW_KEY}, active_key_id="key:v2"),
                store_id=STORE_ID,
            )
            with self.assertRaisesRegex(
                LearningCheckpointError, "CHECKPOINT_KEY_MISSING:key:v1"
            ):
                missing.verify(store)

    def test_key_rotation_allows_old_secret_removal_and_detects_history_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, old_authority = self._environment(root)
            candidate, _, _ = approved_candidate()
            LearningStagingGateway(store, old_authority).stage(candidate)

            rotating = LearningCheckpointAuthority(
                old_authority.journal_path,
                keyring(active="key:v2", include_old=True, include_new=True),
                store_id=STORE_ID,
            )
            rotated = rotating.rotate_key(store)
            self.assertEqual(rotated.key_id, "key:v2")
            self.assertEqual(rotated.mutation_kind, "key_rotation")

            new_only = LearningCheckpointAuthority(
                old_authority.journal_path,
                keyring(active="key:v2", include_old=False, include_new=True),
                store_id=STORE_ID,
            )
            self.assertEqual(new_only.verify(store).checkpoint_sha256, rotated.checkpoint_sha256)

            lines = old_authority.journal_path.read_text(encoding="utf-8").splitlines()
            first = json.loads(lines[0])
            first["mutation_kind"] = "stage"
            lines[0] = json.dumps(first, sort_keys=True, separators=(",", ":"))
            old_authority.journal_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            if hasattr(old_authority.journal_path, "chmod"):
                old_authority.journal_path.chmod(0o600)

            with self.assertRaisesRegex(LearningCheckpointError, "CHECKPOINT_HASH_MISMATCH"):
                new_only.verify(store)

    def test_learner_gateway_exposes_stage_only_and_fixed_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, authority = self._environment(root)
            candidate, _, _ = approved_candidate()
            learner = LearningStagingGateway(store, authority)

            public = {
                name
                for name in dir(learner)
                if not name.startswith("_") and callable(getattr(learner, name))
            }
            self.assertEqual(public, {"stage"})
            learner.stage(candidate)
            last = store.ledger()[-1]
            self.assertEqual(last["actor_id"], "learner:reflection")
            self.assertEqual(last["reason_code"], "CANDIDATE_STAGED")
            for forbidden in ("promote", "verify", "rotate_key", "sign", "archive", "rollback"):
                self.assertFalse(hasattr(learner, forbidden))


if __name__ == "__main__":
    unittest.main()
