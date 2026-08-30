from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from three_agent.adaptive_learning_store import (
    AdaptiveLearningStore,
    AdaptiveLearningStoreError,
    GENESIS_HASH,
    LEDGER_SCHEMA,
)

NOW = "2026-08-31T03:30:00Z"
H1 = "sha256:" + "1" * 64


class AdaptiveLearningStoreIntegrityTests(unittest.TestCase):
    def test_forged_ledger_row_blocks_active_read_and_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AdaptiveLearningStore(Path(tmp) / "learning.db")
            with store.connect() as conn:
                conn.execute(
                    """
                    INSERT INTO learning_ledger(
                        schema_version,event_id,event_type,item_id,candidate_id,candidate_sha256,
                        knowledge_sha256,before_sha256,after_sha256,validation_receipt_sha256,
                        source_experience_hashes_json,evidence_hashes_json,actor_id,reason_code,
                        timestamp,previous_entry_sha256,entry_sha256
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        LEDGER_SCHEMA,
                        "learning-event:forged",
                        "archive",
                        "candidate:forged",
                        None,
                        None,
                        H1,
                        H1,
                        None,
                        None,
                        "[]",
                        "[]",
                        "attacker:local",
                        "FORGED",
                        NOW,
                        GENESIS_HASH,
                        H1,
                    ),
                )

            verification = store.verify_ledger()
            self.assertFalse(verification["passed"])
            self.assertTrue(
                any(code.startswith("ENTRY_HASH_MISMATCH") for code in verification["failures"])
            )

            with self.assertRaisesRegex(
                AdaptiveLearningStoreError, "LEARNING_LEDGER_INTEGRITY_FAILED"
            ):
                store.active("candidate:forged")

            with self.assertRaisesRegex(
                AdaptiveLearningStoreError, "LEARNING_LEDGER_INTEGRITY_FAILED"
            ):
                store.archive(
                    "candidate:forged",
                    expected_current_sha256=H1,
                )


if __name__ == "__main__":
    unittest.main()
