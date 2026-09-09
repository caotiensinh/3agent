from __future__ import annotations

import json
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path

from three_agent.secure_memory import SecureMemoryStore


class SecureMemoryStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "memory.sqlite3"

    def tearDown(self):
        self.tmp.cleanup()

    def test_mutation_is_denied_without_approval(self):
        store = SecureMemoryStore(self.db)
        with self.assertRaisesRegex(PermissionError, "MEMORY_MUTATION_APPROVAL_REQUIRED"):
            store.put("project:a", "owner", {"name": "alice"}, actor="agent")

    def test_namespace_isolation_and_deterministic_id(self):
        store = SecureMemoryStore(self.db)
        a, _ = store.put("a", "same", {"v": 1}, actor="agent", approved_by="operator")
        b, _ = store.put("b", "same", {"v": 2}, actor="agent", approved_by="operator")
        self.assertNotEqual(a.record_id, b.record_id)
        self.assertEqual(store.get("a", "same").value, {"v": 1})
        self.assertEqual(store.get("b", "same").value, {"v": 2})
        self.assertEqual(a.record_id, store.record_id_for("a", "same"))

    def test_query_is_bounded_by_records_and_bytes(self):
        store = SecureMemoryStore(self.db, max_records=2, max_bytes=10_000)
        for i in range(4):
            store.put("n", f"k{i}", {"value": "x" * 20}, actor="agent", approved_by="operator")
        self.assertEqual(len(store.query("n", limit=50)), 2)
        self.assertEqual(len(store.query("n", max_bytes=1)), 0)

    def test_managed_connection_closes_sqlite_handle(self):
        store = SecureMemoryStore(self.db)
        with store._connection() as conn:
            self.assertEqual(conn.execute("SELECT 1").fetchone()[0], 1)
        with self.assertRaises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")

    def test_ttl_expiry_and_purge_produces_receipt(self):
        store = SecureMemoryStore(self.db)
        store.put("n", "short", "value", actor="agent", approved_by="operator", ttl_seconds=1)
        time.sleep(1.05)
        self.assertIsNone(store.get("n", "short"))
        self.assertEqual(store.purge_expired(), 1)
        self.assertEqual(store.list_receipts()[-1].action, "expire")
        self.assertTrue(store.verify_audit_chain())

    def test_record_tamper_is_detected(self):
        store = SecureMemoryStore(self.db)
        record, _ = store.put("n", "k", {"safe": True}, actor="agent", approved_by="operator")
        with closing(sqlite3.connect(self.db)) as conn:
            with conn:
                conn.execute(
                    "UPDATE secure_memory_records SET value_json=? WHERE record_id=?",
                    (json.dumps({"safe": False}), record.record_id),
                )
        with self.assertRaisesRegex(RuntimeError, "MEMORY_RECORD_INTEGRITY_FAILED"):
            store.get("n", "k")

    def test_receipt_chain_detects_tamper(self):
        store = SecureMemoryStore(self.db)
        store.put("n", "a", 1, actor="agent", approved_by="operator")
        store.put("n", "b", 2, actor="agent", approved_by="operator")
        self.assertTrue(store.verify_audit_chain())
        with closing(sqlite3.connect(self.db)) as conn:
            with conn:
                conn.execute("UPDATE secure_memory_receipts SET result='tampered' WHERE sequence=1")
        self.assertFalse(store.verify_audit_chain())

    def test_policy_can_authorize_exact_mutation(self):
        calls = []

        def policy(action, namespace, key, actor):
            calls.append((action, namespace, key, actor))
            return namespace == "approved"

        store = SecureMemoryStore(self.db, approval_policy=policy)
        record, receipt = store.put("approved", "k", 1, actor="agent")
        self.assertEqual(record.value, 1)
        self.assertEqual(receipt.approved_by, "policy")
        self.assertEqual(calls, [("put", "approved", "k", "agent")])


if __name__ == "__main__":
    unittest.main()
