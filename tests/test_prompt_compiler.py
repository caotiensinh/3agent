from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from three_agent.prompt_compiler import PromptCompilationError, PromptCompiler
from three_agent.prompt_ledger import PromptCompilationLedger
from three_agent.public_query_compiler import (
    compile_public_search_queries,
    compile_public_search_query,
)
from three_agent.privacy import assess_public_egress_text
from three_agent.store import TaskStore


class PromptCompilerTests(unittest.TestCase):
    def test_local_compiler_preserves_credentials_and_unique_context(self) -> None:
        raw = (
            "Troubleshoot Ollama login failure.\n\n"
            "username: administrator\n"
            "password: SuperSecret-123456\n"
            "Host is 192.168.11.112. Do not reboot the server."
        )
        result = PromptCompiler.compile(raw)
        self.assertIn("administrator", result.compiled_text)
        self.assertIn("SuperSecret-123456", result.compiled_text)
        self.assertIn("192.168.11.112", result.compiled_text)
        self.assertIn("Do not reboot", result.compiled_text)
        self.assertNotIn("compiled_text", result.metadata())
        self.assertFalse(result.metadata()["token_savings_measured"])

    def test_exact_repeated_prose_block_is_compacted_but_emphasis_is_retained(self) -> None:
        block = "Do not reboot this production server because active workloads are running."
        raw = f"Investigate the failure.\n\n{block}\n\n{block}\n\n{block}"
        result = PromptCompiler.compile(raw)
        self.assertEqual(result.compiled_text.count(block), 1)
        self.assertIn("identical_block_count=3", result.compiled_text)
        self.assertEqual(result.duplicate_blocks_removed, 2)
        self.assertLess(result.compiled_utf8_bytes, result.original_utf8_bytes)

    def test_fenced_code_is_not_deduplicated_or_rewritten(self) -> None:
        code = "```bash\nexport PASSWORD='a b c'\necho \"$PASSWORD\"\n```"
        result = PromptCompiler.compile(f"Check this:\n\n{code}\n\n{code}")
        self.assertEqual(result.compiled_text.count(code), 2)

    def test_short_prompt_is_never_inflated_by_compiler_metadata(self) -> None:
        raw = "Explain Python dictionaries."
        result = PromptCompiler.compile(raw)
        self.assertEqual(result.compiled_text, raw)
        self.assertLessEqual(result.compiled_utf8_bytes, result.original_utf8_bytes)

    def test_empty_prompt_fails_closed(self) -> None:
        with self.assertRaises(PromptCompilationError):
            PromptCompiler.compile("   \n\n")


class PromptCompilationLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "tasks.db"
        self.store = TaskStore(self.db)
        self.store.initialize()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_ledger_connection_is_closed_after_context_scope(self) -> None:
        ledger = PromptCompilationLedger(self.store)
        conn = ledger.connect()
        with conn as active:
            active.execute("SELECT 1").fetchone()
        with self.assertRaises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")

    def test_receipt_is_metadata_only_and_original_task_stays_unchanged(self) -> None:
        raw = "password: LocalOnlySecret-12345\n\nAnalyze authentication failure."
        task = self.store.create_task("Auth", raw)
        ledger = PromptCompilationLedger(self.store)
        result = ledger.compile_and_bind(task.task_id)
        self.assertIn("LocalOnlySecret-12345", result.compiled_text)
        self.assertEqual(self.store.get_task(task.task_id).request, raw)
        record = ledger.get(task.task_id)
        self.assertIsNotNone(record)
        serialized = " ".join(f"{key}={value}" for key, value in record.items())
        self.assertNotIn("LocalOnlySecret-12345", serialized)
        self.assertNotIn(raw, serialized)
        self.assertEqual(record["token_savings_measured"], 0)

    def test_changed_original_after_binding_is_rejected(self) -> None:
        task = self.store.create_task("Immutable", "Original request")
        ledger = PromptCompilationLedger(self.store)
        ledger.compile_and_bind(task.task_id)
        with sqlite3.connect(self.db) as conn:
            conn.execute(
                "UPDATE tasks SET request=? WHERE task_id=?",
                ("Changed request", task.task_id),
            )
        with self.assertRaises(PromptCompilationError):
            ledger.compile_and_bind(task.task_id)


class PublicQueryCompilerTests(unittest.TestCase):
    def test_credentials_private_ip_and_token_are_removed_before_egress(self) -> None:
        raw = (
            "Ollama connection refused Ubuntu 24.04 "
            "username=administrator password=SuperSecret-123456 "
            "host 192.168.11.112 ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        )
        result = compile_public_search_query(raw)
        self.assertTrue(result.allowed)
        self.assertIn("Ollama", result.query)
        self.assertIn("Ubuntu 24.04", result.query)
        self.assertNotIn("administrator", result.query)
        self.assertNotIn("SuperSecret", result.query)
        self.assertNotIn("192.168.11.112", result.query)
        self.assertNotIn("ghp_", result.query)
        self.assertGreater(result.removed_sensitive_fields, 0)
        self.assertTrue(assess_public_egress_text(result.query).allowed)

    def test_private_key_is_removed_while_public_problem_statement_survives(self) -> None:
        raw = (
            "SSH public key authentication permission denied\n"
            "-----BEGIN PRIVATE KEY-----\n"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            "-----END PRIVATE KEY-----"
        )
        result = compile_public_search_query(raw)
        self.assertTrue(result.allowed)
        self.assertIn("SSH public key authentication permission denied", result.query)
        self.assertNotIn("PRIVATE KEY", result.query)
        self.assertNotIn("AAAA", result.query)

    def test_sensitive_only_input_is_blocked_instead_of_sending_placeholders(self) -> None:
        result = compile_public_search_query(
            "username=administrator password=SuperSecret-123456 192.168.11.112"
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.query, "")

    def test_multiple_queries_are_deduplicated_after_sanitization(self) -> None:
        queries, diagnostics = compile_public_search_queries(
            [
                "Ollama connection refused password=aaaabbbbccccdddd",
                "Ollama connection refused password=xxxxaaaabbbbcccc",
            ]
        )
        self.assertEqual(queries, ["Ollama connection refused"])
        self.assertTrue(any("sanitized" in item for item in diagnostics))


if __name__ == "__main__":
    unittest.main()
