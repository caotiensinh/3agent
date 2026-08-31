from __future__ import annotations

import ast
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import three_agent.adaptive_learning_lifecycle as lifecycle_module
from three_agent.adaptive_learning_checkpoint import LearningCheckpointError
from three_agent.adaptive_learning_lifecycle import (
    AdaptiveLearningLifecycleError,
    bootstrap_learning_store,
    verify_learning_store,
)
from three_agent.adaptive_learning_runtime import build_runtime_learning_binding


STORE_ID = "learning-store:phase4f"
KEY_ID = "key:v1"


class AdaptiveLearningLifecycleTests(unittest.TestCase):
    @staticmethod
    def _paths(root: Path) -> dict[str, Path]:
        return {
            "store_path": root / "store" / "learning.db",
            "journal_path": root / "checkpoint" / "journal.jsonl",
            "witness_path": root / "trusted-head" / "head.json",
            "key_path": root / "keys" / "checkpoint.key",
        }

    def test_fresh_bootstrap_creates_private_authenticated_generation(self):
        if os.name != "posix":
            self.skipTest("Phase 4F raw file key provider is POSIX-only")
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(Path(tmp))
            receipt = bootstrap_learning_store(**paths, store_id=STORE_ID, key_id=KEY_ID)
            verified = verify_learning_store(**paths, store_id=STORE_ID, key_id=KEY_ID)

            self.assertEqual(receipt["schema_version"], "workspace-adaptive-learning-bootstrap/v1")
            self.assertEqual(verified["schema_version"], "workspace-adaptive-learning-bootstrap-verify/v1")
            self.assertEqual(receipt["checkpoint_sequence"], 1)
            self.assertEqual(receipt["checkpoint_sha256"], verified["checkpoint_sha256"])
            self.assertEqual(receipt["state_sha256"], verified["state_sha256"])
            self.assertEqual(receipt["ledger_entry_count"], 0)
            self.assertEqual(receipt["version_count"], 0)
            for path in paths.values():
                self.assertTrue(path.is_file())
                self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0)
            self.assertGreaterEqual(paths["key_path"].stat().st_size, 32)

    def test_receipt_is_metadata_only_and_never_contains_path_key_or_mac(self):
        if os.name != "posix":
            self.skipTest("POSIX-only")
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(Path(tmp))
            receipt = bootstrap_learning_store(**paths, store_id=STORE_ID, key_id=KEY_ID)
            serialized = json.dumps(receipt, sort_keys=True)
            for path in paths.values():
                self.assertNotIn(str(path), serialized)
            self.assertNotIn("mac", serialized.lower())
            self.assertNotIn(paths["key_path"].read_bytes().hex(), serialized)
            self.assertEqual(
                set(receipt),
                {
                    "schema_version",
                    "store_id",
                    "key_id",
                    "checkpoint_sequence",
                    "checkpoint_sha256",
                    "state_sha256",
                    "ledger_entry_count",
                    "version_count",
                },
            )

    def test_existing_any_target_blocks_before_first_mutation(self):
        if os.name != "posix":
            self.skipTest("POSIX-only")
        for existing_name in ("store_path", "journal_path", "witness_path", "key_path"):
            with self.subTest(existing=existing_name), tempfile.TemporaryDirectory() as tmp:
                paths = self._paths(Path(tmp))
                target = paths[existing_name]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"preexisting")
                before = target.read_bytes()
                with self.assertRaisesRegex(AdaptiveLearningLifecycleError, "TARGET_EXISTS"):
                    bootstrap_learning_store(**paths, store_id=STORE_ID, key_id=KEY_ID)
                self.assertEqual(target.read_bytes(), before)
                for name, path in paths.items():
                    if name != existing_name:
                        self.assertFalse(path.exists(), name)

    def test_path_collision_is_rejected_before_mutation(self):
        if os.name != "posix":
            self.skipTest("POSIX-only")
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(Path(tmp))
            paths["witness_path"] = paths["journal_path"]
            with self.assertRaisesRegex(AdaptiveLearningLifecycleError, "PATH_COLLISION"):
                bootstrap_learning_store(**paths, store_id=STORE_ID, key_id=KEY_ID)
            self.assertFalse(paths["store_path"].exists())
            self.assertFalse(paths["key_path"].exists())

    def test_second_bootstrap_never_rebaselines_existing_generation(self):
        if os.name != "posix":
            self.skipTest("POSIX-only")
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(Path(tmp))
            first = bootstrap_learning_store(**paths, store_id=STORE_ID, key_id=KEY_ID)
            with self.assertRaisesRegex(AdaptiveLearningLifecycleError, "TARGET_EXISTS"):
                bootstrap_learning_store(**paths, store_id=STORE_ID, key_id=KEY_ID)
            second = verify_learning_store(**paths, store_id=STORE_ID, key_id=KEY_ID)
            self.assertEqual(first["checkpoint_sha256"], second["checkpoint_sha256"])
            self.assertEqual(second["checkpoint_sequence"], 1)

    def test_verify_is_read_only_and_repeatable(self):
        if os.name != "posix":
            self.skipTest("POSIX-only")
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(Path(tmp))
            bootstrap_learning_store(**paths, store_id=STORE_ID, key_id=KEY_ID)
            before = {name: path.read_bytes() for name, path in paths.items()}
            first = verify_learning_store(**paths, store_id=STORE_ID, key_id=KEY_ID)
            second = verify_learning_store(**paths, store_id=STORE_ID, key_id=KEY_ID)
            after = {name: path.read_bytes() for name, path in paths.items()}
            self.assertEqual(first, second)
            self.assertEqual(before, after)

    def test_tampered_store_or_wrong_key_fails_verification(self):
        if os.name != "posix":
            self.skipTest("POSIX-only")
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(Path(tmp))
            bootstrap_learning_store(**paths, store_id=STORE_ID, key_id=KEY_ID)
            original_key = paths["key_path"].read_bytes()
            paths["key_path"].write_bytes(b"x" * 32)
            paths["key_path"].chmod(0o600)
            with self.assertRaises(LearningCheckpointError):
                verify_learning_store(**paths, store_id=STORE_ID, key_id=KEY_ID)
            paths["key_path"].write_bytes(original_key)
            paths["key_path"].chmod(0o600)
            data = paths["store_path"].read_bytes()
            paths["store_path"].write_bytes(data + b"tamper")
            paths["store_path"].chmod(0o600)
            with self.assertRaises(Exception):
                verify_learning_store(**paths, store_id=STORE_ID, key_id=KEY_ID)

    def test_bootstrap_output_is_accepted_by_phase4d_runtime_binding(self):
        if os.name != "posix":
            self.skipTest("POSIX-only")
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(Path(tmp))
            bootstrap_learning_store(**paths, store_id=STORE_ID, key_id=KEY_ID)
            config = SimpleNamespace(
                environment="production",
                confidentiality_mode="confidential",
                raw={
                    "adaptive_learning": {
                        "runtime_retrieval": {
                            "enabled": True,
                            "store_path": str(paths["store_path"]),
                            "checkpoint_journal_path": str(paths["journal_path"]),
                            "trusted_head_witness_path": str(paths["witness_path"]),
                            "store_id": STORE_ID,
                            "active_key_id": KEY_ID,
                            "key_files": {KEY_ID: str(paths["key_path"])},
                            "domain": "analyst",
                        }
                    }
                },
            )
            binding = build_runtime_learning_binding(config)
            self.assertTrue(binding.enabled)
            self.assertEqual(binding.domain, "analyst")
            for forbidden in ("stage", "promote", "archive", "rollback", "rotate_key", "sign"):
                self.assertFalse(hasattr(binding.gateway, forbidden), forbidden)

    def test_failure_cleanup_removes_only_ceremony_targets(self):
        if os.name != "posix":
            self.skipTest("POSIX-only")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._paths(root)
            sentinel = root / "sentinel.txt"
            sentinel.write_text("keep", encoding="utf-8")
            with patch(
                "three_agent.adaptive_learning_lifecycle.LearningCheckpointAuthority.bootstrap",
                side_effect=LearningCheckpointError("forced"),
            ):
                with self.assertRaises(LearningCheckpointError):
                    bootstrap_learning_store(**paths, store_id=STORE_ID, key_id=KEY_ID)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")
            for path in paths.values():
                self.assertFalse(path.exists())

    def test_module_has_no_network_process_model_or_git_imports(self):
        tree = ast.parse(Path(lifecycle_module.__file__).read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertTrue(
            {
                "socket",
                "subprocess",
                "urllib",
                "requests",
                "httpx",
                "http",
                "ftplib",
                "git",
                "ollama",
            }.isdisjoint(imported)
        )

    def test_non_posix_provider_fails_before_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(Path(tmp))
            with patch("three_agent.adaptive_learning_lifecycle.os.name", "nt"):
                with self.assertRaisesRegex(AdaptiveLearningLifecycleError, "POSIX_ONLY"):
                    bootstrap_learning_store(**paths, store_id=STORE_ID, key_id=KEY_ID)
            for path in paths.values():
                self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
