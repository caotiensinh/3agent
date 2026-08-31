from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


SCRIPT = Path("scripts/workspace_auth_guard.py")


def load_module():
    spec = importlib.util.spec_from_file_location("workspace_auth_guard", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_db(path: Path) -> None:
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(
            """
            CREATE TABLE workspace_users (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                bootstrap_admin INTEGER NOT NULL,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until REAL NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            "INSERT INTO workspace_users VALUES (?,?,?,?,?,?,?,?,?)",
            ("u1", "admin", "admin", 1, 1, "11" * 16, "22" * 32, 0, 0),
        )
        conn.commit()


class AuthGuardTests(unittest.TestCase):
    def test_fingerprint_ignores_lockout_counters_but_detects_password_change(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "tasks.db"
            make_db(db)
            before = module.credential_fingerprint(db)
            with closing(sqlite3.connect(db)) as conn:
                conn.execute("UPDATE workspace_users SET failed_attempts=4, locked_until=12345")
                conn.commit()
            self.assertEqual(before, module.credential_fingerprint(db))
            with closing(sqlite3.connect(db)) as conn:
                conn.execute("UPDATE workspace_users SET password_hash=?", ("33" * 32,))
                conn.commit()
            self.assertNotEqual(before, module.credential_fingerprint(db))

    def test_snapshot_verify_and_restore_round_trip(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"
            (root / "config").mkdir(parents=True)
            (root / "data").mkdir()
            db = root / "data/tasks.db"
            make_db(db)
            (root / "config/workspace.secure.json").write_text(
                json.dumps({"database_path": "data/tasks.db"}), encoding="utf-8"
            )
            env = Path(td) / "chat.env"
            state = Path(td) / "state.json"
            backup = Path(td) / "backup.sqlite3"
            self.assertEqual(0, module.snapshot(root, env, backup, state))
            self.assertTrue(backup.is_file())
            self.assertTrue(state.is_file())
            self.assertTrue(json.loads(state.read_text(encoding="utf-8"))["applicable"])
            self.assertEqual(0, module.verify(root, env, state))
            with closing(sqlite3.connect(db)) as conn:
                conn.execute(
                    "UPDATE workspace_users SET password_salt=?,password_hash=?",
                    ("44" * 16, "55" * 32),
                )
                conn.commit()
            self.assertEqual(22, module.verify(root, env, state))
            self.assertEqual(0, module.restore(state, backup))
            self.assertEqual(0, module.verify(root, env, state))
            if os.name == "posix":
                self.assertEqual(0o600, os.stat(backup).st_mode & 0o777)
                self.assertEqual(0o600, os.stat(state).st_mode & 0o777)

    def test_guard_never_prints_password_material(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn('print(payload["credential_fingerprint"]', text)
        self.assertNotIn("print(row", text)
        self.assertIn("CREDENTIAL_INVARIANT_MISMATCH", text)
        self.assertIn("CREDENTIAL_RESTORE_OK", text)


if __name__ == "__main__":
    unittest.main()
