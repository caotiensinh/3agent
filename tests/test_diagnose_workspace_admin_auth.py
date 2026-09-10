from __future__ import annotations

import hashlib
import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path("scripts/diagnose_workspace_admin_auth.py")


def load_module():
    spec = importlib.util.spec_from_file_location("diagnose_workspace_admin_auth", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AdminAuthDiagnosticTests(unittest.TestCase):
    def test_password_match_uses_workspace_scrypt_contract(self) -> None:
        module = load_module()
        password = "correct horse battery staple"
        salt = bytes.fromhex("11" * 16)
        digest = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=module.SCRYPT_N,
            r=module.SCRYPT_R, p=module.SCRYPT_P, dklen=module.SCRYPT_DKLEN,
        )
        self.assertTrue(module.matches(password, salt.hex(), digest.hex()))
        self.assertFalse(module.matches("wrong", salt.hex(), digest.hex()))

    def test_diagnostic_is_read_only_and_never_prints_auth_secrets(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("getpass.getpass", text)
        self.assertIn("mode=ro", text)
        self.assertIn("hmac.compare_digest", text)
        self.assertNotIn("UPDATE workspace_users", text)
        self.assertNotIn("INSERT INTO workspace_users", text)
        self.assertNotIn("DELETE FROM workspace_users", text)
        self.assertNotIn('print(row["password_hash"]', text)
        self.assertNotIn('print(row["password_salt"]', text)
        self.assertIn("PASSWORD_STILL_CORRECT", text)
        self.assertIn("PASSWORD_CORRECT_BUT_ACCOUNT_LOCKED", text)
        self.assertIn("PASSWORD_DOES_NOT_MATCH_CURRENT_DB", text)


if __name__ == "__main__":
    unittest.main()
