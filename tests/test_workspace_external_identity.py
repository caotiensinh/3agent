from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from three_agent.workspace_external_identity import (
    ExternalIdentityStore,
    ExternalSessionAuthStore,
)


class ExternalIdentityStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "workspace.db"
        self.auth = ExternalSessionAuthStore(self.db)
        self.auth.initialize()
        self.admin = self.auth.bootstrap_admin(
            "admin",
            "AdminPassword-12345",
            display_name="Administrator",
        )
        self.user = self.auth.create_user(
            username="worker",
            password="WorkerPassword-12345",
            display_name="Worker",
            role="user",
        )
        self.store = ExternalIdentityStore(self.auth)
        self.store.initialize()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_first_external_assertion_is_pending_and_stores_no_raw_subject(self) -> None:
        key = "a" * 64
        identity = self.store.record_assertion("google", key, "Google User")
        self.assertEqual(identity["status"], "pending")
        self.assertEqual(identity["provider"], "google")
        self.assertNotIn("external_key", identity)
        with self.auth.connect() as conn:
            row = conn.execute(
                "SELECT external_key FROM workspace_external_identities WHERE identity_id=?",
                (identity["identity_id"],),
            ).fetchone()
        self.assertEqual(row["external_key"], key)

    def test_admin_can_bind_pending_identity_to_existing_enabled_user(self) -> None:
        identity = self.store.record_assertion("github", "b" * 64, "octocat")
        approved = self.store.approve(identity["identity_id"], self.user["user_id"])
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["user_id"], self.user["user_id"])

        token, user = self.auth.issue_session_for_user(
            self.user["user_id"], "192.168.11.103"
        )
        self.assertEqual(user["username"], "worker")
        self.assertIsNotNone(
            self.auth.user_for_session(token, "192.168.11.103")
        )
        self.assertIsNone(
            self.auth.user_for_session(token, "192.168.11.104")
        )

    def test_binding_to_disabled_user_fails_closed(self) -> None:
        identity = self.store.record_assertion("line", "c" * 64, "LINE User")
        self.auth.update_user(self.user["user_id"], enabled=False)
        with self.assertRaisesRegex(ValueError, "enabled local WorkSpace user"):
            self.store.approve(identity["identity_id"], self.user["user_id"])

    def test_rejected_identity_cannot_reappear_as_pending(self) -> None:
        identity = self.store.record_assertion("google", "d" * 64, "Rejected")
        rejected = self.store.reject(identity["identity_id"])
        self.assertEqual(rejected["status"], "rejected")
        again = self.store.record_assertion("google", "d" * 64, "Rejected Again")
        self.assertEqual(again["status"], "rejected")

    def test_public_identity_listing_never_exposes_external_key(self) -> None:
        self.store.record_assertion("github", "e" * 64, "GitHub User")
        listing = self.store.list_identities()
        self.assertEqual(len(listing), 1)
        self.assertNotIn("external_key", listing[0])


if __name__ == "__main__":
    unittest.main()
