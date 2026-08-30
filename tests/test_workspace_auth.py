import tempfile
import unittest
from pathlib import Path

from three_agent.workspace_auth import WorkspaceAuthStore


class WorkspaceAuthStoreTests(unittest.TestCase):
    def make_store(self):
        tmp = tempfile.TemporaryDirectory()
        store = WorkspaceAuthStore(Path(tmp.name) / "workspace.db")
        store.initialize()
        self.addCleanup(tmp.cleanup)
        return store

    def test_bootstrap_login_session_and_password_change(self):
        store = self.make_store()
        admin = store.bootstrap_admin(
            "admin", "0123456789abcdef", display_name="Admin User"
        )
        self.assertEqual(admin["role"], "admin")
        self.assertNotIn("password_hash", admin)
        result = store.login("admin", "0123456789abcdef", "192.168.11.20")
        self.assertIsNotNone(result)
        token, user = result
        self.assertEqual(user["user_id"], admin["user_id"])
        self.assertTrue(store.valid(token, "192.168.11.20"))
        self.assertFalse(store.valid(token, "192.168.11.21"))

        result = store.login("admin", "0123456789abcdef", "192.168.11.20")
        self.assertIsNotNone(result)
        token, _ = result
        store.change_password(
            admin["user_id"], "0123456789abcdef", "fedcba9876543210"
        )
        self.assertFalse(store.valid(token, "192.168.11.20"))
        self.assertIsNone(
            store.login("admin", "0123456789abcdef", "192.168.11.20")
        )
        self.assertIsNotNone(
            store.login("admin", "fedcba9876543210", "192.168.11.20")
        )

    def test_admin_can_create_user_and_last_admin_is_fail_closed(self):
        store = self.make_store()
        admin = store.bootstrap_admin("admin", "0123456789abcdef")
        member = store.create_user(
            username="rnd.user",
            password="abcdefghijklmnop",
            display_name="R&D User",
            department="R&D",
            role="user",
        )
        self.assertEqual(member["role"], "user")
        self.assertEqual(len(store.list_users()), 2)
        with self.assertRaisesRegex(ValueError, "last enabled administrator"):
            store.update_user(admin["user_id"], enabled=False)
        with self.assertRaisesRegex(ValueError, "last enabled administrator"):
            store.update_user(admin["user_id"], role="user")

        second_admin = store.create_user(
            username="admin2",
            password="abcdefghijklmnop",
            display_name="Admin Two",
            role="admin",
        )
        store.update_user(admin["user_id"], enabled=False)
        users = {row["user_id"]: row for row in store.list_users()}
        self.assertFalse(users[admin["user_id"]]["enabled"])
        self.assertTrue(users[second_admin["user_id"]]["enabled"])

    def test_disabled_user_and_admin_password_reset_revoke_sessions(self):
        store = self.make_store()
        store.bootstrap_admin("admin", "0123456789abcdef")
        user = store.create_user(
            username="worker",
            password="abcdefghijklmnop",
            display_name="Worker",
        )
        result = store.login("worker", "abcdefghijklmnop", "10.0.0.8")
        self.assertIsNotNone(result)
        token, _ = result
        self.assertTrue(store.valid(token, "10.0.0.8"))
        store.update_user(user["user_id"], new_password="ponmlkjihgfedcba")
        self.assertFalse(store.valid(token, "10.0.0.8"))
        result = store.login("worker", "ponmlkjihgfedcba", "10.0.0.8")
        self.assertIsNotNone(result)
        token, _ = result
        store.update_user(user["user_id"], enabled=False)
        self.assertFalse(store.valid(token, "10.0.0.8"))

    def test_short_password_and_duplicate_username_rejected(self):
        store = self.make_store()
        with self.assertRaisesRegex(ValueError, "at least 16"):
            store.bootstrap_admin("admin", "short")
        store.bootstrap_admin("admin", "0123456789abcdef")
        store.create_user(
            username="member",
            password="abcdefghijklmnop",
            display_name="Member",
        )
        with self.assertRaisesRegex(ValueError, "already exists"):
            store.create_user(
                username="MEMBER",
                password="ponmlkjihgfedcba",
                display_name="Member 2",
            )


if __name__ == "__main__":
    unittest.main()
