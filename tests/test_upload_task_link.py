import tempfile
import unittest
from pathlib import Path

from three_agent.store import TaskStore


class UploadTaskLinkTests(unittest.TestCase):
    def test_upload_ids_are_attached_to_exact_task(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStore(Path(tmp) / "tasks.db")
            store.initialize()
            one = store.create_task("one", "one")
            two = store.create_task("two", "two")
            store.attach_uploads(one.task_id, ["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"])
            store.attach_uploads(one.task_id, ["aaaaaaaaaaaaaaaa"])
            self.assertEqual(
                store.upload_ids_for_task(one.task_id),
                ["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"],
            )
            self.assertEqual(store.upload_ids_for_task(two.task_id), [])


if __name__ == "__main__":
    unittest.main()
