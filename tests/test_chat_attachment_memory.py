from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from three_agent.chat_attachment_memory import ConversationAttachmentMemory
from three_agent.chat_gateway import ContinuitySecurityAwareProjectChatService


class ConversationAttachmentMemoryTests(unittest.TestCase):
    def test_attachment_references_survive_restart_without_copying_file_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "workspace.db"
            memory = ConversationAttachmentMemory(db)
            memory.initialize()
            conversation = "c" * 16
            upload_a = "a" * 16
            upload_b = "b" * 16
            memory.record(conversation, "job-1", [upload_a, upload_b])

            restarted = ConversationAttachmentMemory(db)
            restarted.initialize()
            self.assertEqual(
                restarted.recent_upload_ids(conversation, max_messages=1),
                [upload_a, upload_b],
            )

            with restarted.connect() as conn:
                columns = [
                    str(row[1])
                    for row in conn.execute("PRAGMA table_info(chat_message_attachments)")
                ]
            self.assertEqual(
                columns,
                ["conversation_id", "job_id", "upload_id", "ordinal", "created_at"],
            )

    def test_followup_resolves_recent_attachment_through_owner_validation(self):
        service = object.__new__(ContinuitySecurityAwareProjectChatService)
        service.history = SimpleNamespace(
            get_conversation=lambda owner_key, conversation_id: {
                "conversation_id": conversation_id,
                "messages": [],
            }
        )
        service.attachment_memory = SimpleNamespace(
            recent_upload_ids=lambda conversation_id, **kwargs: ["a" * 16]
        )
        service.orchestrator = SimpleNamespace(knowledge_gateway=object())

        with patch(
            "three_agent.chat_gateway._validate_owned_uploads",
            return_value=["a" * 16],
        ) as validator:
            resolved = service._resolve_submit_uploads(
                "hãy phân tích tiếp file đó",
                channel="web",
                sender="workspace-user:test",
                conversation_id="c" * 16,
                upload_ids=[],
            )
        self.assertEqual(resolved, ["a" * 16])
        validator.assert_called_once()

    def test_unrelated_turn_does_not_silently_inherit_old_attachment(self):
        service = object.__new__(ContinuitySecurityAwareProjectChatService)
        service.history = SimpleNamespace()
        service.attachment_memory = SimpleNamespace()
        service.orchestrator = SimpleNamespace(knowledge_gateway=object())
        resolved = service._resolve_submit_uploads(
            "Hãy giải thích nguyên lý DNS từ đầu.",
            channel="web",
            sender="workspace-user:test",
            conversation_id="c" * 16,
            upload_ids=[],
        )
        self.assertEqual(resolved, [])


if __name__ == "__main__":
    unittest.main()
