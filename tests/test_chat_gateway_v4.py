import unittest

from three_agent.chat_gateway_v4 import HTML_V4, MAX_UPLOAD_REQUEST_BYTES
from three_agent.knowledge_gateway import MAX_UPLOAD_BYTES, MAX_UPLOADS_PER_TASK


class ChatGatewayV4Tests(unittest.TestCase):
    def test_upload_ui_and_endpoint_contract_are_present(self):
        self.assertIn('id="fileInput"', HTML_V4)
        self.assertIn("/api/upload", HTML_V4)
        self.assertIn("upload_ids", HTML_V4)
        self.assertIn(".txt,.md,.markdown,.html,.htm,.zip,.png,.jpg,.jpeg,.webp", HTML_V4)
        self.assertIn("Copy answer", HTML_V4)
        self.assertLess(MAX_UPLOAD_BYTES, MAX_UPLOAD_REQUEST_BYTES)
        self.assertEqual(MAX_UPLOADS_PER_TASK, 8)


if __name__ == "__main__":
    unittest.main()
