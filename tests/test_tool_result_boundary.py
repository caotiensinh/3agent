from __future__ import annotations

import hashlib
import unittest

from three_agent.tool_result_boundary import (
    MAX_RESULT_FIELD_BYTES,
    TOOL_RESULT_BOUNDARY_SCHEMA,
    ToolResultBoundaryError,
    bound_process_output,
    bound_text_result,
)


class ToolResultBoundaryTests(unittest.TestCase):
    def test_bound_text_result_redacts_common_secret_literals_and_preserves_raw_digest(self) -> None:
        raw = (
            "password=hunter2\n"
            "Authorization: Bearer abcdefghijklmnop\n"
            "api_key='top-secret-value'\n"
            "normal=visible\n"
        )
        result = bound_text_result(raw, max_bytes=4096)

        self.assertNotIn("hunter2", result.text)
        self.assertNotIn("abcdefghijklmnop", result.text)
        self.assertNotIn("top-secret-value", result.text)
        self.assertIn("normal=visible", result.text)
        self.assertGreaterEqual(result.redactions, 3)
        self.assertFalse(result.truncated)
        self.assertEqual(result.original_bytes, len(raw.encode("utf-8")))
        self.assertEqual(
            result.sha256,
            "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        )

    def test_utf8_result_is_hard_bounded_without_returning_partial_codepoint(self) -> None:
        raw = "日本語" * 100
        result = bound_text_result(raw, max_bytes=101)

        self.assertTrue(result.truncated)
        self.assertLessEqual(result.returned_bytes, 101)
        self.assertEqual(result.returned_bytes, len(result.text.encode("utf-8")))
        result.text.encode("utf-8").decode("utf-8")

    def test_private_key_material_is_redacted_before_projection(self) -> None:
        raw = (
            "header\n"
            "-----BEGIN PRIVATE KEY-----\n"
            "super-secret-private-key-material\n"
            "-----END PRIVATE KEY-----\n"
            "footer\n"
        )
        result = bound_text_result(raw, max_bytes=4096)

        self.assertNotIn("super-secret-private-key-material", result.text)
        self.assertIn("[REDACTED PRIVATE KEY]", result.text)
        self.assertEqual(result.redactions, 1)

    def test_process_output_has_independent_stdout_stderr_limits_and_metadata(self) -> None:
        stdout = "A" * 200
        stderr = "B" * 100
        result = bound_process_output(
            stdout,
            stderr,
            stdout_limit_bytes=64,
            stderr_limit_bytes=32,
        )

        self.assertEqual(len(result["stdout"].encode("utf-8")), 64)
        self.assertEqual(len(result["stderr"].encode("utf-8")), 32)
        self.assertEqual(result["output_boundary"]["schema_version"], TOOL_RESULT_BOUNDARY_SCHEMA)
        self.assertTrue(result["output_boundary"]["stdout"]["truncated"])
        self.assertTrue(result["output_boundary"]["stderr"]["truncated"])
        self.assertNotIn("text", result["output_boundary"]["stdout"])
        self.assertNotIn("text", result["output_boundary"]["stderr"])

    def test_invalid_limits_fail_closed(self) -> None:
        for value in (0, -1, MAX_RESULT_FIELD_BYTES + 1):
            with self.subTest(value=value):
                with self.assertRaises(ToolResultBoundaryError):
                    bound_text_result("x", max_bytes=value)


if __name__ == "__main__":
    unittest.main()
