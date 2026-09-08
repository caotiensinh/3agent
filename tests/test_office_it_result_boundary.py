from __future__ import annotations

import hashlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.office_it_tools import execute_local_read
from three_agent.task_contract import TaskContractCompiler
from three_agent.tool_result_boundary import (
    DEFAULT_STDERR_LIMIT_BYTES,
    DEFAULT_STDOUT_LIMIT_BYTES,
    TOOL_RESULT_BOUNDARY_SCHEMA,
)


def _authority(*tool_ids: str) -> TaskCapabilityAuthority:
    contract = TaskContractCompiler().compile(
        task_id="office-it-result-boundary-test",
        task_type="analysis",
        sensitivity="internal",
        allowed_tools=tool_ids,
    )
    return TaskCapabilityAuthority.from_contract(contract)


class OfficeITResultBoundaryTests(unittest.TestCase):
    @patch("three_agent.office_it_tools.subprocess.run")
    @patch("three_agent.office_it_tools.platform.system", return_value="Windows")
    def test_execute_local_read_bounds_and_redacts_process_output(
        self,
        _platform_system,
        run_mock,
    ) -> None:
        stdout_raw = "token=super-secret-token\n" + ("A" * (DEFAULT_STDOUT_LIMIT_BYTES + 4096))
        stderr_raw = "Authorization: Bearer secretbearertoken\n" + (
            "B" * (DEFAULT_STDERR_LIMIT_BYTES + 4096)
        )
        run_mock.return_value = SimpleNamespace(
            returncode=7,
            stdout=stdout_raw,
            stderr=stderr_raw,
        )

        result = execute_local_read(
            "windows.event.system",
            authority=_authority("windows.event.system"),
        )

        self.assertEqual(result["tool_id"], "windows.event.system")
        self.assertEqual(result["returncode"], 7)
        self.assertLessEqual(len(result["stdout"].encode("utf-8")), DEFAULT_STDOUT_LIMIT_BYTES)
        self.assertLessEqual(len(result["stderr"].encode("utf-8")), DEFAULT_STDERR_LIMIT_BYTES)
        self.assertNotIn("super-secret-token", result["stdout"])
        self.assertNotIn("secretbearertoken", result["stderr"])

        boundary = result["output_boundary"]
        self.assertEqual(boundary["schema_version"], TOOL_RESULT_BOUNDARY_SCHEMA)
        self.assertTrue(boundary["stdout"]["truncated"])
        self.assertTrue(boundary["stderr"]["truncated"])
        self.assertGreaterEqual(boundary["stdout"]["redactions"], 1)
        self.assertGreaterEqual(boundary["stderr"]["redactions"], 1)
        self.assertEqual(
            boundary["stdout"]["sha256"],
            "sha256:" + hashlib.sha256(stdout_raw.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(
            boundary["stderr"]["sha256"],
            "sha256:" + hashlib.sha256(stderr_raw.encode("utf-8")).hexdigest(),
        )

        argv = run_mock.call_args.args[0]
        self.assertEqual(argv[:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
        self.assertFalse(run_mock.call_args.kwargs["shell"])


if __name__ == "__main__":
    unittest.main()
